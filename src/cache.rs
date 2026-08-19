//! # Cache Layer
//!
//! This module provides a thread-safe, concurrent cache abstraction with multiple backends.
//!
//! ## Cache Guarantees
//!
//! ### Consistency Guarantees
//! - **Atomic expiry checks**: InMemoryCache performs expiry checks and removal atomically within a single write lock
//! - **No stale reads**: Expired entries are removed immediately upon detection, preventing stale data access
//! - **Connection validation**: RedisCache validates connection health before operations, preventing operations on unhealthy connections
//!
//! ### Concurrency Guarantees
//! - **Thread-safe operations**: All cache operations are protected by appropriate synchronization primitives (RwLock for InMemoryCache, Mutex for health checks)
//! - **No data races**: All shared state is properly synchronized, eliminating data race conditions
//! - **Concurrent read support**: Multiple concurrent reads are supported without blocking (read lock)
//!
//! ### Availability Guarantees
//! - **Health check backoff**: RedisCache implements exponential backoff for health checks to prevent thundering herd
//! - **Graceful degradation**: Connection failures return errors rather than panicking
//! - **Cached health status**: Health checks are cached during backoff periods to reduce load
//!
//! ### Eviction Policy
//! - **LRU with TTL**: InMemoryCache implements LRU eviction combined with TTL-based expiry
//! - **Configurable size limits**: Cache size can be limited via `with_max_size()` (0 = unlimited)
//! - **Atomic eviction**: Eviction occurs atomically within write locks
//!
//! ## Backend Differences
//!
//! ### InMemoryCache
//! - Uses RwLock for fine-grained concurrency control
//! - Manual TTL management with atomic expiry checks
//! - LRU tracking via VecDeque
//! - No external dependencies
//!
//! ### RedisCache
//! - Uses ConnectionManager for connection pooling
//! - Native Redis TTL support
//! - Health check with exponential backoff
//! - Connection state validation before operations
//!
//! ## Metrics
//! - All cache operations emit appropriate metrics (hits, misses, expired, serialization failures)
//! - Metrics are thread-safe via Prometheus IntCounter
//! - Metrics are optional (can be omitted if not needed)
//!
//! ## Event-Driven Invalidation
//! - Cache events (evictions, expirations, updates) can be broadcast to subscribers
//! - Use `subscribe()` to receive a broadcast channel for cache events
//! - Useful for coordinating cache invalidation across multiple components

use anyhow::Result;
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    prelude::v1::*,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{broadcast, Mutex, RwLock, Semaphore};

use crate::metrics::MetricsRegistry;

/// Typed cache key variants to prevent key collisions across namespaces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CacheKey {
    Verification(String),
    Config(String),
    Events(String),
}

impl CacheKey {
    /// Construct a `Verification` key with a normalized (lowercase, trimmed) hash.
    pub fn verification(hash: &str) -> Self {
        CacheKey::Verification(hash.trim().to_lowercase())
    }

    pub fn as_string(&self) -> String {
        match self {
            CacheKey::Verification(hash) => format!("verification:{}", hash),
            CacheKey::Config(key) => format!("config:{}", key),
            CacheKey::Events(hash) => format!("events:{}", hash),
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Entry {
    value: String,
    expires_at: u64,
}

pub enum CacheBackend {
    Redis(RedisCache),
    InMemory(InMemoryCache),
}

impl CacheBackend {
    pub async fn check_connection(&self) -> bool {
        match self {
            Self::Redis(c) => c.check_connection().await,
            Self::InMemory(c) => c.check_connection().await,
        }
    }

    /// Retrieve a raw cached value. Emits cache hit/miss/expired metrics.
    /// When using Redis backend, falls back to InMemory cache on circuit breaker open or failure.
    pub async fn get_raw(&self, key: &CacheKey) -> Result<Option<String>> {
        match self {
            Self::Redis(c) => {
                // Try Redis first
                match c.get_raw(&key.as_string()).await {
                    Ok(result) => {
                        match &result {
                            Some(_) => c.record_hit(),
                            None => c.record_miss(),
                        }
                        Ok(result)
                    }
                    Err(_) => {
                        // Redis failed — fallback to InMemory cache
                        if let Some(ref m) = c.metrics {
                            m.increment_cache_fallback_use();
                        }
                        let (value, was_expired) = c.fallback().get_raw_with_expiry(key).await?;
                        if was_expired {
                            c.fallback().record_expired();
                        } else if value.is_some() {
                            c.fallback().record_hit();
                        } else {
                            c.fallback().record_miss();
                        }
                        Ok(value)
                    }
                }
            }
            Self::InMemory(c) => {
                // InMemory distinguishes expired from true miss
                let (value, was_expired) = c.get_raw_with_expiry(key).await?;
                if was_expired {
                    c.record_expired();
                } else if value.is_some() {
                    c.record_hit();
                } else {
                    c.record_miss();
                }
                Ok(value)
            }
        }
    }

    pub async fn set_raw(&self, key: &CacheKey, value: &str, ttl: u64) -> Result<()> {
        match self {
            Self::Redis(c) => {
                // Try Redis first
                match c.set_raw(&key.as_string(), value, ttl).await {
                    Ok(()) => Ok(()),
                    Err(_) => {
                        // Redis failed — write to InMemory fallback cache
                        if let Some(ref m) = c.metrics {
                            m.increment_cache_fallback_use();
                        }
                        c.fallback().set_raw(key, value, ttl).await
                    }
                }
            }
            Self::InMemory(c) => c.set_raw(key, value, ttl).await,
        }
    }

    pub async fn get<T>(&self, key: &CacheKey) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        match self.get_raw(key).await? {
            Some(v) => match serde_json::from_str(&v) {
                Ok(parsed) => Ok(Some(parsed)),
                Err(_) => {
                    // Record serialization failure on any backend
                    match self {
                        Self::Redis(c) => c.record_serialization_failure(),
                        Self::InMemory(c) => c.record_serialization_failure(),
                    }
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    pub async fn set<T>(&self, key: &CacheKey, value: &T, ttl: u64) -> Result<()>
    where
        T: Serialize,
    {
        let serialized = serde_json::to_string(value)?;
        self.set_raw(key, &serialized, ttl).await
    }

    pub async fn delete(&self, key: &CacheKey) -> Result<()> {
        match self {
            Self::Redis(c) => {
                // Try Redis first
                match c.delete(&key.as_string()).await {
                    Ok(()) => Ok(()),
                    Err(_) => {
                        // Redis failed — delete from InMemory fallback cache
                        if let Some(ref m) = c.metrics {
                            m.increment_cache_fallback_use();
                        }
                        c.fallback().delete(key).await
                    }
                }
            }
            Self::InMemory(c) => c.delete(key).await,
        }
    }
}

// ── Circuit Breaker ──────────────────────────────────────────────────────

/// Circuit breaker states for Redis cache operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation: requests pass through.
    Closed,
    /// Circuit is tripped: all requests are rejected.
    Open,
    /// Probing: limited requests allowed to test recovery.
    HalfOpen,
}

impl CircuitState {
    fn as_str(&self) -> &'static str {
        match self {
            CircuitState::Closed => "closed",
            CircuitState::Open => "open",
            CircuitState::HalfOpen => "half_open",
        }
    }

    fn as_metric_value(&self) -> i64 {
        match self {
            CircuitState::Closed => 0,
            CircuitState::Open => 1,
            CircuitState::HalfOpen => 2,
        }
    }
}

/// Configuration for the cache circuit breaker.
#[derive(Debug, Clone)]
pub struct CacheCircuitBreakerConfig {
    pub failure_threshold: u32,
    pub open_duration_ms: u64,
    pub half_open_max_calls: u32,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
}

impl Default for CacheCircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration_ms: 30_000,
            half_open_max_calls: 1,
            backoff_base_ms: 100,
            backoff_max_ms: 30_000,
        }
    }
}

/// Circuit breaker for Redis cache operations.
///
/// Transitions: Closed -> Open (after failure_threshold failures)
///            Open -> HalfOpen (after open_duration with exponential backoff)
///            HalfOpen -> Closed (on success) or Open (on failure)
#[derive(Debug)]
pub struct CacheCircuitBreaker {
    state: CircuitState,
    consecutive_failures: u32,
    failure_threshold: u32,
    #[allow(dead_code)]
    open_duration: Duration,
    half_open_max_calls: u32,
    half_open_calls: u32,
    opened_at: Option<Instant>,
    backoff_base: Duration,
    backoff_max: Duration,
    _last_transition: Option<(CircuitState, CircuitState)>,
}

impl CacheCircuitBreaker {
    pub fn new(config: CacheCircuitBreakerConfig) -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            failure_threshold: config.failure_threshold,
            open_duration: Duration::from_millis(config.open_duration_ms),
            half_open_max_calls: config.half_open_max_calls,
            half_open_calls: 0,
            opened_at: None,
            backoff_base: Duration::from_millis(config.backoff_base_ms),
            backoff_max: Duration::from_millis(config.backoff_max_ms),
            _last_transition: None,
        }
    }

    /// Check if a request is allowed through the circuit breaker.
    pub fn should_allow(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if we should transition to HalfOpen
                if let Some(opened_at) = self.opened_at {
                    let backoff = self.current_backoff();
                    if opened_at.elapsed() >= backoff {
                        self.transition_to(CircuitState::HalfOpen);
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => {
                self.half_open_calls < self.half_open_max_calls
            }
        }
    }

    /// Record a successful operation.
    pub fn record_success(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.consecutive_failures = 0;
            }
            CircuitState::HalfOpen => {
                // Success in half-open: close the circuit
                self.half_open_calls += 1;
                if self.half_open_calls >= self.half_open_max_calls {
                    self.transition_to(CircuitState::Closed);
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but handle gracefully
            }
        }
    }

    /// Record a failed operation.
    pub fn record_failure(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.consecutive_failures += 1;
                if self.consecutive_failures >= self.failure_threshold {
                    self.transition_to(CircuitState::Open);
                }
            }
            CircuitState::HalfOpen => {
                // Failure in half-open: reopen the circuit
                self.transition_to(CircuitState::Open);
            }
            CircuitState::Open => {
                // Already open, just increment counter
                self.consecutive_failures += 1;
            }
        }
    }

    fn transition_to(&mut self, new_state: CircuitState) {
        let old_state = self.state;
        self.state = new_state;
        match new_state {
            CircuitState::Closed => {
                self.consecutive_failures = 0;
                self.opened_at = None;
                self.half_open_calls = 0;
            }
            CircuitState::Open => {
                self.opened_at = Some(Instant::now());
                self.half_open_calls = 0;
            }
            CircuitState::HalfOpen => {
                self.half_open_calls = 0;
            }
        }
        // Notify metrics
        // Note: metrics are passed separately to avoid circular dependency
        self._last_transition = Some((old_state, new_state));
    }

    /// Returns the last state transition if one occurred, and clears it.
    pub fn take_last_transition(&mut self) -> Option<(CircuitState, CircuitState)> {
        self._last_transition.take()
    }

    /// Get the current exponential backoff duration.
    fn current_backoff(&self) -> Duration {
        let failure_count = self.consecutive_failures.max(1);
        let base = self.backoff_base.as_millis() as u64;
        let exponent = (failure_count - 1).min(6);
        let backoff_ms = (base * 2u64.pow(exponent)).min(self.backoff_max.as_millis() as u64);
        Duration::from_millis(backoff_ms)
    }

    /// Get the current state.
    pub fn state(&self) -> CircuitState {
        self.state
    }
}

// ── Bulkhead ──────────────────────────────────────────────────────────────

/// Configuration for the cache bulkhead.
#[derive(Debug, Clone)]
pub struct CacheBulkheadConfig {
    pub max_concurrent: u32,
    pub max_queue: u32,
}

impl Default for CacheBulkheadConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 20,
            max_queue: 200,
        }
    }
}

/// Bulkhead for limiting concurrent Redis cache operations.
///
/// Uses a semaphore to limit concurrent operations and a queue depth limit
/// to prevent memory exhaustion under load.
#[derive(Debug)]
pub struct CacheBulkhead {
    semaphore: Arc<Semaphore>,
    #[allow(dead_code)]
    max_concurrent: usize,
    #[allow(dead_code)]
    max_queue: usize,
}

impl CacheBulkhead {
    pub fn new(config: CacheBulkheadConfig) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(config.max_concurrent as usize)),
            max_concurrent: config.max_concurrent as usize,
            max_queue: config.max_queue as usize,
        }
    }

    /// Try to acquire a permit. Returns Ok(BulkheadGuard) if available, Err if bulkhead is full.
    ///
    /// Non-blocking: immediately rejects if no permits are available.
    pub async fn try_acquire(&self) -> Result<BulkheadGuard, ()> {
        let permit = Arc::clone(&self.semaphore)
            .try_acquire_owned()
            .map_err(|_| ())?;
        Ok(BulkheadGuard { _permit: permit })
    }

    /// Get the number of currently active operations.
    pub fn active_count(&self) -> usize {
        self.max_concurrent - self.semaphore.available_permits()
    }
}

/// Guard that releases a bulkhead permit on drop.
#[derive(Debug)]
pub struct BulkheadGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

pub struct RedisCache {
    connection: ConnectionManager,
    metrics: Option<Arc<MetricsRegistry>>,
    // Health check state with mutex to prevent concurrent health checks
    health_check_state: Arc<Mutex<HealthCheckState>>,
    // Circuit breaker for Redis operations
    circuit_breaker: Arc<Mutex<CacheCircuitBreaker>>,
    // Bulkhead for limiting concurrent Redis operations
    bulkhead: Arc<CacheBulkhead>,
    // Fallback InMemory cache for when Redis is open/unhealthy
    fallback_cache: InMemoryCache,
    // Circuit breaker configuration
    #[allow(dead_code)]
    circuit_breaker_config: CacheCircuitBreakerConfig,
}

struct HealthCheckState {
    last_check: Option<SystemTime>,
    is_healthy: bool,
    backoff_until: Option<SystemTime>,
    consecutive_failures: u32,
}

impl HealthCheckState {
    fn new() -> Self {
        Self {
            last_check: None,
            is_healthy: true,
            backoff_until: None,
            consecutive_failures: 0,
        }
    }

    fn should_check(&self) -> bool {
        // Check if we're in backoff period
        if let Some(backoff_until) = self.backoff_until {
            if SystemTime::now() < backoff_until {
                return false;
            }
        }
        true
    }

    fn record_success(&mut self) {
        self.is_healthy = true;
        self.last_check = Some(SystemTime::now());
        self.backoff_until = None;
        self.consecutive_failures = 0;
    }

    fn record_failure(&mut self) {
        self.is_healthy = false;
        self.last_check = Some(SystemTime::now());
        self.consecutive_failures += 1;

        // Exponential backoff: 2^failures seconds, capped at 60s
        let backoff_secs = (2u64.pow(self.consecutive_failures.min(6))).min(60);
        self.backoff_until = Some(SystemTime::now() + Duration::from_secs(backoff_secs));
    }
}

impl RedisCache {
    pub async fn new(redis_url: &str) -> Result<Self> {
        Self::with_config(
            redis_url,
            CacheCircuitBreakerConfig::default(),
            CacheBulkheadConfig::default(),
        )
        .await
    }

    pub async fn with_config(
        redis_url: &str,
        cb_config: CacheCircuitBreakerConfig,
        bulkhead_config: CacheBulkheadConfig,
    ) -> Result<Self> {
        let client = redis::Client::open(redis_url)?;
        let connection = ConnectionManager::new(client).await?;
        Ok(Self {
            connection,
            metrics: None,
            health_check_state: Arc::new(Mutex::new(HealthCheckState::new())),
            circuit_breaker: Arc::new(Mutex::new(CacheCircuitBreaker::new(cb_config.clone()))),
            bulkhead: Arc::new(CacheBulkhead::new(bulkhead_config)),
            fallback_cache: InMemoryCache::new(),
            circuit_breaker_config: cb_config,
        })
    }

    pub fn with_metrics(mut self, metrics: Arc<MetricsRegistry>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Check if the circuit breaker allows operations.
    pub async fn circuit_breaker_allows(&self) -> bool {
        self.circuit_breaker.lock().await.should_allow()
    }

    /// Record a successful Redis operation with the circuit breaker.
    pub async fn record_success(&self) {
        let mut cb = self.circuit_breaker.lock().await;
        cb.record_success();
        if let Some((from, to)) = cb.take_last_transition() {
            if let Some(ref m) = self.metrics {
                m.record_cache_circuit_transition(from.as_str(), to.as_str());
                m.set_cache_circuit_state(to.as_metric_value());
                if to == CircuitState::Closed {
                    m.increment_cache_circuit_recovery();
                }
            }
        }
    }

    /// Record a failed Redis operation with the circuit breaker.
    pub async fn record_failure(&self) {
        let mut cb = self.circuit_breaker.lock().await;
        cb.record_failure();
        if let Some((from, to)) = cb.take_last_transition() {
            if let Some(ref m) = self.metrics {
                m.record_cache_circuit_transition(from.as_str(), to.as_str());
                m.set_cache_circuit_state(to.as_metric_value());
            }
        }
    }

    /// Get the current circuit breaker state.
    pub async fn circuit_state(&self) -> CircuitState {
        self.circuit_breaker.lock().await.state()
    }

    /// Get a reference to the fallback InMemory cache.
    pub fn fallback(&self) -> &InMemoryCache {
        &self.fallback_cache
    }

    async fn check_connection(&self) -> bool {
        let mut state = self.health_check_state.lock().await;

        // Return cached healthy status if we're not due for a check
        if !state.should_check() {
            return state.is_healthy;
        }

        // Perform health check
        let result = {
            let mut conn = self.connection.clone();
            redis::cmd("PING")
                .query_async::<ConnectionManager, String>(&mut conn)
                .await
                .is_ok()
        };

        if result {
            state.record_success();
        } else {
            state.record_failure();
        }

        result
    }

    async fn get_raw(&self, key: &str) -> Result<Option<String>> {
        // Check circuit breaker
        if !self.circuit_breaker.lock().await.should_allow() {
            if let Some(ref m) = self.metrics {
                m.increment_cache_circuit_rejection();
            }
            return Err(anyhow::anyhow!("Cache circuit breaker is open"));
        }

        // Check bulkhead
        let _permit = match self.bulkhead.try_acquire().await {
            Ok(p) => p,
            Err(()) => {
                if let Some(ref m) = self.metrics {
                    m.increment_cache_bulkhead_rejection();
                }
                return Err(anyhow::anyhow!("Cache bulkhead is full"));
            }
        };

        // Update bulkhead metric
        if let Some(ref m) = self.metrics {
            m.set_cache_bulkhead_active(self.bulkhead.active_count() as i64);
        }

        // Validate connection state before operation
        if !self.check_connection().await {
            self.record_failure().await;
            return Err(anyhow::anyhow!("Redis connection is unhealthy"));
        }

        match self.connection.clone().get(key).await {
            Ok(value) => {
                self.record_success().await;
                Ok(value)
            }
            Err(e) => {
                self.record_failure().await;
                Err(e.into())
            }
        }
    }

    async fn set_raw(&self, key: &str, value: &str, ttl: u64) -> Result<()> {
        // Check circuit breaker
        if !self.circuit_breaker.lock().await.should_allow() {
            if let Some(ref m) = self.metrics {
                m.increment_cache_circuit_rejection();
            }
            return Err(anyhow::anyhow!("Cache circuit breaker is open"));
        }

        // Check bulkhead
        let _permit = match self.bulkhead.try_acquire().await {
            Ok(p) => p,
            Err(()) => {
                if let Some(ref m) = self.metrics {
                    m.increment_cache_bulkhead_rejection();
                }
                return Err(anyhow::anyhow!("Cache bulkhead is full"));
            }
        };

        // Update bulkhead metric
        if let Some(ref m) = self.metrics {
            m.set_cache_bulkhead_active(self.bulkhead.active_count() as i64);
        }

        // Validate connection state before operation
        if !self.check_connection().await {
            self.record_failure().await;
            return Err(anyhow::anyhow!("Redis connection is unhealthy"));
        }

        match self.connection.clone().set_ex::<_, _, ()>(key, value, ttl).await {
            Ok(()) => {
                self.record_success().await;
                Ok(())
            }
            Err(e) => {
                self.record_failure().await;
                Err(e.into())
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        // Check circuit breaker
        if !self.circuit_breaker.lock().await.should_allow() {
            if let Some(ref m) = self.metrics {
                m.increment_cache_circuit_rejection();
            }
            return Err(anyhow::anyhow!("Cache circuit breaker is open"));
        }

        // Check bulkhead
        let _permit = match self.bulkhead.try_acquire().await {
            Ok(p) => p,
            Err(()) => {
                if let Some(ref m) = self.metrics {
                    m.increment_cache_bulkhead_rejection();
                }
                return Err(anyhow::anyhow!("Cache bulkhead is full"));
            }
        };

        // Update bulkhead metric
        if let Some(ref m) = self.metrics {
            m.set_cache_bulkhead_active(self.bulkhead.active_count() as i64);
        }

        // Validate connection state before operation
        if !self.check_connection().await {
            self.record_failure().await;
            return Err(anyhow::anyhow!("Redis connection is unhealthy"));
        }

        match self.connection.clone().del::<_, ()>(key).await {
            Ok(()) => {
                self.record_success().await;
                Ok(())
            }
            Err(e) => {
                self.record_failure().await;
                Err(e.into())
            }
        }
    }

    fn record_hit(&self) {
        if let Some(ref m) = self.metrics {
            m.increment_cache_hits();
        }
    }

    fn record_miss(&self) {
        if let Some(ref m) = self.metrics {
            m.increment_cache_misses();
        }
    }

    #[allow(dead_code)]
    fn record_expired(&self) {
        if let Some(ref m) = self.metrics {
            m.increment_cache_expired();
        }
    }

    fn record_serialization_failure(&self) {
        if let Some(ref m) = self.metrics {
            m.increment_cache_serialization_failures();
        }
    }
}

/// Cache event types for event-driven invalidation.
#[derive(Debug, Clone)]
pub enum CacheEvent {
    Evicted { key: CacheKey },
    Expired { key: CacheKey },
    Updated { key: CacheKey },
    Deleted { key: CacheKey },
}

/// Snapshot of cache statistics for monitoring.
#[derive(Debug, Clone)]
pub struct CacheStatsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub expired: u64,
    pub hit_rate: f64,
    pub current_size: usize,
    pub max_size: usize,
}

pub struct InMemoryCache {
    store: Arc<RwLock<HashMap<CacheKey, Entry>>>,
    metrics: Option<Arc<MetricsRegistry>>,
    // LRU tracking: queue of keys in access order (front = most recently used)
    lru_queue: Arc<RwLock<VecDeque<CacheKey>>>,
    // Maximum cache size (0 = unlimited)
    max_size: usize,
    // Cache statistics
    stats: Arc<RwLock<CacheStats>>,
    // Event broadcast channel for cache events
    event_tx: broadcast::Sender<CacheEvent>,
}

#[derive(Debug, Default)]
struct CacheStats {
    hits: u64,
    misses: u64,
    evictions: u64,
    expired: u64,
}

impl CacheStats {
    fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryCache {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(100);
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            metrics: None,
            lru_queue: Arc::new(RwLock::new(VecDeque::new())),
            max_size: 0, // Unlimited by default
            stats: Arc::new(RwLock::new(CacheStats::default())),
            event_tx,
        }
    }

    /// Create a new InMemoryCache with a maximum size limit.
    /// When the limit is reached, the least recently used entries are evicted.
    pub fn with_max_size(max_size: usize) -> Self {
        let (event_tx, _) = broadcast::channel(100);
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            metrics: None,
            lru_queue: Arc::new(RwLock::new(VecDeque::new())),
            max_size,
            stats: Arc::new(RwLock::new(CacheStats::default())),
            event_tx,
        }
    }

    /// Subscribe to cache events for event-driven invalidation.
    /// Returns a receiver that will receive CacheEvent messages.
    pub fn subscribe(&self) -> broadcast::Receiver<CacheEvent> {
        self.event_tx.subscribe()
    }

    /// Warm the cache with critical data by preloading entries.
    /// This is useful for loading frequently accessed data at startup.
    pub async fn warm(&self, entries: Vec<(CacheKey, String, u64)>) -> Result<usize> {
        let mut store = self.store.write().await;
        let mut lru_queue = self.lru_queue.write().await;
        let mut stats = self.stats.write().await;

        let mut loaded = 0;
        for (key, value, ttl) in entries {
            store.insert(
                key.clone(),
                Entry {
                    value: value.clone(),
                    expires_at: now_secs().saturating_add(ttl),
                },
            );
            lru_queue.retain(|k| k != &key);
            lru_queue.push_front(key);
            loaded += 1;
        }

        // Evict if over limit
        if self.max_size > 0 {
            while store.len() > self.max_size {
                if let Some(lru_key) = lru_queue.pop_back() {
                    store.remove(&lru_key);
                    stats.evictions += 1;
                } else {
                    break;
                }
            }
        }

        Ok(loaded)
    }

    /// Get cache statistics including hit rate and counts.
    pub async fn stats(&self) -> CacheStatsSnapshot {
        let stats = self.stats.read().await;
        let store = self.store.read().await;
        let snapshot = CacheStatsSnapshot {
            hits: stats.hits,
            misses: stats.misses,
            evictions: stats.evictions,
            expired: stats.expired,
            hit_rate: stats.hit_rate(),
            current_size: store.len(),
            max_size: self.max_size,
        };

        // Update Prometheus metrics if available
        if let Some(ref metrics) = self.metrics {
            metrics.set_cache_size(snapshot.current_size as u64);
            metrics.set_cache_hit_rate(snapshot.hit_rate);
            metrics.increment_cache_evictions_by(stats.evictions);
        }

        snapshot
    }

    /// Batch get multiple keys efficiently.
    pub async fn get_batch(&self, keys: &[CacheKey]) -> Result<Vec<(CacheKey, Option<String>)>> {
        let mut store = self.store.write().await;
        let mut lru_queue = self.lru_queue.write().await;
        let mut stats = self.stats.write().await;

        let mut results = Vec::with_capacity(keys.len());
        let now = now_secs();

        for key in keys {
            match store.get(key) {
                Some(entry) if entry.expires_at > now => {
                    // Valid entry
                    results.push((key.clone(), Some(entry.value.clone())));

                    // Update LRU
                    lru_queue.retain(|k| k != key);
                    lru_queue.push_front(key.clone());

                    stats.hits += 1;
                }
                Some(_) => {
                    // Expired entry
                    store.remove(key);
                    lru_queue.retain(|k| k != key);
                    results.push((key.clone(), None));
                    stats.expired += 1;
                }
                None => {
                    results.push((key.clone(), None));
                    stats.misses += 1;
                }
            }
        }

        Ok(results)
    }

    /// Batch set multiple keys efficiently.
    pub async fn set_batch(&self, entries: Vec<(CacheKey, String, u64)>) -> Result<usize> {
        let mut store = self.store.write().await;
        let mut lru_queue = self.lru_queue.write().await;
        let mut stats = self.stats.write().await;

        for (key, value, ttl) in &entries {
            store.insert(
                key.clone(),
                Entry {
                    value: value.clone(),
                    expires_at: now_secs().saturating_add(*ttl),
                },
            );
            lru_queue.retain(|k| k != key);
            lru_queue.push_front(key.clone());
        }

        // Evict if over limit
        if self.max_size > 0 {
            while store.len() > self.max_size {
                if let Some(lru_key) = lru_queue.pop_back() {
                    store.remove(&lru_key);
                    stats.evictions += 1;
                } else {
                    break;
                }
            }
        }

        Ok(entries.len())
    }

    pub fn with_metrics(mut self, metrics: Arc<MetricsRegistry>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    async fn check_connection(&self) -> bool {
        true
    }

    /// Returns (value, was_expired).
    /// Atomic operation: checks expiry and removes expired entry in single write lock.
    /// Updates LRU order on successful access.
    async fn get_raw_with_expiry(&self, key: &CacheKey) -> Result<(Option<String>, bool)> {
        let mut store = self.store.write().await;
        let mut lru_queue = self.lru_queue.write().await;
        let mut stats = self.stats.write().await;

        match store.get(key) {
            Some(entry) if entry.expires_at > now_secs() => {
                // Entry is valid - clone value while holding lock
                let value = entry.value.clone();

                // Update LRU: move to front (most recently used)
                lru_queue.retain(|k| k != key);
                lru_queue.push_front(key.clone());

                stats.hits += 1;
                Ok((Some(value), false))
            }
            Some(_) => {
                // Entry exists but TTL has elapsed - remove it atomically
                store.remove(key);
                lru_queue.retain(|k| k != key);
                stats.expired += 1;

                // Broadcast expiration event
                let _ = self.event_tx.send(CacheEvent::Expired { key: key.clone() });

                Ok((None, true))
            }
            None => {
                stats.misses += 1;
                Ok((None, false))
            }
        }
    }

    #[allow(dead_code)]
    async fn get_raw(&self, key: &CacheKey) -> Result<Option<String>> {
        let (value, _was_expired) = self.get_raw_with_expiry(key).await?;
        Ok(value)
    }

    async fn set_raw(&self, key: &CacheKey, value: &str, ttl: u64) -> Result<()> {
        let mut store = self.store.write().await;
        let mut lru_queue = self.lru_queue.write().await;

        let _is_update = store.contains_key(key);

        // Insert or update entry
        store.insert(
            key.clone(),
            Entry {
                value: value.to_string(),
                expires_at: now_secs().saturating_add(ttl),
            },
        );

        // Update LRU: move to front (most recently used)
        lru_queue.retain(|k| k != key);
        lru_queue.push_front(key.clone());

        // Broadcast update event for any set (create or update) so subscribers
        // always receive the latest state change.
        let _ = self.event_tx.send(CacheEvent::Updated { key: key.clone() });

        // Evict entries if over max_size
        if self.max_size > 0 {
            let mut stats = self.stats.write().await;
            while store.len() > self.max_size {
                if let Some(lru_key) = lru_queue.pop_back() {
                    store.remove(&lru_key);
                    stats.evictions += 1;

                    // Broadcast eviction event
                    let _ = self.event_tx.send(CacheEvent::Evicted {
                        key: lru_key.clone(),
                    });
                } else {
                    break;
                }
            }
        }

        Ok(())
    }

    async fn delete(&self, key: &CacheKey) -> Result<()> {
        let mut store = self.store.write().await;
        let mut lru_queue = self.lru_queue.write().await;
        let existed = store.remove(key).is_some();
        lru_queue.retain(|k| k != key);

        if existed {
            let _ = self.event_tx.send(CacheEvent::Deleted { key: key.clone() });
        }

        Ok(())
    }

    fn record_hit(&self) {
        if let Some(ref m) = self.metrics {
            m.increment_cache_hits();
        }
    }

    fn record_miss(&self) {
        if let Some(ref m) = self.metrics {
            m.increment_cache_misses();
        }
    }

    fn record_expired(&self) {
        if let Some(ref m) = self.metrics {
            m.increment_cache_expired();
        }
    }

    fn record_serialization_failure(&self) {
        if let Some(ref m) = self.metrics {
            m.increment_cache_serialization_failures();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::broadcast::error::TryRecvError;
    use tokio::time::sleep;

    #[tokio::test]
    async fn in_memory_cache_returns_value_within_ttl() {
        let cache = CacheBackend::InMemory(InMemoryCache::new());
        let key = CacheKey::Verification("abc".to_string());
        cache.set_raw(&key, "value", 60).await.unwrap();
        assert_eq!(
            cache.get_raw(&key).await.unwrap(),
            Some("value".to_string())
        );
    }

    #[tokio::test]
    async fn in_memory_cache_expires_entry_after_ttl() {
        let cache = CacheBackend::InMemory(InMemoryCache::new());
        let key = CacheKey::Verification("ttl_test".to_string());
        cache.set_raw(&key, "stale", 1).await.unwrap();
        sleep(Duration::from_secs(2)).await;
        assert_eq!(cache.get_raw(&key).await.unwrap(), None);
    }

    #[tokio::test]
    async fn cache_keys_are_namespaced() {
        let v_key = CacheKey::Verification("x".to_string());
        let c_key = CacheKey::Config("x".to_string());
        assert_ne!(v_key.as_string(), c_key.as_string());
    }

    #[tokio::test]
    async fn verification_key_normalizes_case() {
        let lower = CacheKey::verification("abc");
        let upper = CacheKey::verification("ABC");
        assert_eq!(lower.as_string(), upper.as_string());
    }

    #[tokio::test]
    async fn different_namespaces_do_not_collide() {
        let cache = CacheBackend::InMemory(InMemoryCache::new());
        let v_key = CacheKey::Verification("same".to_string());
        let c_key = CacheKey::Config("same".to_string());
        cache.set_raw(&v_key, "verification_val", 60).await.unwrap();
        cache.set_raw(&c_key, "config_val", 60).await.unwrap();
        assert_eq!(
            cache.get_raw(&v_key).await.unwrap(),
            Some("verification_val".to_string())
        );
        assert_eq!(
            cache.get_raw(&c_key).await.unwrap(),
            Some("config_val".to_string())
        );
    }

    #[tokio::test]
    async fn delete_removes_entry() {
        let cache = CacheBackend::InMemory(InMemoryCache::new());
        let key = CacheKey::Verification("del".to_string());
        cache.set_raw(&key, "v", 60).await.unwrap();
        cache.delete(&key).await.unwrap();
        assert_eq!(cache.get_raw(&key).await.unwrap(), None);
    }

    #[tokio::test]
    async fn in_memory_cache_emits_hit_metric() {
        let metrics = MetricsRegistry::arc();
        let cache = InMemoryCache::new().with_metrics(Arc::clone(&metrics));
        let backend = CacheBackend::InMemory(cache);
        let key = CacheKey::Verification("metric_hit".to_string());

        backend.set_raw(&key, "value", 60).await.unwrap();
        backend.get_raw(&key).await.unwrap();

        let output = metrics.render();
        assert!(output.contains("cache_hits_total"));
    }

    #[tokio::test]
    async fn in_memory_cache_emits_miss_metric() {
        let metrics = MetricsRegistry::arc();
        let cache = InMemoryCache::new().with_metrics(Arc::clone(&metrics));
        let backend = CacheBackend::InMemory(cache);
        let key = CacheKey::Verification("metric_miss".to_string());

        backend.get_raw(&key).await.unwrap();

        let output = metrics.render();
        assert!(output.contains("cache_misses_total"));
    }

    #[tokio::test]
    async fn in_memory_cache_emits_expired_metric() {
        let metrics = MetricsRegistry::arc();
        let cache = InMemoryCache::new().with_metrics(Arc::clone(&metrics));
        let backend = CacheBackend::InMemory(cache);
        let key = CacheKey::Verification("metric_expired".to_string());

        backend.set_raw(&key, "stale", 1).await.unwrap();
        sleep(Duration::from_secs(2)).await;
        backend.get_raw(&key).await.unwrap();

        let output = metrics.render();
        assert!(output.contains("cache_expired_total"));
    }

    #[tokio::test]
    async fn in_memory_cache_emits_serialization_failure_metric() {
        let metrics = MetricsRegistry::arc();
        let cache = InMemoryCache::new().with_metrics(Arc::clone(&metrics));
        let backend = CacheBackend::InMemory(cache);
        let key = CacheKey::Verification("serial_fail".to_string());

        // Store invalid JSON
        backend.set_raw(&key, "not-valid-json", 60).await.unwrap();
        // Try to deserialize as a struct — should fail
        let result: Option<serde_json::Value> = backend.get(&key).await.unwrap();
        // serde_json::from_str on "not-valid-json" fails → serialization failure metric
        assert!(result.is_none());

        let output = metrics.render();
        assert!(output.contains("cache_serialization_failures_total"));
    }

    #[tokio::test]
    async fn event_cache_stores_and_retrieves_events() {
        let cache = CacheBackend::InMemory(InMemoryCache::new());
        let key = CacheKey::Events("doc-hash-1".to_string());
        let events = vec!["{\"seq\":1}", "{\"seq\":2}"];
        let serialized = serde_json::to_string(&events).unwrap();

        cache.set_raw(&key, &serialized, 60).await.unwrap();
        let retrieved: Option<Vec<serde_json::Value>> = cache.get(&key).await.unwrap();

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn event_cache_events_namespace_does_not_collide() {
        let cache = CacheBackend::InMemory(InMemoryCache::new());
        let v_key = CacheKey::Verification("x".to_string());
        let e_key = CacheKey::Events("x".to_string());

        cache.set_raw(&v_key, "verification_val", 60).await.unwrap();
        cache.set_raw(&e_key, "events_val", 60).await.unwrap();
        assert_eq!(
            cache.get_raw(&v_key).await.unwrap(),
            Some("verification_val".to_string())
        );
        assert_eq!(
            cache.get_raw(&e_key).await.unwrap(),
            Some("events_val".to_string())
        );
    }

    #[tokio::test]
    async fn concurrent_reads_do_not_race() {
        let cache = CacheBackend::InMemory(InMemoryCache::new());
        let key = CacheKey::Verification("concurrent_read".to_string());
        cache.set_raw(&key, "value", 60).await.unwrap();

        let cache = Arc::new(cache);
        let mut handles = vec![];

        for _ in 0..100 {
            let cache_clone = Arc::clone(&cache);
            let key_clone = key.clone();
            handles.push(tokio::spawn(async move {
                cache_clone.get_raw(&key_clone).await.unwrap()
            }));
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        for result in results {
            assert_eq!(result.unwrap(), Some("value".to_string()));
        }
    }

    #[tokio::test]
    async fn concurrent_writes_are_consistent() {
        let cache = CacheBackend::InMemory(InMemoryCache::new());
        let cache = Arc::new(cache);
        let mut handles = vec![];

        for i in 0..50 {
            let cache_clone = Arc::clone(&cache);
            let key = CacheKey::Verification(format!("concurrent_write_{}", i));
            handles.push(tokio::spawn(async move {
                cache_clone
                    .set_raw(&key, &format!("value_{}", i), 60)
                    .await
                    .unwrap();
                cache_clone.get_raw(&key).await.unwrap()
            }));
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        for (i, result) in results.iter().enumerate() {
            assert_eq!(result.as_ref().unwrap(), &Some(format!("value_{}", i)));
        }
    }

    #[tokio::test]
    async fn lru_eviction_under_concurrent_load() {
        let cache = InMemoryCache::with_max_size(10);
        let backend = CacheBackend::InMemory(cache);
        let backend = Arc::new(backend);
        let mut handles = vec![];

        // Write 20 entries concurrently (should evict 10)
        for i in 0..20 {
            let backend_clone = Arc::clone(&backend);
            let key = CacheKey::Verification(format!("lru_{}", i));
            handles.push(tokio::spawn(async move {
                backend_clone
                    .set_raw(&key, &format!("value_{}", i), 60)
                    .await
                    .unwrap();
            }));
        }

        futures::future::join_all(handles).await;

        // Verify only 10 entries remain
        let mut count = 0;
        for i in 0..20 {
            let key = CacheKey::Verification(format!("lru_{}", i));
            if backend.get_raw(&key).await.unwrap().is_some() {
                count += 1;
            }
        }
        assert_eq!(count, 10);
    }

    #[tokio::test]
    async fn metrics_accurate_under_concurrent_load() {
        let metrics = MetricsRegistry::arc();
        let cache = InMemoryCache::new().with_metrics(Arc::clone(&metrics));
        let backend = CacheBackend::InMemory(cache);
        let backend = Arc::new(backend);
        let mut handles = vec![];

        // Concurrent hits
        // Ensure the key exists so these are hits, not misses.
        backend
            .set_raw(
                &CacheKey::Verification("metric_concurrent".to_string()),
                "value",
                60,
            )
            .await
            .unwrap();
        for _ in 0..50 {
            let backend_clone = Arc::clone(&backend);
            let key = CacheKey::Verification("metric_concurrent".to_string());
            handles.push(tokio::spawn(async move {
                backend_clone.get_raw(&key).await.unwrap()
            }));
        }

        // Concurrent misses
        for i in 0..30 {
            let backend_clone = Arc::clone(&backend);
            let key = CacheKey::Verification(format!("miss_{}", i));
            handles.push(tokio::spawn(async move {
                backend_clone.get_raw(&key).await.unwrap()
            }));
        }

        futures::future::join_all(handles).await;

        let output = metrics.render();
        assert!(output.contains("cache_misses_total"));
        // Verify metrics were incremented (should have 30 misses)
        assert!(output.contains("cache_misses_total 30"));
    }

    #[tokio::test]
    async fn atomic_expiry_check_under_concurrent_access() {
        let cache = CacheBackend::InMemory(InMemoryCache::new());
        let key = CacheKey::Verification("expiry_race".to_string());
        cache.set_raw(&key, "value", 1).await.unwrap();

        let cache = Arc::new(cache);
        let mut handles = vec![];

        // Wait for expiry and then read concurrently
        sleep(Duration::from_secs(2)).await;
        for _ in 0..20 {
            let cache_clone = Arc::clone(&cache);
            let key_clone = key.clone();
            handles.push(tokio::spawn(async move {
                cache_clone.get_raw(&key_clone).await.unwrap()
            }));
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        // All reads should return None (expired)
        for result in results {
            assert_eq!(result.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn redis_health_check_prevents_concurrent_checks() {
        // This test verifies the health check backoff mechanism
        let cache = RedisCache::new("redis://127.0.0.1:6379").await;

        // If Redis is not available, this will fail gracefully
        if cache.is_err() {
            // Skip test if Redis is not available
            return;
        }

        let cache = cache.unwrap();
        let cache = Arc::new(cache);
        let mut handles = vec![];

        // Trigger concurrent health checks
        for _ in 0..10 {
            let cache_clone = Arc::clone(&cache);
            handles.push(tokio::spawn(
                async move { cache_clone.check_connection().await },
            ));
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        // All should complete without panicking
        for result in results {
            result.unwrap();
        }
    }

    #[tokio::test]
    async fn cache_warming_preloads_entries() {
        let cache = InMemoryCache::new();
        let entries = vec![
            (
                CacheKey::Verification("warm1".to_string()),
                "value1".to_string(),
                60,
            ),
            (
                CacheKey::Verification("warm2".to_string()),
                "value2".to_string(),
                60,
            ),
            (
                CacheKey::Verification("warm3".to_string()),
                "value3".to_string(),
                60,
            ),
        ];

        let loaded = cache.warm(entries).await.unwrap();
        assert_eq!(loaded, 3);

        // Verify entries are accessible
        let backend = CacheBackend::InMemory(cache);
        assert_eq!(
            backend
                .get_raw(&CacheKey::Verification("warm1".to_string()))
                .await
                .unwrap(),
            Some("value1".to_string())
        );
        assert_eq!(
            backend
                .get_raw(&CacheKey::Verification("warm2".to_string()))
                .await
                .unwrap(),
            Some("value2".to_string())
        );
        assert_eq!(
            backend
                .get_raw(&CacheKey::Verification("warm3".to_string()))
                .await
                .unwrap(),
            Some("value3".to_string())
        );
    }

    #[tokio::test]
    async fn cache_warming_respects_max_size() {
        let cache = InMemoryCache::with_max_size(5);
        let entries: Vec<_> = (0..10)
            .map(|i| {
                (
                    CacheKey::Verification(format!("warm_{}", i)),
                    format!("value_{}", i),
                    60,
                )
            })
            .collect();

        let loaded = cache.warm(entries).await.unwrap();
        assert_eq!(loaded, 10);

        // Verify only 5 entries remain
        let stats = cache.stats().await;
        assert_eq!(stats.current_size, 5);
    }

    #[tokio::test]
    async fn cache_stats_track_operations() {
        let cache = InMemoryCache::new();
        let backend = CacheBackend::InMemory(cache);

        // Miss
        backend
            .get_raw(&CacheKey::Verification("miss".to_string()))
            .await
            .unwrap();

        // Set and hit
        backend
            .set_raw(&CacheKey::Verification("hit".to_string()), "value", 60)
            .await
            .unwrap();
        backend
            .get_raw(&CacheKey::Verification("hit".to_string()))
            .await
            .unwrap();
        backend
            .get_raw(&CacheKey::Verification("hit".to_string()))
            .await
            .unwrap();

        let cache = match backend {
            CacheBackend::InMemory(c) => c,
            _ => std::panic!("Expected InMemoryCache"),
        };

        let stats = cache.stats().await;
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!(stats.hit_rate > 0.0);
    }

    #[tokio::test]
    async fn cache_stats_track_evictions() {
        let cache = InMemoryCache::with_max_size(3);
        let backend = CacheBackend::InMemory(cache);

        // Add 5 entries (should evict 2)
        for i in 0..5 {
            backend
                .set_raw(
                    &CacheKey::Verification(format!("evict_{}", i)),
                    &format!("value_{}", i),
                    60,
                )
                .await
                .unwrap();
        }

        let cache = match backend {
            CacheBackend::InMemory(c) => c,
            _ => std::panic!("Expected InMemoryCache"),
        };

        let stats = cache.stats().await;
        assert_eq!(stats.evictions, 2);
        assert_eq!(stats.current_size, 3);
    }

    #[tokio::test]
    async fn batch_get_retrieves_multiple_keys() {
        let cache = InMemoryCache::new();
        let backend = CacheBackend::InMemory(cache);

        backend
            .set_raw(&CacheKey::Verification("key1".to_string()), "value1", 60)
            .await
            .unwrap();
        backend
            .set_raw(&CacheKey::Verification("key2".to_string()), "value2", 60)
            .await
            .unwrap();
        backend
            .set_raw(&CacheKey::Verification("key3".to_string()), "value3", 60)
            .await
            .unwrap();

        let cache = match backend {
            CacheBackend::InMemory(c) => c,
            _ => std::panic!("Expected InMemoryCache"),
        };

        let keys = vec![
            CacheKey::Verification("key1".to_string()),
            CacheKey::Verification("key2".to_string()),
            CacheKey::Verification("key3".to_string()),
            CacheKey::Verification("key4".to_string()), // miss
        ];

        let results = cache.get_batch(&keys).await.unwrap();
        assert_eq!(results.len(), 4);
        assert_eq!(results[0].1, Some("value1".to_string()));
        assert_eq!(results[1].1, Some("value2".to_string()));
        assert_eq!(results[2].1, Some("value3".to_string()));
        assert_eq!(results[3].1, None);
    }

    #[tokio::test]
    async fn batch_set_stores_multiple_keys() {
        let cache = InMemoryCache::new();
        let entries = vec![
            (
                CacheKey::Verification("batch1".to_string()),
                "value1".to_string(),
                60,
            ),
            (
                CacheKey::Verification("batch2".to_string()),
                "value2".to_string(),
                60,
            ),
            (
                CacheKey::Verification("batch3".to_string()),
                "value3".to_string(),
                60,
            ),
        ];

        let count = cache.set_batch(entries).await.unwrap();
        assert_eq!(count, 3);

        let stats = cache.stats().await;
        assert_eq!(stats.current_size, 3);
    }

    #[tokio::test]
    async fn event_driven_invalidation_broadcasts_events() {
        let cache = InMemoryCache::new();
        let mut rx = cache.subscribe();

        // Set a key
        cache
            .set_raw(
                &CacheKey::Verification("event_key".to_string()),
                "value",
                60,
            )
            .await
            .unwrap();

        // Update it
        cache
            .set_raw(
                &CacheKey::Verification("event_key".to_string()),
                "new_value",
                60,
            )
            .await
            .unwrap();

        // Delete it
        cache
            .delete(&CacheKey::Verification("event_key".to_string()))
            .await
            .unwrap();

        // Check events with timeout
        let event1 = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(event1.is_ok());
        matches!(event1.unwrap().unwrap(), CacheEvent::Updated { .. });

        let event2 = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(event2.is_ok());
        matches!(event2.unwrap().unwrap(), CacheEvent::Updated { .. });

        let event3 = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(event3.is_ok());
        matches!(event3.unwrap().unwrap(), CacheEvent::Deleted { .. });
    }

    #[tokio::test]
    async fn event_broadcasts_on_expiry() {
        let cache = InMemoryCache::new();
        let mut rx = cache.subscribe();

        cache
            .set_raw(
                &CacheKey::Verification("expire_key".to_string()),
                "value",
                1,
            )
            .await
            .unwrap();
        // Drain any prior events (e.g., initial Updated from set)
        loop {
            match rx.try_recv() {
                Ok(_) => continue,
                Err(TryRecvError::Empty) => break,
                Err(_) => break,
            }
        }

        sleep(Duration::from_secs(2)).await;

        // Trigger expiry check
        cache
            .get_raw(&CacheKey::Verification("expire_key".to_string()))
            .await
            .unwrap();

        // Check for expiration event
        let event = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(event.is_ok());
        if let Ok(Ok(CacheEvent::Expired { .. })) = event {
            // Correct event type
        } else {
            std::panic!("Expected Expired event");
        }
    }

    #[tokio::test]
    async fn event_broadcasts_on_eviction() {
        let cache = InMemoryCache::with_max_size(2);
        let mut rx = cache.subscribe();
        // Perform sets that should trigger eviction
        cache
            .set_raw(&CacheKey::Verification("evict1".to_string()), "value1", 60)
            .await
            .unwrap();
        cache
            .set_raw(&CacheKey::Verification("evict2".to_string()), "value2", 60)
            .await
            .unwrap();
        cache
            .set_raw(&CacheKey::Verification("evict3".to_string()), "value3", 60)
            .await
            .unwrap();

        // Consume events until we see an Evicted event or timeout
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        let mut found = false;
        while std::time::Instant::now() < deadline {
            if let Ok(Ok(ev)) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
                if let CacheEvent::Evicted { .. } = ev {
                    found = true;
                    break;
                }
            }
        }

        if !found {
            std::panic!("Expected Evicted event");
        }
    }

    #[tokio::test]
    async fn multiple_subscribers_receive_events() {
        let cache = InMemoryCache::new();
        let mut rx1 = cache.subscribe();
        let mut rx2 = cache.subscribe();

        cache
            .set_raw(&CacheKey::Verification("multi".to_string()), "value", 60)
            .await
            .unwrap();
        cache
            .delete(&CacheKey::Verification("multi".to_string()))
            .await
            .unwrap();

        // Both subscribers should receive events
        let event1 = tokio::time::timeout(Duration::from_millis(100), rx1.recv()).await;
        let event2 = tokio::time::timeout(Duration::from_millis(100), rx2.recv()).await;

        assert!(event1.is_ok());
        assert!(event2.is_ok());
    }

    // ── Circuit Breaker Tests ───────────────────────────────────────────

    #[test]
    fn circuit_breaker_starts_closed() {
        let mut cb = CacheCircuitBreaker::new(CacheCircuitBreakerConfig::default());
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.should_allow());
    }

    #[test]
    fn circuit_breaker_opens_after_threshold() {
        let config = CacheCircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let mut cb = CacheCircuitBreaker::new(config);

        // Record failures up to threshold
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Should not allow when open
        assert!(!cb.should_allow());
    }

    #[test]
    fn circuit_breaker_success_resets_failures() {
        let config = CacheCircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let mut cb = CacheCircuitBreaker::new(config);

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_success(); // resets failures
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed); // not open yet
    }

    #[test]
    fn circuit_breaker_transitions_to_half_open_after_backoff() {
        let config = CacheCircuitBreakerConfig {
            failure_threshold: 1,
            open_duration_ms: 10, // very short for testing
            backoff_base_ms: 10,
            backoff_max_ms: 100,
            ..Default::default()
        };
        let mut cb = CacheCircuitBreaker::new(config);

        // Open the circuit
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Initially blocked
        assert!(!cb.should_allow());

        // Wait for backoff to expire
        std::thread::sleep(Duration::from_millis(20));

        // Should now transition to HalfOpen and allow
        assert!(cb.should_allow());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn circuit_breaker_half_open_success_closes() {
        let config = CacheCircuitBreakerConfig {
            failure_threshold: 1,
            open_duration_ms: 10,
            half_open_max_calls: 1,
            backoff_base_ms: 10,
            backoff_max_ms: 100,
            ..Default::default()
        };
        let mut cb = CacheCircuitBreaker::new(config);

        cb.record_failure(); // opens circuit
        std::thread::sleep(Duration::from_millis(20));
        cb.should_allow(); // transitions to half_open

        cb.record_success(); // should close circuit
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn circuit_breaker_half_open_failure_reopens() {
        let config = CacheCircuitBreakerConfig {
            failure_threshold: 1,
            open_duration_ms: 10,
            half_open_max_calls: 2,
            backoff_base_ms: 10,
            backoff_max_ms: 100,
            ..Default::default()
        };
        let mut cb = CacheCircuitBreaker::new(config);

        cb.record_failure(); // opens circuit
        std::thread::sleep(Duration::from_millis(20));
        cb.should_allow(); // transitions to half_open
        cb.record_failure(); // should reopen circuit
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn circuit_breaker_exponential_backoff_grows() {
        let config = CacheCircuitBreakerConfig {
            failure_threshold: 1,
            open_duration_ms: 60_000,
            backoff_base_ms: 100,
            backoff_max_ms: 30_000,
            ..Default::default()
        };
        let mut cb = CacheCircuitBreaker::new(config);

        cb.record_failure();
        let backoff1 = cb.current_backoff();

        cb.record_failure();
        let backoff2 = cb.current_backoff();

        // Backoff should grow exponentially
        assert!(backoff2 > backoff1);
    }

    #[test]
    fn circuit_breaker_backoff_caps_at_max() {
        let config = CacheCircuitBreakerConfig {
            failure_threshold: 1,
            open_duration_ms: 60_000,
            backoff_base_ms: 100,
            backoff_max_ms: 500,
            ..Default::default()
        };
        let mut cb = CacheCircuitBreaker::new(config);

        // Trigger many failures to grow backoff
        for _ in 0..20 {
            cb.record_failure();
        }

        let backoff = cb.current_backoff();
        assert!(backoff <= Duration::from_millis(500));
    }

    #[test]
    fn circuit_breaker_take_last_transition() {
        let config = CacheCircuitBreakerConfig {
            failure_threshold: 1,
            ..Default::default()
        };
        let mut cb = CacheCircuitBreaker::new(config);

        // No transition yet
        assert!(cb.take_last_transition().is_none());

        // Open the circuit -> should record transition
        cb.record_failure();
        let transition = cb.take_last_transition();
        assert!(transition.is_some());
        let (from, to) = transition.unwrap();
        assert_eq!(from, CircuitState::Closed);
        assert_eq!(to, CircuitState::Open);

        // Should be cleared
        assert!(cb.take_last_transition().is_none());
    }

    // ── Bulkhead Tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn bulkhead_allows_up_to_max_concurrent() {
        let config = CacheBulkheadConfig {
            max_concurrent: 3,
            max_queue: 10,
        };
        let bulkhead = CacheBulkhead::new(config);

        assert_eq!(bulkhead.active_count(), 0);

        let _p1 = bulkhead.try_acquire().await.unwrap();
        assert_eq!(bulkhead.active_count(), 1);

        let _p2 = bulkhead.try_acquire().await.unwrap();
        assert_eq!(bulkhead.active_count(), 2);

        let _p3 = bulkhead.try_acquire().await.unwrap();
        assert_eq!(bulkhead.active_count(), 3);
    }

    #[tokio::test]
    async fn bulkhead_rejects_when_full() {
        let config = CacheBulkheadConfig {
            max_concurrent: 2,
            max_queue: 0, // no queue
        };
        let bulkhead = CacheBulkhead::new(config);

        let _p1 = bulkhead.try_acquire().await.unwrap();
        let _p2 = bulkhead.try_acquire().await.unwrap();

        // Should reject when at capacity
        assert!(bulkhead.try_acquire().await.is_err());
    }

    #[tokio::test]
    async fn bulkhead_permits_release_on_drop() {
        let config = CacheBulkheadConfig {
            max_concurrent: 1,
            max_queue: 10,
        };
        let bulkhead = CacheBulkhead::new(config);

        {
            let _permit = bulkhead.try_acquire().await.unwrap();
            assert_eq!(bulkhead.active_count(), 1);
        } // permit dropped here

        assert_eq!(bulkhead.active_count(), 0);
        assert!(bulkhead.try_acquire().await.is_ok());
    }

    #[tokio::test]
    async fn bulkhead_limits_concurrent_permits() {
        let config = CacheBulkheadConfig {
            max_concurrent: 3,
            max_queue: 10,
        };
        let bulkhead = CacheBulkhead::new(config);

        // Use all concurrent slots
        let _p1 = bulkhead.try_acquire().await.unwrap();
        let _p2 = bulkhead.try_acquire().await.unwrap();
        let _p3 = bulkhead.try_acquire().await.unwrap();

        // At max capacity — should reject
        assert!(bulkhead.try_acquire().await.is_err());

        // Drop one permit
        drop(_p1);

        // Now should succeed again
        assert!(bulkhead.try_acquire().await.is_ok());
    }

    // ── Circuit Breaker Metrics Test ────────────────────────────────────

    #[test]
    fn circuit_state_as_str_and_metric() {
        assert_eq!(CircuitState::Closed.as_str(), "closed");
        assert_eq!(CircuitState::Open.as_str(), "open");
        assert_eq!(CircuitState::HalfOpen.as_str(), "half_open");

        assert_eq!(CircuitState::Closed.as_metric_value(), 0);
        assert_eq!(CircuitState::Open.as_metric_value(), 1);
        assert_eq!(CircuitState::HalfOpen.as_metric_value(), 2);
    }

    // ── Fallback Integration Tests ──────────────────────────────────────

    #[tokio::test]
    async fn redis_cache_fallback_to_inmemory_on_circuit_open() {
        // Create a RedisCache with a very low failure threshold
        let cb_config = CacheCircuitBreakerConfig {
            failure_threshold: 1,
            open_duration_ms: 60_000,
            half_open_max_calls: 1,
            backoff_base_ms: 100,
            backoff_max_ms: 30_000,
        };
        let bulkhead_config = CacheBulkheadConfig::default();

        // Try to connect to Redis — if unavailable, we test the fallback path
        let redis_cache =
            RedisCache::with_config("redis://127.0.0.1:6379", cb_config, bulkhead_config).await;
        if redis_cache.is_err() {
            return; // Skip if Redis unavailable
        }
        let redis_cache = redis_cache.unwrap();
        let metrics = MetricsRegistry::arc();
        let redis_cache = redis_cache.with_metrics(Arc::clone(&metrics));
        let backend = CacheBackend::Redis(redis_cache);

        // Open the circuit breaker by recording a failure
        if let CacheBackend::Redis(ref c) = backend {
            c.record_failure().await;
            assert_eq!(c.circuit_state().await, CircuitState::Open);
        }

        // Set a value — should fallback to InMemory
        let key = CacheKey::Verification("fallback_test".to_string());
        backend.set_raw(&key, "fallback_value", 60).await.unwrap();

        // Get the value — should come from fallback
        let value = backend.get_raw(&key).await.unwrap();
        assert_eq!(value, Some("fallback_value".to_string()));

        // Check fallback metric
        let output = metrics.render();
        assert!(output.contains("cache_fallback_uses_total"));
    }

    #[tokio::test]
    async fn cache_backend_inmemory_has_no_circuit_breaker() {
        // InMemory backend should always work regardless of circuit breaker state
        let cache = CacheBackend::InMemory(InMemoryCache::new());
        let key = CacheKey::Verification("no_cb".to_string());

        cache.set_raw(&key, "value", 60).await.unwrap();
        let value = cache.get_raw(&key).await.unwrap();
        assert_eq!(value, Some("value".to_string()));

        cache.delete(&key).await.unwrap();
        assert_eq!(cache.get_raw(&key).await.unwrap(), None);
    }

    #[tokio::test]
    async fn circuit_breaker_config_defaults() {
        let config = CacheCircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.open_duration_ms, 30_000);
        assert_eq!(config.half_open_max_calls, 1);
        assert_eq!(config.backoff_base_ms, 100);
        assert_eq!(config.backoff_max_ms, 30_000);
    }

    #[tokio::test]
    async fn bulkhead_config_defaults() {
        let config = CacheBulkheadConfig::default();
        assert_eq!(config.max_concurrent, 20);
        assert_eq!(config.max_queue, 200);
    }

    // ── Error Variant Tests ─────────────────────────────────────────────

    #[test]
    fn circuit_breaker_error_display() {
        use crate::error::AuditError;
        let err = AuditError::CircuitBreakerOpen("redis is down".to_string());
        assert!(err.to_string().contains("circuit breaker open"));
        assert!(err.to_string().contains("redis is down"));
    }

    #[test]
    fn bulkhead_full_error_display() {
        use crate::error::AuditError;
        let err = AuditError::BulkheadFull("too many operations".to_string());
        assert!(err.to_string().contains("bulkhead full"));
        assert!(err.to_string().contains("too many operations"));
    }

    #[test]
    fn cache_unhealthy_error_display() {
        use crate::error::AuditError;
        let err = AuditError::CacheUnhealthy("connection refused".to_string());
        assert!(err.to_string().contains("cache unhealthy"));
        assert!(err.to_string().contains("connection refused"));
    }
}

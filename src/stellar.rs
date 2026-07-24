use anyhow::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    boxed::Box,
    fmt,
    future::Future,
    string::{String, ToString},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
    vec::Vec,
};
use thiserror::Error;
use tokio::sync::Semaphore as AsyncSemaphore;

use crate::{
    cache::{CacheBackend, CacheKey},
    config::AppConfig,
    hash_validator::CanonicalHash,
};

use crate::metrics::MetricsRegistry;

const DEFAULT_RETRY_BASE_DELAY_MS: u64 = 100;
const DEFAULT_RETRY_MAX_DELAY_MS: u64 = 10_000;
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_FAILURE_THRESHOLD: u32 = 5;
const DEFAULT_OPEN_DURATION_MS: u64 = 30_000;
const DEFAULT_HALF_OPEN_MAX_CALLS: u32 = 1;

#[derive(Clone)]
pub struct StellarClient {
    horizon_url: String,
    http_client: reqwest::Client,
    circuit_breaker: Arc<CircuitBreaker>,
    max_retries: u32,
    metrics: Option<Arc<MetricsRegistry>>,
    config: StellarClientConfig,
    cache: Option<Arc<CacheBackend>>,
    bulkhead: Arc<AsyncSemaphore>,
}

#[derive(Debug, Clone)]
pub struct StellarClientConfig {
    pub retry: RetryPolicy,
    pub circuit_breaker: CircuitBreakerConfig,
    pub request_timeout: Duration,
    pub rate_limit_per_second: u32,
    pub rate_limit_burst: u32,
    pub bulkhead: BulkheadConfig,
    pub graceful_degradation: GracefulDegradationConfig,
}

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub jitter: RetryJitter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryJitter {
    None,
    Full,
    Equal,
    Decorrelated,
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub open_duration: Duration,
    pub half_open_max_calls: u32,
}

#[derive(Debug, Clone)]
pub struct BulkheadConfig {
    pub max_concurrent: u32,
    pub max_queue: u32,
}

#[derive(Debug, Clone)]
pub struct GracefulDegradationConfig {
    pub fallback_cache_ttl: Duration,
    pub stale_cache_ok: bool,
}

impl Default for BulkheadConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 10,
            max_queue: 100,
        }
    }
}

impl Default for GracefulDegradationConfig {
    fn default() -> Self {
        Self {
            fallback_cache_ttl: Duration::from_secs(300),
            stale_cache_ok: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CircuitBreakerMetrics {
    pub trips: u64,
    pub recoveries: u64,
    pub half_open_successes: u64,
    pub half_open_failures: u64,
    pub rejected_calls: u64,
    pub successful_calls: u64,
    pub failed_calls: u64,
    pub timeout_calls: u64,
    pub retryable_http_calls: u64,
    pub consecutive_failures: u32,
    pub in_flight: u32,
}

#[derive(Debug, Error)]
pub enum StellarError {
    #[error("stellar circuit breaker is {state:?}; retry after {retry_after:?}")]
    CircuitOpen {
        state: CircuitState,
        retry_after: Duration,
    },
    #[error("stellar request to {url} failed: {reason}")]
    Request { url: String, reason: String },
    #[error("stellar request to {url} timed out after {timeout:?}")]
    Timeout { url: String, timeout: Duration },
    #[error("stellar horizon returned HTTP {status} for {url}: {body}")]
    RetryableHttpStatus {
        status: u16,
        url: String,
        body: String,
    },
    #[error("stellar horizon returned non-retryable HTTP {status} for {url}: {body}")]
    NonRetryableHttpStatus {
        status: u16,
        url: String,
        body: String,
    },
    #[error("stellar horizon response for {url} could not be parsed: {source}. Body: {body}")]
    ResponseParse {
        url: String,
        body: String,
        source: serde_json::Error,
    },
    #[error("stellar verification for hash {hash} did not find a matching transaction")]
    VerificationNotFound { hash: String },
    #[error("stellar operation '{operation}' failed after {attempts} attempts ({retries_attempted} retries): {final_error}")]
    RetryExhausted {
        operation: &'static str,
        attempts: u32,
        retries_attempted: u32,
        final_error: Box<StellarError>,
    },
}

impl std::fmt::Debug for StellarClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StellarClient")
            .field("horizon_url", &self.horizon_url)
            .field("http_client", &self.http_client)
            .field("max_retries", &self.max_retries)
            .field("metrics", &self.metrics.as_ref().map(|_| "<metrics>"))
            .finish()
    }
}

/// Categorised outcome of a Stellar Horizon verification.
///
/// Distinguishes the four states required by the acceptance criteria:
/// confirmed match, no match, network failure, and malformed response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// A matching Stellar transaction was found with correct memo.
    ConfirmedMatch,
    /// Horizon was reachable but no transaction matched the hash.
    NoMatch,
    /// All retries exhausted due to network / connection errors.
    NetworkError,
    /// Horizon returned a response that could not be parsed.
    MalformedResponse,
}

/// Result of a Stellar Horizon verification request.
///
/// When `status` is [`VerificationStatus::ConfirmedMatch`], `transaction_id`
/// and `timestamp` carry the on-chain proof. For all other statuses both
/// fields are `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub status: VerificationStatus,
    pub transaction_id: Option<String>,
    pub timestamp: Option<i64>,
    /// HTTP status code if the last error was an HTTP response error
    pub last_http_status: Option<u16>,
}

pub type StellarResult<T> = Result<T, StellarError>;

impl VerificationResult {
    /// Convenience: `true` only for [`VerificationStatus::ConfirmedMatch`].
    pub fn verified(&self) -> bool {
        matches!(self.status, VerificationStatus::ConfirmedMatch)
    }
}

/// A parsed Stellar transaction extracted from a Horizon response.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionRecord {
    pub transaction_id: String,
    pub timestamp: i64,
    /// Always `true` when constructed from a confirmed match.
    /// Retained for cache backward-compatibility; new code should
    /// use [`VerificationStatus::ConfirmedMatch`] instead.
    pub verified: bool,
}

impl StellarClient {
    pub fn new(horizon_url: &str) -> Self {
        Self::with_config(horizon_url, StellarClientConfig::default())
    }

    pub fn from_app_config(config: &AppConfig) -> Self {
        Self::with_config(
            &config.stellar_horizon_url,
            StellarClientConfig::from_app_config(config),
        )
    }

    pub fn with_config(horizon_url: &str, config: StellarClientConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            horizon_url: trim_trailing_slash(horizon_url),
            http_client,
            circuit_breaker: Arc::new(CircuitBreaker::new(config.circuit_breaker.clone())),
            max_retries: config.retry.max_retries,
            metrics: None,
            bulkhead: Arc::new(AsyncSemaphore::new(config.bulkhead.max_concurrent as usize)),
            config,
            cache: None,
        }
    }

    pub fn config(&self) -> &StellarClientConfig {
        &self.config
    }

    /// Set the maximum number of retries for `verify_hash`.
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<MetricsRegistry>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn with_cache(mut self, cache: Arc<CacheBackend>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Warm the cache with pre-known verification results.
    /// This is useful for loading frequently accessed hashes at startup.
    pub async fn warm_cache(
        &self,
        entries: Vec<(String, VerificationResult, u64)>,
    ) -> Result<usize> {
        if let Some(cache) = &self.cache {
            if let CacheBackend::InMemory(inmem) = cache.as_ref() {
                let cache_entries: Vec<_> = entries
                    .into_iter()
                    .map(|(hash, result, ttl)| {
                        let key = CacheKey::verification(&hash);
                        let value = serde_json::to_string(&result).unwrap_or_default();
                        (key, value, ttl)
                    })
                    .collect();

                inmem.warm(cache_entries).await
            } else {
                Ok(0) // Redis warming not implemented yet
            }
        } else {
            Ok(0)
        }
    }

    pub fn verification_cache_key(hash: &str) -> CacheKey {
        CacheKey::verification(hash)
    }

    pub fn circuit_state(&self) -> CircuitState {
        self.circuit_breaker.state()
    }

    pub fn circuit_breaker_metrics(&self) -> CircuitBreakerMetrics {
        self.circuit_breaker.metrics()
    }

    pub async fn check_connection(&self) -> bool {
        let start = MetricsRegistry::start_timer();
        let result = self
            .http_client
            .get(&self.horizon_url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);

        if let Some(ref m) = self.metrics {
            m.increment_request_count();
            let status = if result { "success" } else { "error" };
            m.record_horizon_latency(status, MetricsRegistry::elapsed_secs(start));
            if !result {
                m.increment_error_count();
            }
        }
        result
    }

    pub async fn check_connection_with_retry(&self) -> StellarResult<bool> {
        let max_attempts = self.config.retry.max_retries.saturating_add(1);
        let mut last_error = None;

        for attempt in 0..max_attempts {
            match self.check_connection().await {
                true => return Ok(true),
                false => {
                    if attempt + 1 == max_attempts {
                        break;
                    }
                    last_error = Some(StellarError::Request {
                        url: self.horizon_url.clone(),
                        reason: "connection check returned a non-success response".to_string(),
                    });
                    sleep(self.retry_delay(attempt)).await;
                }
            }
        }

        Err(StellarError::RetryExhausted {
            operation: "check_connection",
            attempts: max_attempts,
            retries_attempted: self.config.retry.max_retries,
            final_error: Box::new(last_error.unwrap_or_else(|| StellarError::Request {
                url: self.horizon_url.clone(),
                reason: "connection check failed".to_string(),
            })),
        })
    }

    pub async fn verify_hash_with_retry(&self, hash: &str) -> StellarResult<VerificationResult> {
        self.circuit_breaker
            .call(|| async { self.execute_verify_hash_with_retry(hash).await })
            .await
    }

    async fn execute_verify_hash_with_retry(
        &self,
        hash: &str,
    ) -> StellarResult<VerificationResult> {
        let result = self.verify_hash(hash).await;
        match result.status {
            VerificationStatus::ConfirmedMatch | VerificationStatus::NoMatch => Ok(result),
            VerificationStatus::NetworkError | VerificationStatus::MalformedResponse => {
                let reason = match result.last_http_status {
                    Some(status) => format!("HTTP {}", status),
                    None => format!("verification returned {:?}", result.status),
                };
                Err(StellarError::RetryExhausted {
                    operation: "verify_hash",
                    attempts: self.max_retries + 1,
                    retries_attempted: self.max_retries,
                    final_error: Box::new(StellarError::Request {
                        url: self.horizon_url.clone(),
                        reason,
                    }),
                })
            }
        }
    }

    fn retry_delay(&self, attempt: u32) -> Duration {
        let base = self.config.retry.base_delay;
        let max_delay = self.config.retry.max_delay;
        let multiplier = 2_u32.saturating_pow(attempt.min(31));
        let exponential = base.checked_mul(multiplier).unwrap_or(max_delay);
        let capped = exponential.min(max_delay);

        match self.config.retry.jitter {
            RetryJitter::None => capped,
            RetryJitter::Full => jittered_delay_full(capped),
            RetryJitter::Equal => jittered_delay_equal(capped),
            RetryJitter::Decorrelated => jittered_delay_decorrelated(capped, attempt),
        }
    }

    /// Verify a document hash against Stellar Horizon with retries.
    ///
    /// Queries `GET /transactions?memo={hash}`, parses the response, and:
    ///
    /// * Cross-checks the returned transaction's memo field against the
    ///   requested hash.
    /// * Extracts the transaction ID and ledger close timestamp.
    /// * Distinguishes between [`VerificationStatus::ConfirmedMatch`],
    ///   [`VerificationStatus::NoMatch`], [`VerificationStatus::NetworkError`],
    ///   and [`VerificationStatus::MalformedResponse`].
    ///
    /// Records latency, success/failure, and retry metrics.
    pub async fn verify_hash(&self, hash: &str) -> VerificationResult {
        // Enforce canonicalization at the API/service boundary. This rejects
        // non-canonical input (uppercase, whitespace, wrong algorithm/length)
        // before any network call, guaranteeing every downstream consumer
        // operates on a validated, canonical SHA-256 hash.
        let canonical = match CanonicalHash::new(hash) {
            Ok(c) => c,
            Err(_) => {
                return VerificationResult {
                    status: VerificationStatus::MalformedResponse,
                    transaction_id: None,
                    timestamp: None,
                    last_http_status: None,
                };
            }
        };
        let hash = canonical.as_str();

        let overall_start = MetricsRegistry::start_timer();
        let mut last_status = VerificationStatus::NoMatch;
        let mut last_http_status: Option<u16> = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                if let Some(ref m) = self.metrics {
                    m.increment_retry();
                }
                tokio::time::sleep(self.retry_delay(attempt - 1)).await;
            }

            let horizon_start = MetricsRegistry::start_timer();
            let url = format!("{}/transactions?memo={}", self.horizon_url, hash);

            let bulkhead_acquired =
                tokio::time::timeout(Duration::from_millis(500), self.bulkhead.acquire())
                    .await
                    .is_ok();

            if !bulkhead_acquired {
                if let Some(fallback) = self.try_stale_cache_fallback(hash).await {
                    return fallback;
                }
                last_status = VerificationStatus::NetworkError;
                continue;
            }

            let resp_result = self.http_client.get(&url).send().await;

            match resp_result {
                Ok(resp) => {
                    let horizon_latency = MetricsRegistry::elapsed_secs(horizon_start);
                    let status_str = if resp.status().is_success() {
                        "success"
                    } else {
                        "error"
                    };

                    if let Some(ref m) = self.metrics {
                        m.record_horizon_latency(status_str, horizon_latency);
                    }

                    if resp.status().is_success() {
                        match self.parse_horizon_transaction(resp, hash).await {
                            Ok(Some(record)) => {
                                if let Some(ref m) = self.metrics {
                                    m.record_verification(
                                        "success",
                                        MetricsRegistry::elapsed_secs(overall_start),
                                    );
                                }
                                return VerificationResult {
                                    status: VerificationStatus::ConfirmedMatch,
                                    transaction_id: Some(record.transaction_id),
                                    timestamp: Some(record.timestamp),
                                    last_http_status: None,
                                };
                            }
                            Ok(None) => {
                                last_status = VerificationStatus::NoMatch;
                                break; // legitimate negative — don't retry
                            }
                            Err(_) => {
                                last_status = VerificationStatus::MalformedResponse;
                                // parse failure may be transient — continue retry
                            }
                        }
                    } else {
                        let status = resp.status().as_u16();
                        if is_retryable_status(status) {
                            last_status = VerificationStatus::NetworkError;
                            last_http_status = Some(status);
                            // HTTP error — continue retry
                        } else {
                            last_status = VerificationStatus::NoMatch;
                            last_http_status = Some(status);
                            break; // non-retryable — don't retry
                        }
                    }
                }
                Err(_) => {
                    let horizon_latency = MetricsRegistry::elapsed_secs(horizon_start);
                    if let Some(ref m) = self.metrics {
                        m.record_horizon_latency("error", horizon_latency);
                    }
                    last_status = VerificationStatus::NetworkError;
                    last_http_status = None;
                }
            }
        }

        if let Some(ref m) = self.metrics {
            m.record_verification("failure", MetricsRegistry::elapsed_secs(overall_start));
        }
        VerificationResult {
            status: last_status,
            transaction_id: None,
            timestamp: None,
            last_http_status,
        }
    }

    /// Parse a Horizon `/transactions` response and cross-check the memo
    /// field against the expected hash.
    async fn parse_horizon_transaction(
        &self,
        resp: reqwest::Response,
        expected_hash: &str,
    ) -> Result<Option<TransactionRecord>> {
        #[derive(Deserialize)]
        struct HorizonEmbedded {
            records: Vec<HorizonTransaction>,
        }

        #[derive(Deserialize)]
        struct HorizonResponse {
            #[serde(rename = "_embedded")]
            embedded: HorizonEmbedded,
        }

        #[derive(Deserialize)]
        struct HorizonTransaction {
            id: String,
            created_at: Option<String>,
            #[serde(default)]
            memo: Option<String>,
            #[serde(rename = "memo_type", default)]
            memo_type: Option<String>,
        }

        let body: HorizonResponse = resp.json().await?;

        for tx in body.embedded.records {
            // Cross-check: the transaction's memo must match the expected hash.
            // Horizon filters by memo on the server side, but we verify
            // client-side for defense in depth.
            //
            // A document hash is recorded as either a `text` memo (the hex
            // string itself) or a `hash` memo (base64 of the decoded 32 bytes).
            // `expected_hash` is already canonical (lowercase), so the
            // comparison is a direct, allocation-free string equality.
            let memo = tx.memo.as_deref().unwrap_or("");
            let expected_hash_b64 = crate::hash_validator::CanonicalHash::new(expected_hash)
                .ok()
                .and_then(|c| c.to_stellar_memo_base64().ok());

            let memo_matches = match tx.memo_type.as_deref() {
                Some("text") => memo.eq_ignore_ascii_case(expected_hash),
                Some("hash") => expected_hash_b64
                    .as_deref()
                    .map(|b64| b64 == memo)
                    .unwrap_or(false),
                _ => false,
            };

            if memo_matches {
                let timestamp = tx
                    .created_at
                    .as_ref()
                    .and_then(|ts| {
                        chrono::DateTime::parse_from_rfc3339(ts)
                            .ok()
                            .map(|dt| dt.timestamp())
                    })
                    .unwrap_or(0);

                return Ok(Some(TransactionRecord {
                    transaction_id: tx.id,
                    timestamp,
                    verified: true,
                }));
            }
        }

        Ok(None)
    }

    async fn try_stale_cache_fallback(&self, hash: &str) -> Option<VerificationResult> {
        let cache = self.cache.as_ref()?;
        let key = CacheKey::verification(hash);
        let result = cache.get::<VerificationResult>(&key).await.ok()??;
        if result.verified() || self.config.graceful_degradation.stale_cache_ok {
            return Some(result);
        }
        None
    }

    pub async fn anchor_transfer(&self, _transfer_hash: &str, _memo: &str) -> Result<()> {
        if let Some(ref m) = self.metrics {
            m.increment_request_count();
        }
        Ok(())
    }
}

impl StellarClientConfig {
    pub fn from_app_config(config: &AppConfig) -> Self {
        Self {
            retry: RetryPolicy {
                max_retries: config.stellar_max_retries,
                base_delay: Duration::from_millis(config.stellar_retry_base_delay_ms),
                max_delay: Duration::from_millis(config.stellar_retry_max_delay_ms),
                jitter: match config.stellar_retry_jitter_type.to_lowercase().as_str() {
                    "none" => RetryJitter::None,
                    "full" => RetryJitter::Full,
                    "equal" => RetryJitter::Equal,
                    "decorrelated" => RetryJitter::Decorrelated,
                    _ => RetryJitter::Full,
                },
            },
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: config.stellar_circuit_breaker_failure_threshold,
                open_duration: Duration::from_millis(
                    config.stellar_circuit_breaker_open_duration_ms,
                ),
                half_open_max_calls: config.stellar_circuit_breaker_half_open_max_calls,
            },
            request_timeout: Duration::from_millis(config.stellar_request_timeout_ms),
            rate_limit_per_second: config.rate_limit_per_second,
            rate_limit_burst: config.rate_limit_burst,
            bulkhead: BulkheadConfig {
                max_concurrent: config.stellar_bulkhead_max_concurrent,
                max_queue: config.stellar_bulkhead_max_queue,
            },
            graceful_degradation: GracefulDegradationConfig::default(),
        }
    }
}

impl Default for StellarClientConfig {
    fn default() -> Self {
        Self {
            retry: RetryPolicy {
                max_retries: 3,
                base_delay: Duration::from_millis(DEFAULT_RETRY_BASE_DELAY_MS),
                max_delay: Duration::from_millis(DEFAULT_RETRY_MAX_DELAY_MS),
                jitter: RetryJitter::Full,
            },
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: DEFAULT_FAILURE_THRESHOLD,
                open_duration: Duration::from_millis(DEFAULT_OPEN_DURATION_MS),
                half_open_max_calls: DEFAULT_HALF_OPEN_MAX_CALLS,
            },
            request_timeout: Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS),
            rate_limit_per_second: 10,
            rate_limit_burst: 10,
            bulkhead: BulkheadConfig::default(),
            graceful_degradation: GracefulDegradationConfig::default(),
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: DEFAULT_FAILURE_THRESHOLD,
            open_duration: Duration::from_millis(DEFAULT_OPEN_DURATION_MS),
            half_open_max_calls: DEFAULT_HALF_OPEN_MAX_CALLS,
        }
    }
}

impl StellarError {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::CircuitOpen { .. }
            | Self::Request { .. }
            | Self::Timeout { .. }
            | Self::RetryableHttpStatus { .. }
            | Self::ResponseParse { .. } => true,
            Self::RetryExhausted { final_error, .. } => final_error.is_retryable(),
            Self::NonRetryableHttpStatus { .. } | Self::VerificationNotFound { .. } => false,
        }
    }

    pub fn affects_circuit_breaker(&self) -> bool {
        match self {
            Self::RetryExhausted { final_error, .. } => final_error.affects_circuit_breaker(),
            Self::Request { .. } | Self::Timeout { .. } | Self::RetryableHttpStatus { .. } => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: AtomicUsize,
    opened_at: Mutex<Option<Instant>>,
    consecutive_failures: AtomicUsize,
    half_open_in_flight: AtomicUsize,
    half_open_successes: AtomicUsize,
    half_open_semaphore: Arc<AsyncSemaphore>,
    metrics: Mutex<CircuitBreakerMetrics>,
}

impl CircuitBreaker {
    fn new(config: CircuitBreakerConfig) -> Self {
        let max_calls = config.half_open_max_calls.max(1) as usize;
        Self {
            config,
            state: AtomicUsize::new(CircuitState::Closed as usize),
            opened_at: Mutex::new(None),
            consecutive_failures: AtomicUsize::new(0),
            half_open_in_flight: AtomicUsize::new(0),
            half_open_successes: AtomicUsize::new(0),
            half_open_semaphore: Arc::new(AsyncSemaphore::new(max_calls)),
            metrics: Mutex::new(CircuitBreakerMetrics::default()),
        }
    }

    fn state(&self) -> CircuitState {
        match self.state.load(Ordering::Relaxed) {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }

    fn metrics(&self) -> CircuitBreakerMetrics {
        *self.metrics.lock().unwrap()
    }

    async fn call<F, Fut, T>(&self, operation: F) -> StellarResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = StellarResult<T>>,
    {
        self.allow_call().await?;
        let result = operation().await;
        self.record_result(&result).await;
        result
    }

    async fn allow_call(&self) -> StellarResult<()> {
        loop {
            let current = self.state.load(Ordering::Relaxed);
            match current {
                s if s == (CircuitState::Closed as usize) => return Ok(()),
                s if s == (CircuitState::Open as usize) => {
                    let opened_at = *self.opened_at.lock().unwrap();
                    if let Some(opened_at) = opened_at {
                        let elapsed = opened_at.elapsed();
                        if elapsed >= self.config.open_duration {
                            let expected = CircuitState::HalfOpen as usize;
                            if self
                                .state
                                .compare_exchange(
                                    current,
                                    expected,
                                    Ordering::Relaxed,
                                    Ordering::Relaxed,
                                )
                                .is_ok()
                            {
                                self.half_open_in_flight.store(0, Ordering::Relaxed);
                                self.half_open_successes.store(0, Ordering::Relaxed);
                                return Ok(());
                            }
                            continue;
                        }
                        let retry_after = self.config.open_duration.saturating_sub(elapsed);
                        self.increment_rejected_calls();
                        return Err(StellarError::CircuitOpen {
                            state: CircuitState::Open,
                            retry_after,
                        });
                    }
                    let expected = CircuitState::HalfOpen as usize;
                    if self
                        .state
                        .compare_exchange(current, expected, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                    {
                        self.half_open_in_flight.store(0, Ordering::Relaxed);
                        self.half_open_successes.store(0, Ordering::Relaxed);
                        return Ok(());
                    }
                    continue;
                }
                s if s == (CircuitState::HalfOpen as usize) => {
                    let _max_calls = self.config.half_open_max_calls.max(1) as usize;
                    let permit = self.half_open_semaphore.try_acquire();
                    if permit.is_err() {
                        self.increment_rejected_calls();
                        return Err(StellarError::CircuitOpen {
                            state: CircuitState::HalfOpen,
                            retry_after: Duration::ZERO,
                        });
                    }
                    self.half_open_in_flight.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                _ => return Ok(()),
            }
        }
    }

    async fn record_result<T>(&self, result: &StellarResult<T>) {
        match result {
            Ok(_) => self.record_success().await,
            Err(err) if err.affects_circuit_breaker() => self.record_failure(err).await,
            Err(_) => {}
        }
    }

    async fn record_success(&self) {
        let current = self.state.load(Ordering::Relaxed);
        if current == (CircuitState::Closed as usize) {
            self.consecutive_failures.store(0, Ordering::Relaxed);
            self.increment_successful_calls();
            return;
        }
        if current == (CircuitState::HalfOpen as usize) {
            self.half_open_in_flight.fetch_sub(1, Ordering::Relaxed);
            let successes = self.half_open_successes.fetch_add(1, Ordering::Relaxed) + 1;
            let should_close =
                successes >= self.config.half_open_max_calls.max(1).try_into().unwrap();
            self.increment_successful_calls();
            self.increment_half_open_successes();
            if should_close {
                let expected = CircuitState::HalfOpen as usize;
                let closed = CircuitState::Closed as usize;
                if self
                    .state
                    .compare_exchange(expected, closed, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    self.opened_at.lock().unwrap().take();
                    self.consecutive_failures.store(0, Ordering::Relaxed);
                    self.increment_recoveries();
                }
            }
        }
    }

    async fn record_failure(&self, err: &StellarError) {
        let current = self.state.load(Ordering::Relaxed);
        if current == (CircuitState::Closed as usize) {
            let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
            match err {
                StellarError::Timeout { .. } => self.increment_timeout_calls(),
                StellarError::RetryableHttpStatus { .. } => self.increment_retryable_http_calls(),
                _ => {}
            }
            self.increment_failed_calls();
            if failures >= self.config.failure_threshold.max(1).try_into().unwrap() {
                let expected = CircuitState::Closed as usize;
                let open = CircuitState::Open as usize;
                if self
                    .state
                    .compare_exchange(expected, open, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    *self.opened_at.lock().unwrap() = Some(Instant::now());
                    self.increment_trips();
                }
            }
            return;
        }
        if current == (CircuitState::HalfOpen as usize) {
            self.half_open_in_flight.fetch_sub(1, Ordering::Relaxed);
            let expected = CircuitState::HalfOpen as usize;
            let open = CircuitState::Open as usize;
            if self
                .state
                .compare_exchange(expected, open, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                *self.opened_at.lock().unwrap() = Some(Instant::now());
                self.increment_trips();
                self.increment_failed_calls();
                self.increment_half_open_failures();
            }
        }
    }

    fn increment_trips(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.trips = metrics.trips.saturating_add(1);
    }

    fn increment_recoveries(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.recoveries = metrics.recoveries.saturating_add(1);
    }

    fn increment_rejected_calls(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.rejected_calls = metrics.rejected_calls.saturating_add(1);
    }

    fn increment_successful_calls(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.successful_calls = metrics.successful_calls.saturating_add(1);
    }

    fn increment_failed_calls(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.failed_calls = metrics.failed_calls.saturating_add(1);
    }

    fn increment_timeout_calls(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.timeout_calls = metrics.timeout_calls.saturating_add(1);
    }

    fn increment_retryable_http_calls(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.retryable_http_calls = metrics.retryable_http_calls.saturating_add(1);
    }

    fn increment_half_open_successes(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.half_open_successes = metrics.half_open_successes.saturating_add(1);
    }

    fn increment_half_open_failures(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.half_open_failures = metrics.half_open_failures.saturating_add(1);
    }
}

impl fmt::Display for CircuitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "closed"),
            Self::Open => write!(f, "open"),
            Self::HalfOpen => write!(f, "half-open"),
        }
    }
}

fn trim_trailing_slash(value: &str) -> String {
    value.trim_end_matches('/').to_string()
}

fn is_retryable_status(status: u16) -> bool {
    status == 408 || status == 429 || (500..=599).contains(&status)
}

fn jittered_delay_full(max_delay: Duration) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let fraction = nanos as f64 / 1_000_000_000.0;
    let millis = (max_delay.as_secs_f64() * 1000.0 * fraction).round() as u64;
    Duration::from_millis(millis)
}

fn jittered_delay_equal(max_delay: Duration) -> Duration {
    let millis = (max_delay.as_secs_f64() * 1000.0 / 2.0).round() as u64;
    Duration::from_millis(millis)
}

fn jittered_delay_decorrelated(base: Duration, _attempt: u32) -> Duration {
    let mut rng = rand::thread_rng();
    let millis = base.as_millis() as u64;
    let decorrelated = millis.saturating_mul(3).saturating_div(4);
    let jitter = rng.gen_range(0..decorrelated.max(1));
    Duration::from_millis(jitter.min(base.as_millis() as u64))
}

async fn sleep(delay: Duration) {
    if delay.is_zero() {
        tokio::task::yield_now().await;
    } else {
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config() -> StellarClientConfig {
        StellarClientConfig {
            retry: RetryPolicy {
                max_retries: 3,
                base_delay: Duration::ZERO,
                max_delay: Duration::from_millis(1),
                jitter: RetryJitter::None,
            },
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 5,
                open_duration: Duration::from_millis(20),
                half_open_max_calls: 1,
            },
            request_timeout: Duration::from_secs(2),
            rate_limit_per_second: 100,
            rate_limit_burst: 100,
            bulkhead: BulkheadConfig::default(),
            graceful_degradation: GracefulDegradationConfig::default(),
        }
    }

    fn horizon_success_body() -> serde_json::Value {
        json!({
            "_embedded": {
                "records": [
                    {
                        "id": "transaction-id",
                        "memo": CANONICAL_TEST_HASH,
                        "memo_type": "text",
                        "created_at": "2024-01-01T00:00:00Z"
                    }
                ]
            }
        })
    }

    /// Canonical SHA-256 hex string used by retry/circuit-breaker tests. Must be
    /// valid lowercase hex so it passes the boundary canonicalization check.
    const CANONICAL_TEST_HASH: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[tokio::test]
    async fn verify_hash_with_retry_succeeds_after_transient_failures() {
        let server = MockServer::start().await;
        let hash = CANONICAL_TEST_HASH;

        Mock::given(method("GET"))
            .and(path("/transactions"))
            .and(query_param("memo", hash))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/transactions"))
            .and(query_param("memo", hash))
            .respond_with(ResponseTemplate::new(200).set_body_json(horizon_success_body()))
            .expect(1)
            .mount(&server)
            .await;

        let client = StellarClient::with_config(&server.uri(), test_config());
        let result = client.verify_hash_with_retry(hash).await.unwrap();

        assert!(result.verified());
        assert_eq!(result.transaction_id.as_deref(), Some("transaction-id"));
        assert_eq!(result.timestamp, Some(1_704_067_200));
        assert_eq!(client.circuit_breaker_metrics().successful_calls, 1);
    }

    #[tokio::test]
    async fn verify_hash_with_retry_reports_attempts_and_final_error() {
        let server = MockServer::start().await;
        let hash = CANONICAL_TEST_HASH;
        let mut config = test_config();
        config.retry.max_retries = 1;
        config.circuit_breaker.failure_threshold = 1;

        Mock::given(method("GET"))
            .and(path("/transactions"))
            .and(query_param("memo", hash))
            .respond_with(ResponseTemplate::new(503))
            .expect(2)
            .mount(&server)
            .await;

        let client = StellarClient::with_config(&server.uri(), config);
        let err = client.verify_hash_with_retry(hash).await.unwrap_err();

        match err {
            StellarError::RetryExhausted {
                attempts,
                retries_attempted,
                final_error,
                ..
            } => {
                assert_eq!(attempts, 2);
                assert_eq!(retries_attempted, 1);
                assert!(final_error.to_string().contains("HTTP 503"));
            }
            other => panic!("expected RetryExhausted, got {other:?}"),
        }

        assert_eq!(client.circuit_state(), CircuitState::Open);
        assert_eq!(client.circuit_breaker_metrics().trips, 1);
    }

    #[tokio::test]
    async fn circuit_breaker_rejects_calls_while_open() {
        let server = MockServer::start().await;
        let hash = CANONICAL_TEST_HASH;
        let mut config = test_config();
        config.retry.max_retries = 0;
        config.circuit_breaker.failure_threshold = 1;
        config.circuit_breaker.open_duration = Duration::from_millis(50);

        Mock::given(method("GET"))
            .and(path("/transactions"))
            .and(query_param("memo", hash))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let client = StellarClient::with_config(&server.uri(), config);
        let _ = client.verify_hash_with_retry(hash).await.unwrap_err();

        assert_eq!(client.circuit_state(), CircuitState::Open);

        let err = client.verify_hash_with_retry(hash).await.unwrap_err();
        match err {
            StellarError::CircuitOpen { state, retry_after } => {
                assert_eq!(state, CircuitState::Open);
                assert!(retry_after <= Duration::from_millis(50));
            }
            other => panic!("expected CircuitOpen, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn circuit_breaker_recovers_from_half_open_success() {
        let server = MockServer::start().await;
        let hash = CANONICAL_TEST_HASH;
        let mut config = test_config();
        config.retry.max_retries = 0;
        config.circuit_breaker.failure_threshold = 1;
        config.circuit_breaker.open_duration = Duration::from_millis(10);

        Mock::given(method("GET"))
            .and(path("/transactions"))
            .and(query_param("memo", hash))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/transactions"))
            .and(query_param("memo", hash))
            .respond_with(ResponseTemplate::new(200).set_body_json(horizon_success_body()))
            .expect(1)
            .mount(&server)
            .await;

        let client = StellarClient::with_config(&server.uri(), config);
        let _ = client.verify_hash_with_retry(hash).await.unwrap_err();
        tokio::time::sleep(Duration::from_millis(15)).await;
        let result = client.verify_hash_with_retry(hash).await.unwrap();

        assert!(result.verified());
        assert_eq!(client.circuit_state(), CircuitState::Closed);
        assert_eq!(client.circuit_breaker_metrics().recoveries, 1);
        assert_eq!(client.circuit_breaker_metrics().half_open_successes, 1);
    }

    #[test]
    fn retry_delay_uses_exponential_backoff_without_jitter() {
        let client = StellarClient::with_config(
            "https://horizon-testnet.stellar.org",
            StellarClientConfig {
                retry: RetryPolicy {
                    max_retries: 3,
                    base_delay: Duration::from_millis(100),
                    max_delay: Duration::from_secs(10),
                    jitter: RetryJitter::None,
                },
                ..StellarClientConfig::default()
            },
        );

        assert_eq!(client.retry_delay(0), Duration::from_millis(100));
        assert_eq!(client.retry_delay(1), Duration::from_millis(200));
        assert_eq!(client.retry_delay(2), Duration::from_millis(400));
    }

    #[test]
    fn client_accepts_optional_metrics() {
        let client = StellarClient::new("https://horizon-testnet.stellar.org");
        let metrics = MetricsRegistry::arc();
        let client = client.with_metrics(metrics);
        assert!(client.metrics.is_some());
    }

    #[test]
    fn verification_cache_key_is_consistent() {
        let key = StellarClient::verification_cache_key("abc123");
        assert_eq!(key.as_string(), "verification:abc123");
    }

    #[test]
    fn verification_cache_key_normalizes_uppercase() {
        let key = StellarClient::verification_cache_key("ABC123");
        assert_eq!(key.as_string(), "verification:abc123");
    }

    #[test]
    fn verification_result_verified_convenience() {
        let confirmed = VerificationResult {
            status: VerificationStatus::ConfirmedMatch,
            transaction_id: Some("tx123".into()),
            timestamp: Some(12345),
            last_http_status: None,
        };
        assert!(confirmed.verified());

        let no_match = VerificationResult {
            status: VerificationStatus::NoMatch,
            transaction_id: None,
            timestamp: None,
            last_http_status: None,
        };
        assert!(!no_match.verified());
    }

    /// ── Mocked Horizon tests ──────────────────────────────────────────
    ///
    /// These tests use `wiremock` to stand up a local HTTP server that
    /// simulates Horizon responses.  See `Cargo.toml` `[dev-dependencies]`.

    #[cfg(test)]
    mod horizon_mock {
        use super::*;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// Sample Horizon transaction JSON that matches a known hash.
        fn horizon_tx_json(id: &str, memo: &str, created_at: &str) -> serde_json::Value {
            serde_json::json!({
                "_embedded": {
                    "records": [{
                        "id": id,
                        "created_at": created_at,
                        "memo": memo,
                        "memo_type": "text"
                    }]
                }
            })
        }

        /// Empty Horizon response (no matching transactions).
        fn horizon_empty_json() -> serde_json::Value {
            serde_json::json!({
                "_embedded": {
                    "records": []
                }
            })
        }

        #[tokio::test]
        async fn verify_hash_returns_confirmed_match_when_memo_matches() {
            let server = MockServer::start().await;
            let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

            Mock::given(method("GET"))
                .and(path("transactions"))
                .and(query_param("memo", hash))
                .respond_with(ResponseTemplate::new(200).set_body_json(horizon_tx_json(
                    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    hash,
                    "2024-01-15T10:30:00Z",
                )))
                .mount(&server)
                .await;

            let client = StellarClient::new(&server.uri()).with_max_retries(0);

            let result = client.verify_hash(hash).await;

            assert_eq!(result.status, VerificationStatus::ConfirmedMatch);
            assert!(result.transaction_id.is_some());
            assert!(result.timestamp.unwrap() > 0);
        }

        #[tokio::test]
        async fn verify_hash_returns_no_match_when_horizon_empty() {
            let server = MockServer::start().await;
            let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

            Mock::given(method("GET"))
                .and(path("transactions"))
                .and(query_param("memo", hash))
                .respond_with(ResponseTemplate::new(200).set_body_json(horizon_empty_json()))
                .mount(&server)
                .await;

            let client = StellarClient::new(&server.uri()).with_max_retries(0);

            let result = client.verify_hash(hash).await;

            assert_eq!(result.status, VerificationStatus::NoMatch);
            assert!(!result.verified());
        }

        #[tokio::test]
        async fn verify_hash_returns_no_match_when_memo_mismatch() {
            let server = MockServer::start().await;
            let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

            // Horizon returns a transaction, but its memo doesn't match
            Mock::given(method("GET"))
                .and(path("transactions"))
                .and(query_param("memo", hash))
                .respond_with(ResponseTemplate::new(200).set_body_json(horizon_tx_json(
                    "tx123",
                    "wrong-hash-0000000000000000000000000000000000000000000000000000",
                    "2024-01-15T10:30:00Z",
                )))
                .mount(&server)
                .await;

            let client = StellarClient::new(&server.uri()).with_max_retries(0);

            let result = client.verify_hash(hash).await;

            assert_eq!(result.status, VerificationStatus::NoMatch);
            assert!(!result.verified());
        }

        #[tokio::test]
        async fn verify_hash_returns_network_error_on_http_500() {
            let server = MockServer::start().await;
            let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

            Mock::given(method("GET"))
                .and(path("transactions"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&server)
                .await;

            let client = StellarClient::new(&server.uri()).with_max_retries(0);

            let result = client.verify_hash(hash).await;

            assert_eq!(result.status, VerificationStatus::NetworkError);
            assert!(!result.verified());
        }

        #[tokio::test]
        async fn verify_hash_returns_malformed_response_for_invalid_json() {
            let server = MockServer::start().await;
            let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

            Mock::given(method("GET"))
                .and(path("transactions"))
                .respond_with(ResponseTemplate::new(200).set_body_string("not-valid-json{{{"))
                .mount(&server)
                .await;

            let client = StellarClient::new(&server.uri()).with_max_retries(0);

            let result = client.verify_hash(hash).await;

            assert_eq!(result.status, VerificationStatus::MalformedResponse);
            assert!(!result.verified());
        }

        #[tokio::test]
        async fn verify_hash_retries_on_transient_errors() {
            let server = MockServer::start().await;
            let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

            // First two attempts return 500, third succeeds
            Mock::given(method("GET"))
                .and(path("transactions"))
                .and(query_param("memo", hash))
                .respond_with(ResponseTemplate::new(500))
                .up_to_n_times(2)
                .expect(2)
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("transactions"))
                .and(query_param("memo", hash))
                .respond_with(ResponseTemplate::new(200).set_body_json(horizon_tx_json(
                    "tx-retry-ok",
                    hash,
                    "2024-01-15T10:30:00Z",
                )))
                .mount(&server)
                .await;

            let client = StellarClient::new(&server.uri())
                .with_max_retries(3)
                .with_metrics(MetricsRegistry::arc());

            let result = client.verify_hash(hash).await;

            assert_eq!(result.status, VerificationStatus::ConfirmedMatch);
            assert!(result.verified());
        }

        #[tokio::test]
        async fn verify_hash_exhausts_retries_on_persistent_errors() {
            let server = MockServer::start().await;
            let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

            Mock::given(method("GET"))
                .and(path("transactions"))
                .respond_with(ResponseTemplate::new(500))
                .expect(4) // initial + 3 retries
                .mount(&server)
                .await;

            let client = StellarClient::new(&server.uri()).with_max_retries(3);

            let result = client.verify_hash(hash).await;

            assert_eq!(result.status, VerificationStatus::NetworkError);
            assert!(!result.verified());
        }
    }
}

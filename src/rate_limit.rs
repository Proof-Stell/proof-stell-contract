use dashmap::DashMap;
use governor::{
    clock::{Clock, QuantaClock},
    Quota, RateLimiter,
};
use std::{
    num::NonZeroU32,
    string::{String, ToString},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{cache::CacheKey, metrics::MetricsRegistry};

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Type aliases ─────────────────────────────────────────────────────────────

/// Global (unkeyed) rate limiter backed by the Quanta monotonic clock.
pub type GlobalRateLimiter =
    RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, QuantaClock>;

// ── Fixed-point token accounting ─────────────────────────────────────────────

/// Tokens are tracked in thousandths of a token ("milli-tokens") so that
/// sub-token, per-second refill is represented exactly with integer math — no
/// floating point, hence no rounding drift between hosts.
const MILLI: u64 = 1000;

/// Pack `(last_refill_secs, milli_tokens)` into a single `u64` for atomic CAS.
///
/// `last_refill` occupies the high 32 bits (Unix seconds, valid until 2106) and
/// milli-tokens the low 32 bits.
#[inline]
fn pack(secs: u32, milli: u32) -> u64 {
    ((secs as u64) << 32) | (milli as u64)
}

/// Inverse of [`pack`].
#[inline]
fn unpack(v: u64) -> (u32, u32) {
    ((v >> 32) as u32, (v & 0xFFFF_FFFF) as u32)
}

/// Deterministic per-issuer jitter in `[0, window)` seconds.
///
/// Derived from an FNV-1a hash of the issuer key, so it is stable for a given
/// issuer across processes and restarts (no RNG, no wall-clock input) — which is
/// what lets reset times be reproduced deterministically while still spreading
/// distinct issuers across the window to break up synchronized retries.
fn deterministic_jitter(issuer: &str, window: u64) -> u64 {
    if window == 0 {
        return 0;
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in issuer.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash % window
}

/// Outcome of a single [`AtomicTokenBucket::try_consume`] call.
struct ConsumeOutcome {
    /// Whether a token was granted.
    granted: bool,
    /// Milli-tokens added by time-based refill during this call.
    refilled_milli: u64,
    /// Whether the bucket refilled from fully empty (a bucket "reset").
    reset: bool,
}

/// A lock-free token bucket for a single issuer.
///
/// Current tokens (milli-tokens) and the last-refill timestamp are packed into
/// one [`AtomicU64`] and mutated with a compare-and-swap retry loop, so every
/// refill+consume is a single atomic read-modify-write. Concurrent callers
/// racing on the same issuer either succeed on disjoint CAS iterations or retry
/// on a lost race — **no token is ever lost or double-spent**, and elapsed time
/// is folded into the stored timestamp even when a call is rejected so accrued
/// refill is never dropped.
struct AtomicTokenBucket {
    state: AtomicU64,
    /// Capacity in milli-tokens (`burst * 1000`, clamped to `u32`).
    capacity_milli: u32,
    /// Refill rate in milli-tokens per second (`per_second * 1000`).
    refill_milli_per_sec: u32,
    /// Deterministic jitter (seconds) added to reported reset times.
    jitter_offset: u64,
}

impl AtomicTokenBucket {
    fn new(burst: u32, per_second: u32, jitter_seconds: u64, issuer: &str, now: u64) -> Self {
        // Clamp so `units * 1000` cannot overflow a u32.
        let max_units = (u32::MAX / MILLI as u32).max(1);
        let burst = burst.clamp(1, max_units);
        let per_second = per_second.clamp(1, max_units);
        let capacity_milli = burst * MILLI as u32;
        let refill_milli_per_sec = per_second * MILLI as u32;
        let jitter_offset = deterministic_jitter(issuer, jitter_seconds);
        Self {
            state: AtomicU64::new(pack(now as u32, capacity_milli)),
            capacity_milli,
            refill_milli_per_sec,
            jitter_offset,
        }
    }

    /// Tokens after folding in time-based refill from `last` up to `now`.
    #[inline]
    fn refilled(&self, tokens_milli: u32, last: u32, now: u64) -> u32 {
        let elapsed = now.saturating_sub(last as u64);
        let add = elapsed.saturating_mul(self.refill_milli_per_sec as u64);
        ((tokens_milli as u64) + add).min(self.capacity_milli as u64) as u32
    }

    /// Attempt to consume one token, refilling atomically first.
    fn try_consume(&self, now: u64) -> ConsumeOutcome {
        loop {
            let cur = self.state.load(Ordering::Acquire);
            let (last, tokens_milli) = unpack(cur);
            let refilled = self.refilled(tokens_milli, last, now);
            let refill_added = refilled.saturating_sub(tokens_milli) as u64;
            let reset = tokens_milli == 0 && refilled > 0;

            if refilled >= MILLI as u32 {
                let next = pack(now as u32, refilled - MILLI as u32);
                if self
                    .state
                    .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return ConsumeOutcome {
                        granted: true,
                        refilled_milli: refill_added,
                        reset,
                    };
                }
            } else {
                // Not enough for a whole token. Still persist any refill and the
                // advanced clock so accrued time is not lost on rejection.
                let next = pack(now as u32, refilled);
                if cur == next {
                    return ConsumeOutcome {
                        granted: false,
                        refilled_milli: 0,
                        reset: false,
                    };
                }
                if self
                    .state
                    .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return ConsumeOutcome {
                        granted: false,
                        refilled_milli: refill_added,
                        reset,
                    };
                }
            }
            // CAS lost to a concurrent caller — retry with the fresh value.
        }
    }

    /// Read-only view of `(remaining_whole_tokens, reset_at)` at `now`.
    fn snapshot(&self, now: u64) -> (u32, u64) {
        let (last, tokens_milli) = unpack(self.state.load(Ordering::Acquire));
        let refilled = self.refilled(tokens_milli, last, now);
        (refilled / MILLI as u32, self.reset_at(refilled, now))
    }

    /// Deterministic Unix second at which the bucket is full again, including
    /// the per-issuer jitter offset. Computed purely from integer state, so it
    /// does not drift between reads within the same second.
    fn reset_at(&self, tokens_milli: u32, now: u64) -> u64 {
        let deficit = self.capacity_milli.saturating_sub(tokens_milli) as u64;
        let secs_to_full = if self.refill_milli_per_sec == 0 {
            0
        } else {
            deficit.div_ceil(self.refill_milli_per_sec as u64)
        };
        now + secs_to_full + self.jitter_offset
    }

    /// Whole seconds until at least one token is available (min 1 when empty).
    fn time_to_next_token(&self, now: u64) -> u64 {
        let (last, tokens_milli) = unpack(self.state.load(Ordering::Acquire));
        let refilled = self.refilled(tokens_milli, last, now);
        if refilled >= MILLI as u32 {
            return 0;
        }
        if self.refill_milli_per_sec == 0 {
            return 1;
        }
        let deficit = MILLI - refilled as u64;
        deficit.div_ceil(self.refill_milli_per_sec as u64).max(1)
    }

    /// Last time the bucket state was touched (Unix seconds), for TTL eviction.
    fn last_seen(&self) -> u64 {
        unpack(self.state.load(Ordering::Acquire)).0 as u64
    }
}

/// Serializable projection of a bucket, persisted to the shared cache so that
/// warm restarts and multi-node deployments can observe recent quota state.
#[derive(serde::Serialize, serde::Deserialize)]
struct IssuerBucketSnapshot {
    remaining: u32,
    reset_at: u64,
}

// ── Rate limit status ─────────────────────────────────────────────────────────

/// Current quota status for a single issuer.
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    /// The issuer DID / key this status belongs to.
    pub issuer: String,
    /// Remaining tokens in the per-issuer bucket.
    pub remaining: u32,
    /// Unix timestamp (seconds) when the per-issuer bucket fully refills,
    /// including the deterministic per-issuer jitter offset.
    pub reset_at: u64,
    /// Whether the global limiter is currently saturated.
    pub global_throttled: bool,
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// Rate-limiting configuration for both global and per-issuer tiers.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Global requests permitted per second across all issuers.
    pub global_per_second: u32,
    /// Global burst allowance.
    pub global_burst: u32,
    /// Per-issuer requests permitted per second.
    pub per_issuer_per_second: u32,
    /// Per-issuer burst allowance.
    pub per_issuer_burst: u32,
    /// How long an issuer bucket is kept alive after its last access (seconds).
    pub issuer_ttl_seconds: u64,
    /// Maximum deterministic jitter (seconds) added per issuer to reset times
    /// to prevent synchronized refills / thundering-herd retries. `0` disables.
    pub jitter_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_per_second: 100,
            global_burst: 200,
            per_issuer_per_second: 10,
            per_issuer_burst: 20,
            issuer_ttl_seconds: 3600,
            jitter_seconds: 0,
        }
    }
}

// ── Two-tier rate limiter ────────────────────────────────────────────────────

/// Two-tier, metrics-aware rate limiter.
///
/// **Tier 1 – Global**: a single unkeyed `governor` bucket shared across every
/// caller. **Tier 2 – Per-issuer**: a `DashMap` of lock-free
/// [`AtomicTokenBucket`]s, one per issuer address, each performing atomic
/// compare-and-swap token refill/consume.
///
/// Both tiers must pass before a request is accepted. The global tier always
/// takes precedence: if it is saturated the per-issuer check is skipped so that
/// per-issuer token counts stay accurate.
pub struct PerIssuerRateLimiter {
    global: Arc<GlobalRateLimiter>,
    buckets: Arc<DashMap<String, AtomicTokenBucket>>,
    config: RateLimitConfig,
    metrics: Option<Arc<MetricsRegistry>>,
    cache: Option<Arc<crate::cache::CacheBackend>>,
}

impl PerIssuerRateLimiter {
    /// Construct a new two-tier limiter from explicit config.
    pub fn new(config: RateLimitConfig, metrics: Option<Arc<MetricsRegistry>>) -> Self {
        let global_quota =
            Quota::per_second(NonZeroU32::new(config.global_per_second.max(1)).unwrap())
                .allow_burst(NonZeroU32::new(config.global_burst.max(1)).unwrap());
        let global = Arc::new(RateLimiter::direct(global_quota));

        Self {
            global,
            buckets: Arc::new(DashMap::new()),
            config,
            metrics,
            cache: None,
        }
    }

    /// Construct from the application `AppConfig`.
    pub fn from_config(
        cfg: &crate::config::AppConfig,
        metrics: Option<Arc<MetricsRegistry>>,
    ) -> Self {
        Self::new(
            RateLimitConfig {
                global_per_second: cfg.rate_limit_per_second,
                global_burst: cfg.rate_limit_burst,
                per_issuer_per_second: cfg.per_issuer_rate_limit_per_second,
                per_issuer_burst: cfg.per_issuer_rate_limit_burst,
                issuer_ttl_seconds: cfg.issuer_rate_limit_ttl_seconds,
                jitter_seconds: cfg.per_issuer_rate_limit_jitter_seconds,
            },
            metrics,
        )
    }

    pub fn with_cache(mut self, cache: Arc<crate::cache::CacheBackend>) -> Self {
        self.cache = Some(cache);
        self
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Non-blocking check for `issuer`.
    ///
    /// Returns `Ok(())` if both tiers permit the request, or a
    /// [`RateLimitError`] describing which tier rejected it.
    pub fn check(&self, issuer: &str) -> Result<(), RateLimitError> {
        // ── Tier 1: global ────────────────────────────────────────────────
        if let Err(not_until) = self.global.check() {
            if let Some(ref m) = self.metrics {
                m.increment_rate_limit_global_rejection(issuer);
                m.increment_rate_limit_violation();
            }
            let retry_after = not_until.wait_time_from(self.global_clock());
            return Err(RateLimitError::GlobalExhausted { retry_after });
        }

        // ── Tier 2: per-issuer atomic token bucket ────────────────────────
        let now = now_secs();
        let outcome = self.consume_issuer(issuer, now);
        if !outcome.granted {
            if let Some(ref m) = self.metrics {
                m.increment_rate_limit_issuer_rejection(issuer);
                m.increment_rate_limit_violation();
            }
            let retry_after = Duration::from_secs(self.next_token_wait(issuer, now));
            return Err(RateLimitError::IssuerExhausted {
                issuer: issuer.to_string(),
                retry_after,
            });
        }

        // ── Success: record metrics & persist snapshot ────────────────────
        self.record_success(issuer, &outcome, now);
        Ok(())
    }

    /// Async blocking wait until both tiers permit the request.
    pub async fn until_ready(&self, issuer: &str) {
        self.global.until_ready().await;
        loop {
            let now = now_secs();
            let outcome = self.consume_issuer(issuer, now);
            if outcome.granted {
                self.record_success(issuer, &outcome, now);
                return;
            }
            let wait = self.next_token_wait(issuer, now).max(1);
            tokio::time::sleep(Duration::from_secs(wait)).await;
        }
    }

    /// Return the current quota status for `issuer` without consuming a token.
    pub fn status(&self, issuer: &str) -> RateLimitStatus {
        let now = now_secs();
        let (remaining, reset_at) = match self.buckets.get(issuer) {
            Some(b) => b.snapshot(now),
            None => (
                self.config.per_issuer_burst,
                now + deterministic_jitter(issuer, self.config.jitter_seconds),
            ),
        };
        let global_throttled = self.global.check().is_err();
        RateLimitStatus {
            issuer: issuer.to_string(),
            remaining,
            reset_at,
            global_throttled,
        }
    }

    /// Evict issuer buckets not seen within `issuer_ttl_seconds`.
    ///
    /// Call this periodically (e.g. from a background task) to bound memory use.
    pub fn evict_stale(&self) {
        let cutoff = now_secs().saturating_sub(self.config.issuer_ttl_seconds);
        self.buckets.retain(|_, b| b.last_seen() >= cutoff);
    }

    /// Return the number of tracked issuers currently in the bucket map.
    pub fn tracked_issuers(&self) -> usize {
        self.buckets.len()
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    /// Consume one token from `issuer`'s bucket, creating it on first use.
    fn consume_issuer(&self, issuer: &str, now: u64) -> ConsumeOutcome {
        // Fast path: bucket exists — a shared reference is all CAS needs, so
        // concurrent callers contend only on the atomic, not on the map.
        if let Some(bucket) = self.buckets.get(issuer) {
            return bucket.try_consume(now);
        }
        // Slow path: create on first use. `or_insert_with` is atomic, so a race
        // to create the same issuer yields a single shared bucket.
        let bucket = self.buckets.entry(issuer.to_string()).or_insert_with(|| {
            AtomicTokenBucket::new(
                self.config.per_issuer_burst,
                self.config.per_issuer_per_second,
                self.config.jitter_seconds,
                issuer,
                now,
            )
        });
        bucket.try_consume(now)
    }

    fn next_token_wait(&self, issuer: &str, now: u64) -> u64 {
        self.buckets
            .get(issuer)
            .map(|b| b.time_to_next_token(now))
            .unwrap_or(0)
            .max(1)
    }

    fn record_success(&self, issuer: &str, outcome: &ConsumeOutcome, now: u64) {
        if let Some(ref m) = self.metrics {
            m.increment_rate_limit_hit(issuer);
            m.record_token_consumed();
            m.record_tokens_refilled(outcome.refilled_milli / MILLI);
            if outcome.reset {
                m.increment_rate_limit_reset();
            }
        }

        if let Some(cache) = &self.cache {
            if let Some(bucket) = self.buckets.get(issuer) {
                let (remaining, reset_at) = bucket.snapshot(now);
                let snapshot = IssuerBucketSnapshot {
                    remaining,
                    reset_at,
                };
                let cache_key = CacheKey::Config(format!("rate_limit:{}", issuer));
                if let Ok(serialized) = serde_json::to_string(&snapshot) {
                    let _ = cache.set_raw(&cache_key, &serialized, self.config.issuer_ttl_seconds);
                }
            }
        }
    }

    fn global_clock(&self) -> governor::clock::QuantaInstant {
        governor::clock::Clock::now(&QuantaClock::default())
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by [`PerIssuerRateLimiter::check`].
#[derive(Debug)]
pub enum RateLimitError {
    /// The shared global bucket is exhausted.
    GlobalExhausted { retry_after: Duration },
    /// The per-issuer bucket for this caller is exhausted.
    IssuerExhausted {
        issuer: String,
        retry_after: Duration,
    },
}

impl RateLimitError {
    /// Seconds to wait before the next attempt (for `Retry-After` header).
    pub fn retry_after_secs(&self) -> u64 {
        match self {
            Self::GlobalExhausted { retry_after } => retry_after.as_secs().max(1),
            Self::IssuerExhausted { retry_after, .. } => retry_after.as_secs().max(1),
        }
    }

    /// Human-readable reason string suitable for an HTTP 429 body.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::GlobalExhausted { .. } => "global rate limit exceeded",
            Self::IssuerExhausted { .. } => "per-issuer rate limit exceeded",
        }
    }
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GlobalExhausted { retry_after } => write!(
                f,
                "global rate limit exceeded; retry after {}s",
                retry_after.as_secs()
            ),
            Self::IssuerExhausted {
                issuer,
                retry_after,
            } => write!(
                f,
                "per-issuer rate limit exceeded for '{}'; retry after {}s",
                issuer,
                retry_after.as_secs()
            ),
        }
    }
}

impl std::error::Error for RateLimitError {}

// ── Legacy global limiter (kept for backward-compat) ─────────────────────────

/// Build a bare global `governor::RateLimiter` without metrics (legacy compatibility).
pub fn build_rate_limiter(per_second: u32, burst: u32) -> GlobalRateLimiter {
    let quota = Quota::per_second(NonZeroU32::new(per_second.max(1)).unwrap())
        .allow_burst(NonZeroU32::new(burst.max(1)).unwrap());
    RateLimiter::direct(quota)
}

#[derive(Debug)]
pub struct StellarRateLimiter {
    inner: GlobalRateLimiter,
}

impl StellarRateLimiter {
    pub fn new(per_second: u32, burst: u32) -> Self {
        Self {
            inner: build_rate_limiter(per_second, burst),
        }
    }

    pub fn try_acquire(&self) -> bool {
        self.inner.check().is_ok()
    }

    pub async fn acquire(&self) {
        loop {
            match self.inner.check() {
                Ok(()) => return,
                Err(negative) => {
                    let delay = negative.wait_time_from(QuantaClock::default().now());
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    pub fn wait_time(&self) -> Option<Duration> {
        self.inner
            .check()
            .err()
            .map(|negative| negative.wait_time_from(QuantaClock::default().now()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::thread;
    use std::vec::Vec;

    fn test_config(global_rps: u32, issuer_rps: u32) -> RateLimitConfig {
        RateLimitConfig {
            global_per_second: global_rps,
            global_burst: global_rps * 2,
            per_issuer_per_second: issuer_rps,
            per_issuer_burst: issuer_rps * 2,
            issuer_ttl_seconds: 60,
            jitter_seconds: 0,
        }
    }

    #[test]
    fn allows_request_within_limits() {
        let limiter = PerIssuerRateLimiter::new(test_config(100, 10), None);
        assert!(limiter.check("issuer-A").is_ok());
    }

    #[test]
    fn different_issuers_have_independent_buckets() {
        // Give each issuer a burst of 2 so we can exhaust one without touching the other.
        let cfg = RateLimitConfig {
            global_per_second: 1000,
            global_burst: 1000,
            per_issuer_per_second: 1,
            per_issuer_burst: 2,
            issuer_ttl_seconds: 60,
            jitter_seconds: 0,
        };
        let limiter = PerIssuerRateLimiter::new(cfg, None);

        // Exhaust issuer-A
        let _ = limiter.check("issuer-A");
        let _ = limiter.check("issuer-A");
        let a_result = limiter.check("issuer-A");

        // issuer-B should still be fine
        let b_result = limiter.check("issuer-B");

        assert!(
            a_result.is_err(),
            "issuer-A should be exhausted after burst"
        );
        assert!(b_result.is_ok(), "issuer-B bucket should be independent");
    }

    #[test]
    fn rate_limiter_allows_burst_within_configured_limit() {
        let limiter = StellarRateLimiter::new(1, 2);

        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn metrics_rate_limiter_consumes_token_on_check() {
        let metrics = MetricsRegistry::arc();
        let limiter = PerIssuerRateLimiter::new(test_config(100, 10), Some(Arc::clone(&metrics)));

        limiter.check("issuer-M").unwrap();

        let output = metrics.render();
        assert!(output.contains("rate_limit_hits_total"));
    }

    #[test]
    fn metrics_incremented_on_issuer_rejection() {
        let metrics = MetricsRegistry::arc();
        let cfg = RateLimitConfig {
            global_per_second: 1000,
            global_burst: 1000,
            per_issuer_per_second: 1,
            per_issuer_burst: 1,
            issuer_ttl_seconds: 60,
            jitter_seconds: 0,
        };
        let limiter = PerIssuerRateLimiter::new(cfg, Some(Arc::clone(&metrics)));

        let _ = limiter.check("issuer-R");
        let _ = limiter.check("issuer-R"); // triggers rejection

        let output = metrics.render();
        assert!(output.contains("rate_limit_rejections_total"));
    }

    #[test]
    fn tracked_issuers_count_grows_with_distinct_callers() {
        let limiter = PerIssuerRateLimiter::new(test_config(100, 10), None);

        for i in 0..5 {
            let _ = limiter.check(&format!("issuer-{}", i));
        }

        assert_eq!(limiter.tracked_issuers(), 5);
    }

    #[tokio::test]
    async fn until_ready_resolves_and_records_hit() {
        let metrics = MetricsRegistry::arc();
        let limiter = PerIssuerRateLimiter::new(test_config(100, 10), Some(Arc::clone(&metrics)));

        limiter.until_ready("issuer-async").await;

        let output = metrics.render();
        assert!(output.contains("rate_limit_hits_total"));
    }

    #[test]
    fn burst_tolerance_allows_spike_then_rejects() {
        let cfg = RateLimitConfig {
            global_per_second: 1000,
            global_burst: 1000,
            per_issuer_per_second: 1,
            per_issuer_burst: 3,
            issuer_ttl_seconds: 60,
            jitter_seconds: 0,
        };
        let limiter = PerIssuerRateLimiter::new(cfg, None);

        // Should allow burst of 3
        assert!(limiter.check("burst-issuer").is_ok());
        assert!(limiter.check("burst-issuer").is_ok());
        assert!(limiter.check("burst-issuer").is_ok());
        // 4th should be rejected
        assert!(limiter.check("burst-issuer").is_err());
    }

    // ── Atomic-refill / race-condition coverage ───────────────────────────

    #[test]
    fn atomic_bucket_grants_exactly_capacity_under_contention() {
        // A single bucket hammered by many threads at a fixed instant must grant
        // exactly `capacity` tokens — no loss (over-rejection) and no
        // double-spend (over-grant).
        let capacity: u32 = 1000;
        let now = now_secs();
        let bucket = Arc::new(AtomicTokenBucket::new(capacity, 1, 0, "issuer", now));
        let granted = Arc::new(AtomicUsize::new(0));

        let threads = 16;
        let attempts_per_thread = 200; // 16 * 200 = 3200 > capacity
        let mut handles = Vec::new();
        for _ in 0..threads {
            let bucket = Arc::clone(&bucket);
            let granted = Arc::clone(&granted);
            handles.push(thread::spawn(move || {
                for _ in 0..attempts_per_thread {
                    if bucket.try_consume(now).granted {
                        granted.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            granted.load(Ordering::Relaxed),
            capacity as usize,
            "exactly capacity tokens must be granted with no loss or double-spend"
        );
    }

    #[test]
    fn concurrent_checks_never_lose_tokens() {
        // Drive the full two-tier limiter concurrently on one issuer. With the
        // global tier effectively unlimited, at least the whole per-issuer burst
        // must be granted — a race that dropped tokens would grant fewer. (Wall
        // time may advance during the run, so legitimate refill can grant a few
        // more; exact no-double-spend accounting is proven deterministically by
        // the fixed-instant bucket tests.)
        let burst: u32 = 500;
        let cfg = RateLimitConfig {
            global_per_second: 10_000_000,
            global_burst: 10_000_000,
            per_issuer_per_second: 1,
            per_issuer_burst: burst,
            issuer_ttl_seconds: 60,
            jitter_seconds: 0,
        };
        let limiter = Arc::new(PerIssuerRateLimiter::new(cfg, None));
        let granted = Arc::new(AtomicUsize::new(0));

        let threads = 8;
        let attempts_per_thread = 200; // 8 * 200 = 1600 > burst
        let mut handles = Vec::new();
        for _ in 0..threads {
            let limiter = Arc::clone(&limiter);
            let granted = Arc::clone(&granted);
            handles.push(thread::spawn(move || {
                for _ in 0..attempts_per_thread {
                    if limiter.check("hot-issuer").is_ok() {
                        granted.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert!(
            granted.load(Ordering::Relaxed) >= burst as usize,
            "concurrent checks must never grant fewer than the burst (no token loss)"
        );
    }

    #[test]
    fn stress_ten_thousand_issuers_no_token_loss() {
        // 10,000 independent issuer buckets (burst = 1) hammered concurrently at
        // a FIXED instant, so no time-based refill can occur during the run.
        // Exactly one grant per issuer must be observed regardless of how long
        // the test takes or how many callers race on each bucket — proving both
        // per-issuer isolation and that the atomic CAS neither loses a token nor
        // double-spends one, at scale.
        const ISSUERS: usize = 10_000;
        let now = now_secs();
        let buckets: Vec<Arc<AtomicTokenBucket>> = (0..ISSUERS)
            .map(|i| {
                Arc::new(AtomicTokenBucket::new(
                    1,
                    1,
                    0,
                    &format!("issuer-{}", i),
                    now,
                ))
            })
            .collect();
        let buckets = Arc::new(buckets);
        let granted = Arc::new(AtomicUsize::new(0));

        let threads = 10;
        let mut handles = Vec::new();
        for t in 0..threads {
            let buckets = Arc::clone(&buckets);
            let granted = Arc::clone(&granted);
            handles.push(thread::spawn(move || {
                // Each thread sweeps every bucket 3 times, rotating its start so
                // all 10 threads contend on each bucket (30 attempts each).
                for _ in 0..3 {
                    for k in 0..ISSUERS {
                        let idx = (k + t * 997) % ISSUERS;
                        if buckets[idx].try_consume(now).granted {
                            granted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            granted.load(Ordering::Relaxed),
            ISSUERS,
            "each of the 10,000 issuers must grant exactly one token, with no loss or double-spend"
        );
    }

    #[test]
    fn deterministic_jitter_is_stable_and_bounded() {
        let window = 30;
        let a1 = deterministic_jitter("issuer-A", window);
        let a2 = deterministic_jitter("issuer-A", window);
        let b = deterministic_jitter("issuer-B", window);

        assert_eq!(a1, a2, "jitter must be deterministic for a given issuer");
        assert!(a1 < window, "jitter must be bounded by the window");
        assert!(b < window);
        // A zero window disables jitter.
        assert_eq!(deterministic_jitter("issuer-A", 0), 0);
    }

    #[test]
    fn reset_at_is_deterministic_and_includes_jitter() {
        let now = 1_000_000u64;
        let jitter = 30u64;
        // Empty the bucket so reset_at reflects a full-refill horizon.
        let bucket = AtomicTokenBucket::new(5, 5, jitter, "issuer-Z", now);
        // Drain it.
        for _ in 0..5 {
            assert!(bucket.try_consume(now).granted);
        }
        let (remaining, reset_a) = bucket.snapshot(now);
        let (_, reset_b) = bucket.snapshot(now);
        assert_eq!(remaining, 0);
        assert_eq!(reset_a, reset_b, "reset_at must not drift between reads");

        let expected_jitter = deterministic_jitter("issuer-Z", jitter);
        // deficit = 5 tokens, rate = 5/s => 1s to full, plus jitter.
        assert_eq!(reset_a, now + 1 + expected_jitter);
    }

    #[test]
    fn rejected_call_still_folds_in_refill_time() {
        // A bucket that is empty now but has accrued time should refill and grant
        // on a later second — proving elapsed time is not lost on rejection.
        let start = 1_000u64;
        let bucket = AtomicTokenBucket::new(1, 1, 0, "issuer-T", start);
        assert!(bucket.try_consume(start).granted); // consume the single token
        assert!(!bucket.try_consume(start).granted); // empty at the same second
                                                     // One second later, exactly one token has refilled.
        assert!(bucket.try_consume(start + 1).granted);
        assert!(!bucket.try_consume(start + 1).granted);
    }
}

use dashmap::DashMap;
use governor::{
    clock::{Clock, QuantaClock},
    state::keyed::DefaultKeyedStateStore,
    Quota, RateLimiter,
};
use std::{num::NonZeroU32, string::{String, ToString}, sync::Arc, time::Duration};

use crate::metrics::MetricsRegistry;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Type aliases ─────────────────────────────────────────────────────────────

/// Global (unkeyed) rate limiter backed by the Quanta monotonic clock.
pub type GlobalRateLimiter = RateLimiter<
    governor::state::NotKeyed,
    governor::state::InMemoryState,
    QuantaClock,
>;

/// Per-issuer (keyed) rate limiter backed by the Quanta monotonic clock.
pub type KeyedRateLimiterInner = RateLimiter<
    String,
    DefaultKeyedStateStore<String>,
    QuantaClock,
>;

// ── Rate limit status ─────────────────────────────────────────────────────────

/// Current quota status for a single issuer.
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    /// The issuer DID / key this status belongs to.
    pub issuer: String,
    /// Remaining tokens in the per-issuer bucket (approximate).
    pub remaining: u32,
    /// Unix timestamp (seconds) when the per-issuer bucket fully refills.
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
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_per_second: 100,
            global_burst: 200,
            per_issuer_per_second: 10,
            per_issuer_burst: 20,
            issuer_ttl_seconds: 3600,
        }
    }
}

// ── Per-issuer entry ──────────────────────────────────────────────────────────

/// Metadata tracked per issuer alongside the shared keyed limiter.
struct IssuerEntry {
    /// Last time a request was seen from this issuer (Unix seconds).
    last_seen: u64,
    /// Approximate remaining tokens (maintained as a best-effort counter).
    remaining: u32,
    /// Configured burst capacity for this issuer (used for reset estimation).
    #[allow(dead_code)]
    burst: u32,
    /// Seconds per full refill (≈ burst / per_second).
    refill_period_secs: u64,
}

impl IssuerEntry {
    fn new(burst: u32, per_second: u32) -> Self {
        Self {
            last_seen: now_secs(),
            remaining: burst,
            burst,
            refill_period_secs: (burst as u64).saturating_div(per_second as u64).max(1),
        }
    }

    fn reset_at(&self) -> u64 {
        self.last_seen + self.refill_period_secs
    }
}

// ── Two-tier rate limiter ────────────────────────────────────────────────────

/// Two-tier, metrics-aware rate limiter.
///
/// **Tier 1 – Global**: a single unkeyed bucket shared across every caller.
/// **Tier 2 – Per-issuer**: a `DashMap`-backed keyed bucket, one per issuer address.
///
/// Both tiers must pass before a request is accepted.  The global tier always
/// takes precedence: if it is saturated the per-issuer check is skipped so
/// that per-issuer remaining counts stay accurate.
pub struct PerIssuerRateLimiter {
    global: Arc<GlobalRateLimiter>,
    keyed: Arc<KeyedRateLimiterInner>,
    issuer_meta: Arc<DashMap<String, IssuerEntry>>,
    config: RateLimitConfig,
    metrics: Option<Arc<MetricsRegistry>>,
}

impl PerIssuerRateLimiter {
    /// Construct a new two-tier limiter from explicit config.
    pub fn new(config: RateLimitConfig, metrics: Option<Arc<MetricsRegistry>>) -> Self {
        let global_quota =
            Quota::per_second(NonZeroU32::new(config.global_per_second.max(1)).unwrap())
                .allow_burst(NonZeroU32::new(config.global_burst.max(1)).unwrap());
        let global = Arc::new(RateLimiter::direct(global_quota));

        let issuer_quota =
            Quota::per_second(NonZeroU32::new(config.per_issuer_per_second.max(1)).unwrap())
                .allow_burst(NonZeroU32::new(config.per_issuer_burst.max(1)).unwrap());
        let keyed = Arc::new(RateLimiter::keyed(issuer_quota));

        Self {
            global,
            keyed,
            issuer_meta: Arc::new(DashMap::new()),
            config,
            metrics,
        }
    }

    /// Construct from the application `AppConfig`.
    pub fn from_config(
        cfg: &crate::config::AppConfig,
        metrics: Option<Arc<MetricsRegistry>>,
    ) -> Self {
        let rl_cfg = RateLimitConfig {
            global_per_second: cfg.rate_limit_per_second,
            global_burst: cfg.rate_limit_burst,
            per_issuer_per_second: cfg.per_issuer_rate_limit_per_second,
            per_issuer_burst: cfg.per_issuer_rate_limit_burst,
            issuer_ttl_seconds: cfg.issuer_rate_limit_ttl_seconds,
        };
        Self::new(rl_cfg, metrics)
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
            }
            let retry_after = not_until.wait_time_from(self.global_clock());
            return Err(RateLimitError::GlobalExhausted { retry_after });
        }

        // ── Tier 2: per-issuer ────────────────────────────────────────────
        let issuer_key = issuer.to_string();
        if let Err(not_until) = self.keyed.check_key(&issuer_key) {
            if let Some(ref m) = self.metrics {
                m.increment_rate_limit_issuer_rejection(issuer);
            }
            let retry_after = not_until.wait_time_from(self.keyed_clock());
            return Err(RateLimitError::IssuerExhausted {
                issuer: issuer.to_string(),
                retry_after,
            });
        }

        // ── Success: update metadata & metrics ────────────────────────────
        self.update_meta_on_success(issuer);
        if let Some(ref m) = self.metrics {
            m.increment_rate_limit_hit(issuer);
        }

        Ok(())
    }

    /// Async blocking wait until both tiers permit the request.
    pub async fn until_ready(&self, issuer: &str) {
        self.global.until_ready().await;
        self.keyed.until_key_ready(&issuer.to_string()).await;

        self.update_meta_on_success(issuer);
        if let Some(ref m) = self.metrics {
            m.increment_rate_limit_hit(issuer);
        }
    }

    /// Return the current quota status for `issuer` without consuming a token.
    pub fn status(&self, issuer: &str) -> RateLimitStatus {
        let meta = self.issuer_meta.get(issuer);
        let (remaining, reset_at) = match meta {
            Some(e) => (e.remaining, e.reset_at()),
            None => (
                self.config.per_issuer_burst,
                now_secs() + self.config.issuer_ttl_seconds,
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

    /// Evict issuer entries that have not been seen within `issuer_ttl_seconds`.
    ///
    /// Call this periodically (e.g. from a background task) to bound memory use.
    pub fn evict_stale(&self) {
        let cutoff = now_secs().saturating_sub(self.config.issuer_ttl_seconds);
        self.issuer_meta.retain(|_, entry| entry.last_seen >= cutoff);
    }

    /// Return the number of tracked issuers currently in the metadata map.
    pub fn tracked_issuers(&self) -> usize {
        self.issuer_meta.len()
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn update_meta_on_success(&self, issuer: &str) {
        let ts = now_secs();
        let burst = self.config.per_issuer_burst;
        let per_second = self.config.per_issuer_per_second;

        self.issuer_meta
            .entry(issuer.to_string())
            .and_modify(|e| {
                e.last_seen = ts;
                e.remaining = e.remaining.saturating_sub(1);
            })
            .or_insert_with(|| {
                let mut entry = IssuerEntry::new(burst, per_second);
                entry.remaining = entry.remaining.saturating_sub(1);
                entry
            });
    }

    fn global_clock(&self) -> governor::clock::QuantaInstant {
        governor::clock::Clock::now(&QuantaClock::default())
    }

    fn keyed_clock(&self) -> governor::clock::QuantaInstant {
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
            Self::IssuerExhausted { issuer, retry_after } => write!(
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

    fn test_config(global_rps: u32, issuer_rps: u32) -> RateLimitConfig {
        RateLimitConfig {
            global_per_second: global_rps,
            global_burst: global_rps * 2,
            per_issuer_per_second: issuer_rps,
            per_issuer_burst: issuer_rps * 2,
            issuer_ttl_seconds: 60,
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
        };
        let limiter = PerIssuerRateLimiter::new(cfg, None);

        // Should allow burst of 3
        assert!(limiter.check("burst-issuer").is_ok());
        assert!(limiter.check("burst-issuer").is_ok());
        assert!(limiter.check("burst-issuer").is_ok());
        // 4th should be rejected
        assert!(limiter.check("burst-issuer").is_err());
    }
}
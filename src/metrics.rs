use prometheus::{
    Counter, Encoder, Gauge, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts,
    Registry, TextEncoder,
};
use std::prelude::v1::*;
use std::sync::Arc;
use std::time::Instant;

pub trait MetricsBackend: Send + Sync {
    fn register_counter(&self, name: &str, help: &str) -> Result<(), String>;
    fn register_gauge(&self, name: &str, help: &str) -> Result<(), String>;
    fn register_histogram(&self, name: &str, help: &str) -> Result<(), String>;
    fn counter_inc(&self, name: &str, labels: &[(&str, &str)]) -> Result<(), String>;
    fn counter_inc_by(&self, name: &str, value: u64, labels: &[(&str, &str)]) -> Result<(), String>;
    fn gauge_set(&self, name: &str, value: f64, labels: &[(&str, &str)]) -> Result<(), String>;
    fn gauge_inc(&self, name: &str, labels: &[(&str, &str)]) -> Result<(), String>;
    fn gauge_dec(&self, name: &str, labels: &[(&str, &str)]) -> Result<(), String>;
    fn histogram_observe(&self, name: &str, value: f64, labels: &[(&str, &str)]) -> Result<(), String>;
}

/// Central metrics registry wrapping Prometheus instrumentation.
///
/// This registry is shared across all service modules via `Arc<MetricsRegistry>`
/// and exposes a Prometheus text-format endpoint through `render()`.
pub struct MetricsRegistry {
    registry: Registry,

    // ── General request metrics ──
    request_count: Counter,
    error_count: Counter,

    // ── Cache metrics ──
    cache_hits: IntCounter,
    cache_misses: IntCounter,
    cache_expired: IntCounter,
    cache_serialization_failures: IntCounter,
    cache_size: Gauge,
    cache_evictions: IntCounter,
    cache_hit_rate: Gauge,

    // ── Document registration metrics ──
    document_registration_total: IntCounterVec,
    document_revocation_total: IntCounterVec,

    // ── Verification metrics ──
    verification_total: IntCounterVec,
    verification_latency_seconds: HistogramVec,
    horizon_latency_seconds: HistogramVec,
    retry_total: IntCounter,

    // ── Rate limiter metrics (legacy global) ──
    rate_limit_tokens_consumed: IntCounter,
    rate_limit_tokens_refilled: IntCounter,
    rate_limit_violations: IntCounter,
    rate_limit_resets: IntCounter,

    // ── Rate limiter metrics (per-issuer, two-tier) ──
    /// Counts every request that passed both rate-limit tiers, labelled by issuer.
    rate_limit_hits: IntCounterVec,
    /// Counts every request rejected by either tier, labelled by issuer and tier
    /// (`"global"` or `"issuer"`).
    rate_limit_rejections: IntCounterVec,

    // ── Event ingestion metrics ──
    event_duplicates: IntCounter,
    event_ordering_failures: IntCounter,
    event_backlog_size: Gauge,

    // ── Config validation metrics ──
    config_validation_failures: IntCounter,
    config_reload_total: IntCounter,

    // ── Circuit breaker metrics ──
    circuit_state: Gauge,
    circuit_transitions_total: IntCounterVec,
    circuit_state_changes_total: IntCounterVec,

    // ── Cache circuit breaker metrics ──
    cache_circuit_state: Gauge,
    cache_circuit_transitions_total: IntCounterVec,
    cache_circuit_rejections_total: IntCounter,
    cache_circuit_recoveries_total: IntCounter,
    cache_fallback_uses_total: IntCounter,

    // ── Cache bulkhead metrics ──
    cache_bulkhead_active: Gauge,
    cache_bulkhead_rejections_total: IntCounter,

    // ── Webhook delivery metrics ──
    webhook_deliveries_total: IntCounterVec,
    webhook_delivery_latency_seconds: HistogramVec,
    webhook_dlq_depth: Gauge,
    webhook_retries_total: IntCounter,

    dynamic_counters: std::sync::RwLock<std::collections::HashMap<String, prometheus::IntCounterVec>>,
    dynamic_gauges: std::sync::RwLock<std::collections::HashMap<String, prometheus::GaugeVec>>,
    dynamic_histograms: std::sync::RwLock<std::collections::HashMap<String, prometheus::HistogramVec>>,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        let registry = Registry::new();

        // ── General request metrics ──
        let request_count = Counter::new("requests_total", "Total number of API requests").unwrap();
        let error_count =
            Counter::new("errors_total", "Total number of errors encountered").unwrap();

        // ── Cache metrics ──
        let cache_hits = IntCounter::new("cache_hits_total", "Total cache hits").unwrap();
        let cache_misses = IntCounter::new("cache_misses_total", "Total cache misses").unwrap();
        let cache_expired = IntCounter::new(
            "cache_expired_total",
            "Total cache entries returned as miss due to TTL expiry",
        )
        .unwrap();
        let cache_serialization_failures = IntCounter::new(
            "cache_serialization_failures_total",
            "Total cache serialization/deserialization failures",
        )
        .unwrap();
        let cache_size = Gauge::new("cache_size", "Current number of entries in cache").unwrap();
        let cache_evictions =
            IntCounter::new("cache_evictions_total", "Total cache evictions").unwrap();
        let cache_hit_rate = Gauge::new("cache_hit_rate", "Current cache hit rate (0-1)").unwrap();

        // ── Document metrics ──
        let document_registration_total = IntCounterVec::new(
            Opts::new(
                "document_registration_total",
                "Total document registrations by outcome",
            ),
            &["status"],
        )
        .unwrap();

        let document_revocation_total = IntCounterVec::new(
            Opts::new(
                "document_revocation_total",
                "Total document revocations by outcome",
            ),
            &["status"],
        )
        .unwrap();

        // ── Verification metrics ──
        let verification_total = IntCounterVec::new(
            Opts::new("verification_total", "Total verifications by outcome"),
            &["status"],
        )
        .unwrap();

        let verification_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "verification_latency_seconds",
                "End-to-end verification latency in seconds",
            ),
            &["status"],
        )
        .unwrap();

        let horizon_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "horizon_latency_seconds",
                "Stellar Horizon API call latency in seconds",
            ),
            &["status"],
        )
        .unwrap();

        let retry_total = IntCounter::new(
            "retry_total",
            "Total number of retry attempts across all operations",
        )
        .unwrap();

        // ── Rate limiter metrics (legacy) ──
        let rate_limit_tokens_consumed = IntCounter::new(
            "rate_limit_tokens_consumed_total",
            "Total rate limiter tokens consumed (legacy global limiter)",
        )
        .unwrap();

        let rate_limit_tokens_refilled = IntCounter::new(
            "rate_limit_tokens_refilled_total",
            "Total rate limiter tokens replenished by time-based bucket refill",
        )
        .unwrap();

        let rate_limit_violations = IntCounter::new(
            "rate_limit_violations_total",
            "Total rate limit violations – legacy global limiter (requests rejected)",
        )
        .unwrap();

        let rate_limit_resets = IntCounter::new(
            "rate_limit_resets_total",
            "Total rate limiter bucket resets or refills after exhaustion",
        )
        .unwrap();

        // ── Rate limiter metrics (per-issuer, two-tier) ──
        //
        // `rate_limit_hits_total{issuer="<addr>"}` — accepted requests per issuer.
        // `rate_limit_rejections_total{issuer="<addr>",tier="global"|"issuer"}` — rejections.
        let rate_limit_hits = IntCounterVec::new(
            Opts::new(
                "rate_limit_hits_total",
                "Total requests that passed rate limiting, labelled by issuer",
            ),
            &["issuer"],
        )
        .unwrap();

        let rate_limit_rejections = IntCounterVec::new(
            Opts::new(
                "rate_limit_rejections_total",
                "Total requests rejected by rate limiting, labelled by issuer and tier",
            ),
            &["issuer", "tier"],
        )
        .unwrap();

        // ── Event ingestion metrics ──
        let event_duplicates = IntCounter::new(
            "event_duplicates_total",
            "Total duplicate events detected and discarded",
        )
        .unwrap();

        let event_ordering_failures = IntCounter::new(
            "event_ordering_failures_total",
            "Total events rejected due to ordering/sequence failures",
        )
        .unwrap();

        let event_backlog_size = Gauge::new(
            "event_backlog_size",
            "Current number of unprocessed events in the backlog queue",
        )
        .unwrap();

        // ── Config validation metrics ──
        let config_validation_failures = IntCounter::new(
            "config_validation_failures_total",
            "Total configuration validation failures",
        )
        .unwrap();

        let config_reload_total = IntCounter::new(
            "config_reload_total",
            "Total configuration reloads attempted",
        )
        .unwrap();

        // ── Circuit breaker metrics ─────────────────────────────────────
        let circuit_state = Gauge::new(
            "circuit_breaker_state",
            "Current circuit breaker state (0=closed, 1=open, 2=half_open)",
        )
        .unwrap();

        let circuit_transitions_total = IntCounterVec::new(
            Opts::new(
                "circuit_breaker_transitions_total",
                "Total circuit breaker state transitions by target state",
            ),
            &["to_state"],
        )
        .unwrap();

        let circuit_state_changes_total = IntCounterVec::new(
            Opts::new(
                "circuit_breaker_state_changes_total",
                "Total circuit breaker state changes by from_state and to_state",
            ),
            &["from_state", "to_state"],
        )
        .unwrap();

        // ── Cache circuit breaker metrics ────────────────────────────────
        let cache_circuit_state = Gauge::new(
            "cache_circuit_breaker_state",
            "Current cache circuit breaker state (0=closed, 1=open, 2=half_open)",
        )
        .unwrap();

        let cache_circuit_transitions_total = IntCounterVec::new(
            Opts::new(
                "cache_circuit_breaker_transitions_total",
                "Total cache circuit breaker state transitions",
            ),
            &["from_state", "to_state"],
        )
        .unwrap();

        let cache_circuit_rejections_total = IntCounter::new(
            "cache_circuit_breaker_rejections_total",
            "Total cache operations rejected by circuit breaker",
        )
        .unwrap();

        let cache_circuit_recoveries_total = IntCounter::new(
            "cache_circuit_breaker_recoveries_total",
            "Total cache circuit breaker recovery successes",
        )
        .unwrap();

        let cache_fallback_uses_total = IntCounter::new(
            "cache_fallback_uses_total",
            "Total cache operations falling back to InMemory",
        )
        .unwrap();

        // ── Cache bulkhead metrics ───────────────────────────────────────
        let cache_bulkhead_active = Gauge::new(
            "cache_bulkhead_active_operations",
            "Current number of active cache bulkhead operations",
        )
        .unwrap();

        let cache_bulkhead_rejections_total = IntCounter::new(
            "cache_bulkhead_rejections_total",
            "Total cache operations rejected by bulkhead",
        )
        .unwrap();

        // ── Webhook delivery metrics ──
        let webhook_deliveries_total = IntCounterVec::new(
            Opts::new(
                "webhook_deliveries_total",
                "Total webhook delivery attempts by outcome",
            ),
            &["status"],
        )
        .unwrap();

        let webhook_delivery_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "webhook_delivery_latency_seconds",
                "End-to-end webhook delivery latency in seconds",
            ),
            &["status"],
        )
        .unwrap();

        let webhook_dlq_depth = Gauge::new(
            "webhook_dlq_depth",
            "Current number of entries in the webhook dead-letter queue",
        )
        .unwrap();

        let webhook_retries_total = IntCounter::new(
            "webhook_retries_total",
            "Total webhook delivery retry attempts",
        )
        .unwrap();

        // ── Register everything ───────────────────────────────────────────
        for metric in [
            Box::new(request_count.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(error_count.clone()),
            Box::new(cache_hits.clone()),
            Box::new(cache_misses.clone()),
            Box::new(cache_expired.clone()),
            Box::new(cache_serialization_failures.clone()),
            Box::new(cache_size.clone()),
            Box::new(cache_evictions.clone()),
            Box::new(cache_hit_rate.clone()),
            Box::new(document_registration_total.clone()),
            Box::new(document_revocation_total.clone()),
            Box::new(verification_total.clone()),
            Box::new(verification_latency_seconds.clone()),
            Box::new(horizon_latency_seconds.clone()),
            Box::new(retry_total.clone()),
            Box::new(rate_limit_tokens_consumed.clone()),
            Box::new(rate_limit_tokens_refilled.clone()),
            Box::new(rate_limit_violations.clone()),
            Box::new(rate_limit_resets.clone()),
            Box::new(rate_limit_hits.clone()),
            Box::new(rate_limit_rejections.clone()),
            Box::new(event_duplicates.clone()),
            Box::new(event_ordering_failures.clone()),
            Box::new(event_backlog_size.clone()),
            Box::new(config_validation_failures.clone()),
            Box::new(config_reload_total.clone()),
            Box::new(circuit_state.clone()),
            Box::new(circuit_transitions_total.clone()),
            Box::new(circuit_state_changes_total.clone()),
            Box::new(cache_circuit_state.clone()),
            Box::new(cache_circuit_transitions_total.clone()),
            Box::new(cache_circuit_rejections_total.clone()),
            Box::new(cache_circuit_recoveries_total.clone()),
            Box::new(cache_fallback_uses_total.clone()),
            Box::new(cache_bulkhead_active.clone()),
            Box::new(cache_bulkhead_rejections_total.clone()),
            Box::new(webhook_deliveries_total.clone()),
            Box::new(webhook_delivery_latency_seconds.clone()),
            Box::new(webhook_dlq_depth.clone()),
            Box::new(webhook_retries_total.clone()),
        ] {
            registry.register(metric).unwrap();
        }

        Self {
            registry,
            request_count,
            error_count,
            cache_hits,
            cache_misses,
            cache_expired,
            cache_serialization_failures,
            cache_size,
            cache_evictions,
            cache_hit_rate,
            document_registration_total,
            document_revocation_total,
            verification_total,
            verification_latency_seconds,
            horizon_latency_seconds,
            retry_total,
            rate_limit_tokens_consumed,
            rate_limit_tokens_refilled,
            rate_limit_violations,
            rate_limit_resets,
            rate_limit_hits,
            rate_limit_rejections,
            event_duplicates,
            event_ordering_failures,
            event_backlog_size,
            config_validation_failures,
            config_reload_total,
            circuit_state,
            circuit_transitions_total,
            circuit_state_changes_total,
            cache_circuit_state,
            cache_circuit_transitions_total,
            cache_circuit_rejections_total,
            cache_circuit_recoveries_total,
            cache_fallback_uses_total,
            cache_bulkhead_active,
            cache_bulkhead_rejections_total,
            webhook_deliveries_total,
            webhook_delivery_latency_seconds,
            webhook_dlq_depth,
            webhook_retries_total,
            dynamic_counters: std::sync::RwLock::new(std::collections::HashMap::new()),
            dynamic_gauges: std::sync::RwLock::new(std::collections::HashMap::new()),
            dynamic_histograms: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Return a sharable `Arc<MetricsRegistry>` for use across service threads.
    pub fn arc() -> Arc<Self> {
        Arc::new(Self::new())
    }

    // ── Request metrics ──────────────────────────────────────────────────

    pub fn increment_request_count(&self) {
        self.request_count.inc();
    }

    pub fn increment_error_count(&self) {
        self.error_count.inc();
    }

    // ── Cache metrics ────────────────────────────────────────────────────

    pub fn increment_cache_hits(&self) {
        self.cache_hits.inc();
    }

    pub fn increment_cache_misses(&self) {
        self.cache_misses.inc();
    }

    pub fn increment_cache_expired(&self) {
        self.cache_expired.inc();
    }

    pub fn increment_cache_serialization_failures(&self) {
        self.cache_serialization_failures.inc();
    }

    pub fn set_cache_size(&self, size: u64) {
        self.cache_size.set(size as f64);
    }

    pub fn increment_cache_evictions(&self) {
        self.cache_evictions.inc();
    }

    pub fn increment_cache_evictions_by(&self, count: u64) {
        self.cache_evictions.inc_by(count);
    }

    pub fn set_cache_hit_rate(&self, rate: f64) {
        self.cache_hit_rate.set(rate);
    }

    // ── Document metrics ─────────────────────────────────────────────────

    pub fn record_document_registration(&self, status: &str) {
        self.document_registration_total
            .with_label_values(&[status])
            .inc();
    }

    pub fn record_document_revocation(&self, status: &str) {
        self.document_revocation_total
            .with_label_values(&[status])
            .inc();
    }

    // ── Verification metrics ─────────────────────────────────────────────

    pub fn record_verification(&self, status: &str, latency_secs: f64) {
        self.verification_total.with_label_values(&[status]).inc();
        self.verification_latency_seconds
            .with_label_values(&[status])
            .observe(latency_secs);
    }

    pub fn record_horizon_latency(&self, status: &str, latency_secs: f64) {
        self.horizon_latency_seconds
            .with_label_values(&[status])
            .observe(latency_secs);
    }

    pub fn increment_retry(&self) {
        self.retry_total.inc();
    }

    // ── Rate limiter metrics (legacy) ────────────────────────────────────

    pub fn record_token_consumed(&self) {
        self.rate_limit_tokens_consumed.inc();
    }

    /// Record `count` tokens replenished by a time-based bucket refill.
    pub fn record_tokens_refilled(&self, count: u64) {
        if count > 0 {
            self.rate_limit_tokens_refilled.inc_by(count);
        }
    }

    pub fn increment_rate_limit_violation(&self) {
        self.rate_limit_violations.inc();
    }

    pub fn increment_rate_limit_reset(&self) {
        self.rate_limit_resets.inc();
    }

    // ── Rate limiter metrics (per-issuer, two-tier) ──────────────────────

    /// Record an accepted request for `issuer`.
    pub fn increment_rate_limit_hit(&self, issuer: &str) {
        self.rate_limit_hits.with_label_values(&[issuer]).inc();
    }

    /// Record a rejection originating from the **global** tier.
    pub fn increment_rate_limit_global_rejection(&self, issuer: &str) {
        self.rate_limit_rejections
            .with_label_values(&[issuer, "global"])
            .inc();
    }

    /// Record a rejection originating from the **per-issuer** tier.
    pub fn increment_rate_limit_issuer_rejection(&self, issuer: &str) {
        self.rate_limit_rejections
            .with_label_values(&[issuer, "issuer"])
            .inc();
    }

    // ── Event ingestion metrics ──────────────────────────────────────────

    pub fn increment_event_duplicate(&self) {
        self.event_duplicates.inc();
    }

    pub fn increment_event_ordering_failure(&self) {
        self.event_ordering_failures.inc();
    }

    pub fn set_event_backlog(&self, size: i64) {
        self.event_backlog_size.set(size as f64);
    }

    pub fn increment_event_backlog(&self) {
        self.event_backlog_size.inc();
    }

    pub fn decrement_event_backlog(&self) {
        self.event_backlog_size.dec();
    }

    // ── Config metrics ───────────────────────────────────────────────────

    pub fn increment_config_validation_failure(&self) {
        self.config_validation_failures.inc();
    }

    pub fn increment_config_reload(&self) {
        self.config_reload_total.inc();
    }

    // ── Circuit breaker metrics ──────────────────────────────────────

    pub fn set_circuit_state(&self, state: i64) {
        self.circuit_state.set(state as f64);
    }

    pub fn record_circuit_transition(&self, to_state: &str) {
        self.circuit_transitions_total
            .with_label_values(&[to_state])
            .inc();
    }

    pub fn record_circuit_state_change(&self, from_state: &str, to_state: &str) {
        self.circuit_state_changes_total
            .with_label_values(&[from_state, to_state])
            .inc();
    }

    // ── Cache circuit breaker metrics ──────────────────────────────────

    pub fn set_cache_circuit_state(&self, state: i64) {
        self.cache_circuit_state.set(state as f64);
    }

    pub fn record_cache_circuit_transition(&self, from_state: &str, to_state: &str) {
        self.cache_circuit_transitions_total
            .with_label_values(&[from_state, to_state])
            .inc();
    }

    pub fn increment_cache_circuit_rejection(&self) {
        self.cache_circuit_rejections_total.inc();
    }

    pub fn increment_cache_circuit_recovery(&self) {
        self.cache_circuit_recoveries_total.inc();
    }

    pub fn increment_cache_fallback_use(&self) {
        self.cache_fallback_uses_total.inc();
    }

    // ── Cache bulkhead metrics ─────────────────────────────────────────

    pub fn set_cache_bulkhead_active(&self, active: i64) {
        self.cache_bulkhead_active.set(active as f64);
    }

    pub fn increment_cache_bulkhead_rejection(&self) {
        self.cache_bulkhead_rejections_total.inc();
    }

    // ── Webhook delivery metrics ──────────────────────────────────────

    /// Record a completed delivery attempt (success or dead_lettered) with latency.
    pub fn record_webhook_delivery(&self, status: &str, latency_secs: f64) {
        self.webhook_deliveries_total
            .with_label_values(&[status])
            .inc();
        self.webhook_delivery_latency_seconds
            .with_label_values(&[status])
            .observe(latency_secs);
    }

    /// Increment the webhook retry counter by one.
    pub fn increment_webhook_retry(&self) {
        self.webhook_retries_total.inc();
    }

    /// Set the dead-letter queue depth gauge.
    pub fn set_webhook_dlq_depth(&self, depth: i64) {
        self.webhook_dlq_depth.set(depth as f64);
    }

    // ── Latency helper ───────────────────────────────────────────────────

    /// Start a timer for measuring operation latency.
    pub fn start_timer() -> Instant {
        Instant::now()
    }

    /// Return elapsed seconds since `start`.
    pub fn elapsed_secs(start: Instant) -> f64 {
        start.elapsed().as_secs_f64()
    }

    // ── Prometheus rendering ─────────────────────────────────────────────

    /// Render all registered metrics in Prometheus text format.
    ///
    /// Returns a `String` suitable for direct HTTP response or Prometheus scraping.
    /// Callers can wrap this with `axum::response::IntoResponse` at the HTTP layer.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .unwrap_or_default();
        String::from_utf8(buffer).unwrap_or_default()
    }
}

impl MetricsBackend for MetricsRegistry {
    fn register_counter(&self, name: &str, help: &str) -> Result<(), String> {
        let counter = prometheus::IntCounterVec::new(
            prometheus::Opts::new(name, help),
            &["component"],
        ).map_err(|e| e.to_string())?;
        self.registry.register(Box::new(counter.clone())).map_err(|e| e.to_string())?;
        self.dynamic_counters.write().map_err(|e| e.to_string())?.insert(name.to_string(), counter);
        Ok(())
    }

    fn register_gauge(&self, name: &str, help: &str) -> Result<(), String> {
        let gauge = prometheus::GaugeVec::new(
            prometheus::Opts::new(name, help),
            &["component"],
        ).map_err(|e| e.to_string())?;
        self.registry.register(Box::new(gauge.clone())).map_err(|e| e.to_string())?;
        self.dynamic_gauges.write().map_err(|e| e.to_string())?.insert(name.to_string(), gauge);
        Ok(())
    }

    fn register_histogram(&self, name: &str, help: &str) -> Result<(), String> {
        let histogram = prometheus::HistogramVec::new(
            prometheus::HistogramOpts::new(name, help),
            &["component"],
        ).map_err(|e| e.to_string())?;
        self.registry.register(Box::new(histogram.clone())).map_err(|e| e.to_string())?;
        self.dynamic_histograms.write().map_err(|e| e.to_string())?.insert(name.to_string(), histogram);
        Ok(())
    }

    fn counter_inc(&self, name: &str, labels: &[(&str, &str)]) -> Result<(), String> {
        let counters = self.dynamic_counters.read().map_err(|e| e.to_string())?;
        let counter = counters.get(name).ok_or_else(|| format!("counter '{}' not found", name))?;
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();
        counter.with_label_values(&label_values).inc();
        Ok(())
    }

    fn counter_inc_by(&self, name: &str, value: u64, labels: &[(&str, &str)]) -> Result<(), String> {
        let counters = self.dynamic_counters.read().map_err(|e| e.to_string())?;
        let counter = counters.get(name).ok_or_else(|| format!("counter '{}' not found", name))?;
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();
        counter.with_label_values(&label_values).inc_by(value);
        Ok(())
    }

    fn gauge_set(&self, name: &str, value: f64, labels: &[(&str, &str)]) -> Result<(), String> {
        let gauges = self.dynamic_gauges.read().map_err(|e| e.to_string())?;
        let gauge = gauges.get(name).ok_or_else(|| format!("gauge '{}' not found", name))?;
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();
        gauge.with_label_values(&label_values).set(value);
        Ok(())
    }

    fn gauge_inc(&self, name: &str, labels: &[(&str, &str)]) -> Result<(), String> {
        let gauges = self.dynamic_gauges.read().map_err(|e| e.to_string())?;
        let gauge = gauges.get(name).ok_or_else(|| format!("gauge '{}' not found", name))?;
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();
        gauge.with_label_values(&label_values).inc();
        Ok(())
    }

    fn gauge_dec(&self, name: &str, labels: &[(&str, &str)]) -> Result<(), String> {
        let gauges = self.dynamic_gauges.read().map_err(|e| e.to_string())?;
        let gauge = gauges.get(name).ok_or_else(|| format!("gauge '{}' not found", name))?;
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();
        gauge.with_label_values(&label_values).dec();
        Ok(())
    }

    fn histogram_observe(&self, name: &str, value: f64, labels: &[(&str, &str)]) -> Result<(), String> {
        let histograms = self.dynamic_histograms.read().map_err(|e| e.to_string())?;
        let histogram = histograms.get(name).ok_or_else(|| format!("histogram '{}' not found", name))?;
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();
        histogram.with_label_values(&label_values).observe(value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_creates_all_metrics() {
        let metrics = MetricsRegistry::new();

        // Smoke test: invoke each counter at least once
        metrics.increment_request_count();
        metrics.increment_error_count();
        metrics.increment_cache_hits();
        metrics.increment_cache_misses();
        metrics.increment_cache_expired();
        metrics.increment_cache_serialization_failures();
        metrics.record_document_registration("success");
        metrics.record_document_registration("error");
        metrics.record_document_revocation("success");
        metrics.record_verification("success", 0.1);
        metrics.record_verification("failure", 0.2);
        metrics.record_horizon_latency("success", 0.05);
        metrics.record_horizon_latency("error", 1.0);
        metrics.increment_retry();
        metrics.record_token_consumed();
        metrics.increment_rate_limit_violation();
        metrics.increment_rate_limit_hit("GDEX...");
        metrics.increment_rate_limit_global_rejection("GDEX...");
        metrics.increment_rate_limit_issuer_rejection("GDEX...");
        metrics.increment_event_duplicate();
        metrics.increment_event_ordering_failure();
        metrics.set_event_backlog(5);
        metrics.increment_event_backlog();
        metrics.decrement_event_backlog();
        metrics.increment_config_validation_failure();
        metrics.increment_config_reload();
        metrics.set_cache_circuit_state(1);
        metrics.record_cache_circuit_transition("closed", "open");
        metrics.increment_cache_circuit_rejection();
        metrics.increment_cache_circuit_recovery();
        metrics.increment_cache_fallback_use();
        metrics.set_cache_bulkhead_active(3);
        metrics.increment_cache_bulkhead_rejection();
        metrics.record_webhook_delivery("success", 0.05);
        metrics.record_webhook_delivery("dead_lettered", 1.0);
        metrics.increment_webhook_retry();
        metrics.set_webhook_dlq_depth(3);

        let output = metrics.render();
        assert!(output.contains("requests_total"));
        assert!(output.contains("cache_hits_total"));
        assert!(output.contains("verification_total"));
        assert!(output.contains("horizon_latency_seconds"));
        assert!(output.contains("rate_limit_violations_total"));
        assert!(output.contains("rate_limit_hits_total"));
        assert!(output.contains("rate_limit_rejections_total"));
        assert!(output.contains("event_backlog_size"));
        assert!(output.contains("config_validation_failures_total"));
        assert!(output.contains("cache_circuit_breaker_state"));
        assert!(output.contains("cache_circuit_breaker_transitions_total"));
        assert!(output.contains("cache_circuit_breaker_rejections_total"));
        assert!(output.contains("cache_circuit_breaker_recoveries_total"));
        assert!(output.contains("cache_fallback_uses_total"));
        assert!(output.contains("cache_bulkhead_active_operations"));
        assert!(output.contains("cache_bulkhead_rejections_total"));
        assert!(output.contains("webhook_deliveries_total"));
        assert!(output.contains("webhook_delivery_latency_seconds"));
        assert!(output.contains("webhook_dlq_depth"));
        assert!(output.contains("webhook_retries_total"));
    }

    #[test]
    fn per_issuer_hit_metric_carries_issuer_label() {
        let metrics = MetricsRegistry::new();
        metrics.increment_rate_limit_hit("GDEXISSUER001");
        let output = metrics.render();
        assert!(output.contains("GDEXISSUER001"));
        assert!(output.contains("rate_limit_hits_total"));
    }

    #[test]
    fn rejection_metric_carries_tier_label() {
        let metrics = MetricsRegistry::new();
        metrics.increment_rate_limit_global_rejection("GDEXISSUER001");
        metrics.increment_rate_limit_issuer_rejection("GDEXISSUER001");
        let output = metrics.render();
        assert!(output.contains(r#"tier="global""#));
        assert!(output.contains(r#"tier="issuer""#));
    }

    #[test]
    fn timer_returns_positive_elapsed() {
        let start = MetricsRegistry::start_timer();
        let elapsed = MetricsRegistry::elapsed_secs(start);
        assert!(elapsed >= 0.0);
    }

    #[test]
    fn arc_creates_shared_registry() {
        let metrics = MetricsRegistry::arc();
        metrics.increment_request_count();
        let output = metrics.render();
        assert!(output.contains("requests_total"));
    }

    #[test]
    fn dynamic_counter_registration_and_increment() {
        let metrics = MetricsRegistry::new();
        metrics.register_counter("my_custom_counter", "A test counter").unwrap();
        metrics.counter_inc("my_custom_counter", &[("component", "test")]).unwrap();
        metrics.counter_inc_by("my_custom_counter", 5, &[("component", "test")]).unwrap();
        let output = metrics.render();
        assert!(output.contains("my_custom_counter"));
    }

    #[test]
    fn dynamic_gauge_registration_and_set() {
        let metrics = MetricsRegistry::new();
        metrics.register_gauge("my_custom_gauge", "A test gauge").unwrap();
        metrics.gauge_set("my_custom_gauge", 42.0, &[("component", "test")]).unwrap();
        metrics.gauge_inc("my_custom_gauge", &[("component", "test")]).unwrap();
        metrics.gauge_dec("my_custom_gauge", &[("component", "test")]).unwrap();
        let output = metrics.render();
        assert!(output.contains("my_custom_gauge"));
    }

    #[test]
    fn dynamic_histogram_registration_and_observe() {
        let metrics = MetricsRegistry::new();
        metrics.register_histogram("my_custom_histogram", "A test histogram").unwrap();
        metrics.histogram_observe("my_custom_histogram", 0.5, &[("component", "test")]).unwrap();
        let output = metrics.render();
        assert!(output.contains("my_custom_histogram"));
    }

    #[test]
    fn dynamic_metric_not_found_returns_error() {
        let metrics = MetricsRegistry::new();
        assert!(metrics.counter_inc("nonexistent", &[]).is_err());
        assert!(metrics.gauge_set("nonexistent", 1.0, &[]).is_err());
        assert!(metrics.histogram_observe("nonexistent", 1.0, &[]).is_err());
    }
}

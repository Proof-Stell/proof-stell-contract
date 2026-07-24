use std::{
    collections::VecDeque,
    string::{String, ToString},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    vec::Vec,
};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::Mutex;

use crate::{cache::CacheKey, event::Event, metrics::MetricsRegistry};

const MAX_DLQ_DEPTH: usize = 10_000;

/// Prefix for Redis-backed DLQ storage keys.
const DLQ_REDIS_KEY_PREFIX: &str = "webhook:dlq:";

/// Prefix for deduplication cache keys.
const DEDUP_KEY_PREFIX: &str = "webhook:dedup:";

/// HMAC-SHA256 type alias for webhook request signing.
type HmacSha256 = Hmac<Sha256>;

/// Compute an HMAC-SHA256 signature for a webhook payload.
///
/// The signature is computed over the serialized JSON body using the configured
/// webhook secret. Receivers can verify the signature using the shared secret.
fn compute_webhook_signature(secret: &str, body: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac.update(body);
    let result = mac.finalize();
    let code = result.into_bytes();
    hex::encode(code)
}

/// The outbound payload delivered to each webhook URL.
///
/// Receivers can use `idempotency_key` to safely deduplicate retried deliveries —
/// the key is derived from the Soroban transaction hash and event index, so it is
/// stable across replays of the same on-chain event.
///
/// ## Idempotency Protocol
///
/// Every webhook delivery carries:
/// - `X-Idempotency-Key`: A stable, deterministic key derived from the on-chain
///   event. Receivers **must** store this key (along with the HTTP 200 response)
///   and reject/ignore subsequent deliveries with the same key.
/// - `X-Signature-256`: HMAC-SHA256 of the JSON body, computed with the shared
///   `WEBHOOK_SECRET`. Receivers **should** verify this signature before processing
///   the payload.
/// - `X-Event-Id`: The unique event UUID for traceability.
/// - `X-Event-Type`: The event type discriminator (e.g. `DocumentRegistered`).
///
/// ### Receiver Implementation (recommended)
///
/// ```text
/// POST /webhook
/// Content-Type: application/json
/// X-Idempotency-Key: contract:abc123:42:0:doc-1:DocumentRegistered
/// X-Signature-256: 3a8f1b2c...
/// X-Event-Id: 550e8400-e29b-41d4-a716-446655440000
/// X-Event-Type: DocumentRegistered
///
/// { "event_id": "...", "event_type": "DocumentRegistered", ... }
/// ```
///
/// 1. Check `X-Idempotency-Key` against your store; if seen before, return 200 OK.
/// 2. Verify `X-Signature-256` using the shared secret.
/// 3. Process the payload.
/// 4. Store the idempotency key with a TTL >= 1 hour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event_id: String,
    pub event_type: String,
    /// Stable deduplication token: `contract:<tx_hash>:<ledger>:<idx>:<aggregate>:<type>`.
    pub idempotency_key: String,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub aggregate_id: String,
    pub actor: String,
    pub data: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl From<&Event> for WebhookPayload {
    fn from(event: &Event) -> Self {
        Self {
            event_id: event.id.clone(),
            event_type: event.event_type.clone(),
            idempotency_key: event.idempotency_key.clone(),
            sequence: event.sequence,
            timestamp: event.timestamp,
            aggregate_id: event.aggregate_id.clone(),
            actor: event.actor.clone(),
            data: event.data.clone(),
            metadata: event.metadata.clone(),
        }
    }
}

/// A delivery that exhausted all retries and is queued for manual replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterEntry {
    pub url: String,
    pub payload: WebhookPayload,
    pub attempts: u32,
    pub last_error: String,
    pub failed_at: DateTime<Utc>,
}

/// Configuration for [`WebhookDispatcher`].
#[derive(Debug, Clone)]
pub struct WebhookDispatcherConfig {
    pub urls: Vec<String>,
    pub secret: Option<String>,
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub request_timeout_ms: u64,
    pub jitter_enabled: bool,
}

impl Default for WebhookDispatcherConfig {
    fn default() -> Self {
        Self {
            urls: vec![],
            secret: None,
            max_retries: 5,
            base_delay_ms: 200,
            max_delay_ms: 30_000,
            request_timeout_ms: 10_000,
            jitter_enabled: true,
        }
    }
}

/// Dispatches finalized events to all registered webhook URLs with exponential backoff
/// and a bounded dead-letter queue.
///
/// ## Ordering
/// URLs are contacted sequentially in registration order. An event is attempted against
/// every URL regardless of individual failures — a URL that exhausts retries is
/// dead-lettered without blocking delivery to subsequent URLs.
///
/// ## Idempotency
/// Each HTTP request carries `X-Idempotency-Key` derived from the event's transaction
/// hash and event index. Receivers can use this header to safely deduplicate retried
/// deliveries.
///
/// ## Dead-letter queue
/// Failed deliveries are pushed to a bounded queue (max 10 000 entries). When a Redis
/// cache backend is configured, the DLQ is persisted to Redis for durability across
/// process restarts. Call [`WebhookDispatcher::drain_dlq`] to retrieve entries for
/// manual replay.
///
/// ## Request Signing
/// When a `WEBHOOK_SECRET` is configured, every delivery includes an `X-Signature-256`
/// header containing the HMAC-SHA256 digest of the JSON body. Receivers should verify
/// this signature before processing.
pub struct WebhookDispatcher {
    urls: Vec<String>,
    client: reqwest::Client,
    secret: Option<String>,
    max_retries: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
    jitter_enabled: bool,
    metrics: Option<Arc<MetricsRegistry>>,
    dlq: Arc<Mutex<VecDeque<DeadLetterEntry>>>,
    cache: Option<Arc<crate::cache::CacheBackend>>,
    deduplication_ttl: u64,
}

impl WebhookDispatcher {
    pub fn new(config: WebhookDispatcherConfig, metrics: Option<Arc<MetricsRegistry>>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .unwrap_or_default();

        Self {
            urls: config.urls,
            client,
            secret: config.secret,
            max_retries: config.max_retries,
            base_delay_ms: config.base_delay_ms,
            max_delay_ms: config.max_delay_ms,
            jitter_enabled: config.jitter_enabled,
            metrics,
            dlq: Arc::new(Mutex::new(VecDeque::new())),
            cache: None,
            deduplication_ttl: 3600, // 1 hour default
        }
    }

    /// Construct a dispatcher from application config.
    pub fn from_app_config(
        config: &crate::config::AppConfig,
        metrics: Option<Arc<MetricsRegistry>>,
    ) -> Self {
        Self::new(
            WebhookDispatcherConfig {
                urls: config.webhook_urls.clone(),
                secret: config.webhook_secret.clone(),
                max_retries: config.webhook_max_retries,
                base_delay_ms: config.webhook_retry_base_delay_ms,
                max_delay_ms: config.webhook_retry_max_delay_ms,
                request_timeout_ms: config.webhook_request_timeout_ms,
                jitter_enabled: config.webhook_jitter_enabled,
            },
            metrics,
        )
    }

    pub fn with_cache(mut self, cache: Arc<crate::cache::CacheBackend>) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn with_deduplication_ttl(mut self, ttl: u64) -> Self {
        self.deduplication_ttl = ttl;
        self
    }

    /// Dispatch `event` to all configured URLs in registration order.
    ///
    /// Each URL is attempted independently. Failed deliveries are retried with exponential
    /// backoff before being moved to the dead-letter queue. Processing always continues
    /// to the next URL regardless of outcome.
    pub async fn dispatch(&self, event: &Event) {
        if self.urls.is_empty() {
            return;
        }

        // Check for duplicate delivery using cache (Redis-backed for cross-restart durability)
        if let Some(cache) = &self.cache {
            let dedup_key = format!("{}{}", DEDUP_KEY_PREFIX, event.idempotency_key);
            let cache_key = CacheKey::Events(dedup_key);

            if let Ok(Some(_)) = cache.get_raw(&cache_key).await {
                // Already delivered, skip
                if let Some(ref m) = self.metrics {
                    m.increment_webhook_retry();
                }
                return;
            }

            // Mark as delivered with TTL
            let _ = cache
                .set_raw(&cache_key, "delivered", self.deduplication_ttl)
                .await;
        }

        let payload = WebhookPayload::from(event);

        for url in &self.urls {
            self.deliver_with_retry(url, &payload).await;
        }
    }

    /// Spawn [`dispatch`](Self::dispatch) as a background task, releasing the caller immediately.
    pub fn dispatch_background(self: Arc<Self>, event: Event) {
        tokio::spawn(async move {
            self.dispatch(&event).await;
        });
    }

    async fn deliver_with_retry(&self, url: &str, payload: &WebhookPayload) {
        let overall_start = Instant::now();
        let mut last_error = String::from("no attempts made");

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = self.backoff_delay(attempt - 1);
                tokio::time::sleep(Duration::from_millis(delay)).await;

                if let Some(ref m) = self.metrics {
                    m.increment_webhook_retry();
                }
            }

            match self.send_once(url, payload).await {
                Ok(()) => {
                    let latency = overall_start.elapsed().as_secs_f64();
                    if let Some(ref m) = self.metrics {
                        m.record_webhook_delivery("success", latency);
                    }
                    return;
                }
                Err(e) => {
                    last_error = e.to_string();
                    eprintln!(
                        "[webhook] attempt {}/{} failed url={} error={}",
                        attempt + 1,
                        self.max_retries + 1,
                        url,
                        last_error
                    );
                }
            }
        }

        eprintln!(
            "[webhook] dead-lettering url={} after {} attempts",
            url,
            self.max_retries + 1
        );

        let entry = DeadLetterEntry {
            url: url.to_string(),
            payload: payload.clone(),
            attempts: self.max_retries + 1,
            last_error,
            failed_at: Utc::now(),
        };

        // Persist to Redis-backed DLQ if cache is available for durability across restarts.
        // When cache is available, skip the in-memory DLQ to avoid duplication on drain.
        let dlq_depth = if let Some(cache) = &self.cache {
            let dlq_key = CacheKey::Events(format!("{}{}", DLQ_REDIS_KEY_PREFIX, url));
            let serialized = serde_json::to_string(&entry).unwrap_or_default();
            let _ = cache.set_raw(&dlq_key, &serialized, 604800).await;
            // Approximate depth: count persisted entries per URL
            let mut count = 0usize;
            for u in &self.urls {
                let k = CacheKey::Events(format!("{}{}", DLQ_REDIS_KEY_PREFIX, u));
                if let Ok(Some(_)) = cache.get_raw(&k).await {
                    count += 1;
                }
            }
            count
        } else {
            let mut dlq = self.dlq.lock().await;
            if dlq.len() >= MAX_DLQ_DEPTH {
                dlq.pop_front();
            }
            dlq.push_back(entry);
            dlq.len()
        };

        if let Some(ref m) = self.metrics {
            m.record_webhook_delivery("dead_lettered", overall_start.elapsed().as_secs_f64());
            m.set_webhook_dlq_depth(dlq_depth as i64);
        }
    }

    async fn send_once(&self, url: &str, payload: &WebhookPayload) -> anyhow::Result<()> {
        let body = serde_json::to_string(payload)?;

        let mut builder = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Idempotency-Key", &payload.idempotency_key)
            .header("X-Event-Id", &payload.event_id)
            .header("X-Event-Type", &payload.event_type);

        if let Some(ref secret) = self.secret {
            let signature = compute_webhook_signature(secret, body.as_bytes());
            builder = builder
                .header("X-Signature-256", &signature)
                .header("X-Webhook-Secret", secret);
        }

        let response = builder.body(body).send().await?;
        let status = response.status();

        if status.is_success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("HTTP {}", status))
        }
    }

    /// Compute exponential backoff delay for attempt `n` (0-indexed).
    fn backoff_delay(&self, attempt: u32) -> u64 {
        let exp = self.base_delay_ms.saturating_mul(1u64 << attempt.min(20));
        let capped = exp.min(self.max_delay_ms);

        if self.jitter_enabled {
            let max_jitter = capped / 4;
            capped.saturating_add(jitter_ms(max_jitter))
        } else {
            capped
        }
    }

    /// Drain and return all dead-letter entries for manual replay.
    ///
    /// When a cache backend is configured, entries are loaded from persistent storage
    /// (which is the single source of truth). Otherwise, they are drained from the
    /// in-memory queue. After draining, the DLQ depth metric is reset to zero.
    pub async fn drain_dlq(&self) -> Vec<DeadLetterEntry> {
        let entries: Vec<DeadLetterEntry> = if let Some(cache) = &self.cache {
            let mut drained = Vec::new();
            for url in &self.urls {
                let dlq_key = CacheKey::Events(format!("{}{}", DLQ_REDIS_KEY_PREFIX, url));
                if let Ok(Some(raw)) = cache.get_raw(&dlq_key).await {
                    if let Ok(entry) = serde_json::from_str::<DeadLetterEntry>(&raw) {
                        drained.push(entry);
                    }
                }
                let _ = cache.delete(&dlq_key).await;
            }
            drained
        } else {
            let mut dlq = self.dlq.lock().await;
            dlq.drain(..).collect()
        };

        if let Some(ref m) = self.metrics {
            m.set_webhook_dlq_depth(0);
        }

        entries
    }

    /// Number of configured webhook URLs.
    pub async fn url_count(&self) -> usize {
        self.urls.len()
    }

    /// Current number of entries in the dead-letter queue (in-memory + persisted).
    pub async fn dlq_depth(&self) -> usize {
        if let Some(cache) = &self.cache {
            let mut count = 0usize;
            for url in &self.urls {
                let dlq_key = CacheKey::Events(format!("{}{}", DLQ_REDIS_KEY_PREFIX, url));
                if let Ok(Some(_)) = cache.get_raw(&dlq_key).await {
                    count += 1;
                }
            }
            count
        } else {
            self.dlq.lock().await.len()
        }
    }
}

/// Compute a jitter value in [0, max_ms) using sub-millisecond wall-clock noise.
fn jitter_ms(max_ms: u64) -> u64 {
    if max_ms == 0 {
        return 0;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    nanos % max_ms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheBackend;
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_event() -> Event {
        Event::new(
            "doc-1".to_string(),
            crate::event::EVENT_DOCUMENT_REGISTERED.to_string(),
            serde_json::json!({"issuer": "addr1"}),
            "issuer-addr".to_string(),
        )
        .with_idempotency_key("contract:tx1:100:0:doc-1:DocumentRegistered")
    }

    // ── Happy-path delivery ──────────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_sends_to_all_urls_in_order() {
        let server1 = MockServer::start().await;
        let server2 = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server1)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server2)
            .await;

        let config = WebhookDispatcherConfig {
            urls: vec![server1.uri(), server2.uri()],
            max_retries: 0,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, None);
        dispatcher.dispatch(&make_event()).await;

        assert_eq!(server1.received_requests().await.unwrap().len(), 1);
        assert_eq!(server2.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn dispatch_sends_idempotency_key_header() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header(
                "x-idempotency-key",
                "contract:tx1:100:0:doc-1:DocumentRegistered",
            ))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let config = WebhookDispatcherConfig {
            urls: vec![server.uri()],
            max_retries: 0,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, None);
        dispatcher.dispatch(&make_event()).await;

        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn dispatch_sends_event_type_header() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("x-event-type", "DocumentRegistered"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let config = WebhookDispatcherConfig {
            urls: vec![server.uri()],
            max_retries: 0,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, None);
        dispatcher.dispatch(&make_event()).await;

        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn dispatch_sends_webhook_secret_header_when_configured() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("x-webhook-secret", "my-secret"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let config = WebhookDispatcherConfig {
            urls: vec![server.uri()],
            secret: Some("my-secret".to_string()),
            max_retries: 0,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, None);
        dispatcher.dispatch(&make_event()).await;

        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn dispatch_noop_with_no_urls() {
        let config = WebhookDispatcherConfig {
            urls: vec![],
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, None);
        dispatcher.dispatch(&make_event()).await;
        assert_eq!(dispatcher.dlq_depth().await, 0);
    }

    // ── Dead-letter queue ────────────────────────────────────────────────────

    #[tokio::test]
    async fn http_error_response_goes_to_dlq() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let config = WebhookDispatcherConfig {
            urls: vec![server.uri()],
            max_retries: 0,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, None);
        dispatcher.dispatch(&make_event()).await;

        assert_eq!(dispatcher.dlq_depth().await, 1);
    }

    #[tokio::test]
    async fn dlq_entry_preserves_url_and_payload() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let config = WebhookDispatcherConfig {
            urls: vec![server.uri()],
            max_retries: 0,
            ..Default::default()
        };

        let event = make_event();
        let dispatcher = WebhookDispatcher::new(config, None);
        dispatcher.dispatch(&event).await;

        let entries = dispatcher.drain_dlq().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].payload.event_id, event.id);
        assert_eq!(entries[0].payload.idempotency_key, event.idempotency_key);
        assert_eq!(entries[0].attempts, 1);
    }

    #[tokio::test]
    async fn dead_letter_does_not_skip_subsequent_urls() {
        let good_server = MockServer::start().await;
        let bad_server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&bad_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&good_server)
            .await;

        let config = WebhookDispatcherConfig {
            urls: vec![bad_server.uri(), good_server.uri()],
            max_retries: 0,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, None);
        dispatcher.dispatch(&make_event()).await;

        assert_eq!(dispatcher.dlq_depth().await, 1);
        assert_eq!(good_server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn drain_dlq_clears_entries_and_returns_them() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let config = WebhookDispatcherConfig {
            urls: vec![server.uri()],
            max_retries: 0,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, None);
        dispatcher.dispatch(&make_event()).await;

        assert_eq!(dispatcher.dlq_depth().await, 1);
        let entries = dispatcher.drain_dlq().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(dispatcher.dlq_depth().await, 0);
    }

    // ── Metrics ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn successful_delivery_records_metrics() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let metrics = MetricsRegistry::arc();
        let config = WebhookDispatcherConfig {
            urls: vec![server.uri()],
            max_retries: 0,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, Some(Arc::clone(&metrics)));
        dispatcher.dispatch(&make_event()).await;

        let output = metrics.render();
        assert!(output.contains("webhook_deliveries_total"));
        assert!(output.contains(r#"status="success""#));
        assert!(output.contains("webhook_delivery_latency_seconds"));
    }

    #[tokio::test]
    async fn dead_lettered_delivery_records_dlq_metric() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let metrics = MetricsRegistry::arc();
        let config = WebhookDispatcherConfig {
            urls: vec![server.uri()],
            max_retries: 0,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, Some(Arc::clone(&metrics)));
        dispatcher.dispatch(&make_event()).await;

        let output = metrics.render();
        assert!(output.contains("webhook_dlq_depth"));
        assert!(output.contains(r#"status="dead_lettered""#));
    }

    #[tokio::test]
    async fn retry_increments_retry_metric() {
        let server = MockServer::start().await;

        // First response fails, second succeeds.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let metrics = MetricsRegistry::arc();
        let config = WebhookDispatcherConfig {
            urls: vec![server.uri()],
            max_retries: 2,
            base_delay_ms: 1,
            jitter_enabled: false,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, Some(Arc::clone(&metrics)));
        dispatcher.dispatch(&make_event()).await;

        let output = metrics.render();
        assert!(output.contains("webhook_retries_total"));
        // Event was ultimately delivered, not dead-lettered.
        assert_eq!(dispatcher.dlq_depth().await, 0);
    }

    // ── Backoff ───────────────────────────────────────────────────────────────

    #[test]
    fn backoff_delay_doubles_each_attempt() {
        let config = WebhookDispatcherConfig {
            base_delay_ms: 100,
            max_delay_ms: 30_000,
            jitter_enabled: false,
            ..Default::default()
        };
        let d = WebhookDispatcher::new(config, None);

        assert_eq!(d.backoff_delay(0), 100);
        assert_eq!(d.backoff_delay(1), 200);
        assert_eq!(d.backoff_delay(2), 400);
        assert_eq!(d.backoff_delay(3), 800);
    }

    #[test]
    fn backoff_delay_is_capped_at_max_delay() {
        let config = WebhookDispatcherConfig {
            base_delay_ms: 100,
            max_delay_ms: 1_000,
            jitter_enabled: false,
            ..Default::default()
        };
        let d = WebhookDispatcher::new(config, None);

        assert!(d.backoff_delay(20) <= 1_000);
    }

    #[test]
    fn backoff_delay_with_jitter_stays_above_base() {
        let config = WebhookDispatcherConfig {
            base_delay_ms: 100,
            max_delay_ms: 30_000,
            jitter_enabled: true,
            ..Default::default()
        };
        let d = WebhookDispatcher::new(config, None);

        // With jitter the result is >= base (capped) and <= capped + capped/4.
        let delay = d.backoff_delay(0);
        assert!(delay >= 100);
        assert!(delay <= 125); // 100 + 100/4
    }

    // ── Payload ───────────────────────────────────────────────────────────────

    #[test]
    fn webhook_payload_carries_all_event_fields() {
        let event = make_event();
        let payload = WebhookPayload::from(&event);

        assert_eq!(payload.event_id, event.id);
        assert_eq!(payload.event_type, event.event_type);
        assert_eq!(payload.idempotency_key, event.idempotency_key);
        assert_eq!(payload.sequence, event.sequence);
        assert_eq!(payload.aggregate_id, event.aggregate_id);
        assert_eq!(payload.actor, event.actor);
    }

    // ── HMAC-SHA256 Signature ──────────────────────────────────────────────

    #[test]
    fn compute_webhook_signature_produces_expected_output() {
        let secret = "test-secret";
        let body = br#"{"event_id":"evt-1"}"#;
        let sig = compute_webhook_signature(secret, body);
        // HMAC-SHA256 should produce a 64-character hex string
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn compute_webhook_signature_different_secrets_produce_different_signatures() {
        let body = b"hello";
        let sig1 = compute_webhook_signature("secret1", body);
        let sig2 = compute_webhook_signature("secret2", body);
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn compute_webhook_signature_different_bodies_produce_different_signatures() {
        let sig1 = compute_webhook_signature("s", b"body1");
        let sig2 = compute_webhook_signature("s", b"body2");
        assert_ne!(sig1, sig2);
    }

    #[tokio::test]
    async fn dispatch_sends_signature_header_when_secret_configured() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let config = WebhookDispatcherConfig {
            urls: vec![server.uri()],
            secret: Some("whsec_test".to_string()),
            max_retries: 0,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, None);
        dispatcher.dispatch(&make_event()).await;

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let sig_header = reqs[0].headers.get("x-signature-256");
        assert!(sig_header.is_some());
        let sig_value = sig_header.unwrap().to_str().unwrap();
        assert_eq!(sig_value.len(), 64);
    }

    // ── Deduplication ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn deduplication_skips_already_delivered_event() {
        use crate::cache::InMemoryCache;
        let server1 = MockServer::start().await;
        let server2 = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server1)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server2)
            .await;

        let cache = Arc::new(CacheBackend::InMemory(InMemoryCache::new()));
        let config = WebhookDispatcherConfig {
            urls: vec![server1.uri(), server2.uri()],
            max_retries: 0,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, None)
            .with_cache(Arc::clone(&cache))
            .with_deduplication_ttl(3600);

        let event = make_event();

        // First dispatch should deliver to both URLs
        dispatcher.dispatch(&event).await;
        assert_eq!(server1.received_requests().await.unwrap().len(), 1);
        assert_eq!(server2.received_requests().await.unwrap().len(), 1);

        // Second dispatch should be skipped entirely (dedup)
        dispatcher.dispatch(&event).await;
        assert_eq!(server1.received_requests().await.unwrap().len(), 1);
        assert_eq!(server2.received_requests().await.unwrap().len(), 1);
    }

    // ── DLQ Persistence ────────────────────────────────────────────────────

    #[tokio::test]
    async fn dead_lettered_entry_is_persisted_to_cache() {
        use crate::cache::InMemoryCache;
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let cache = Arc::new(CacheBackend::InMemory(InMemoryCache::new()));
        let config = WebhookDispatcherConfig {
            urls: vec![server.uri()],
            max_retries: 0,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, None).with_cache(Arc::clone(&cache));
        dispatcher.dispatch(&make_event()).await;

        let dlq_key = CacheKey::Events(format!("{}{}", DLQ_REDIS_KEY_PREFIX, server.uri()));
        let persisted = cache.get_raw(&dlq_key).await.unwrap();
        assert!(
            persisted.is_some(),
            "DLQ entry should be persisted to cache"
        );

        let entry: DeadLetterEntry = serde_json::from_str(&persisted.unwrap()).unwrap();
        assert_eq!(entry.url, server.uri());
        assert_eq!(entry.attempts, 1);
    }

    #[tokio::test]
    async fn drain_dlq_removes_persisted_entries() {
        use crate::cache::InMemoryCache;
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let cache = Arc::new(CacheBackend::InMemory(InMemoryCache::new()));
        let config = WebhookDispatcherConfig {
            urls: vec![server.uri()],
            max_retries: 0,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config, None).with_cache(Arc::clone(&cache));
        dispatcher.dispatch(&make_event()).await;

        // Drain returns the persisted entry (single source of truth when cache is available)
        let entries = dispatcher.drain_dlq().await;
        assert_eq!(entries.len(), 1);

        // Cache entry should be cleared after drain
        let dlq_key = CacheKey::Events(format!("{}{}", DLQ_REDIS_KEY_PREFIX, server.uri()));
        assert!(cache.get_raw(&dlq_key).await.unwrap().is_none());
        // Both in-memory and persisted entries are cleared
        assert_eq!(dispatcher.dlq_depth().await, 0);
    }
}

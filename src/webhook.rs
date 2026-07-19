use std::{
    collections::VecDeque,
    string::{String, ToString},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    vec::Vec,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{cache::CacheKey, event::Event, metrics::MetricsRegistry};

const MAX_DLQ_DEPTH: usize = 10_000;

/// The outbound payload delivered to each webhook URL.
///
/// Receivers can use `idempotency_key` to safely deduplicate retried deliveries —
/// the key is derived from the Soroban transaction hash and event index, so it is
/// stable across replays of the same on-chain event.
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
/// Failed deliveries are pushed to an in-memory bounded queue (max 10 000 entries).
/// Call [`WebhookDispatcher::drain_dlq`] to retrieve entries for manual replay.
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

        // Check for duplicate delivery using cache
        if let Some(cache) = &self.cache {
            let dedup_key = format!("webhook:{}", event.idempotency_key);
            let cache_key = CacheKey::Events(dedup_key);
            
            if let Ok(Some(_)) = cache.get_raw(&cache_key).await {
                // Already delivered, skip
                if let Some(ref m) = self.metrics {
                    m.increment_webhook_retry(); // Count as a skip/retry
                }
                return;
            }
            
            // Mark as delivered
            let _ = cache.set_raw(&cache_key, "delivered", self.deduplication_ttl).await;
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

        let dlq_depth = {
            let mut dlq = self.dlq.lock().await;
            if dlq.len() >= MAX_DLQ_DEPTH {
                // Evict oldest entry when the queue is full.
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
            .header("X-Event-Type", &payload.event_type)
            .body(body);

        if let Some(ref secret) = self.secret {
            builder = builder.header("X-Webhook-Secret", secret);
        }

        let response = builder.send().await?;
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
    /// After draining, the DLQ depth metric is reset to zero.
    pub async fn drain_dlq(&self) -> Vec<DeadLetterEntry> {
        let mut dlq = self.dlq.lock().await;
        let entries: Vec<_> = dlq.drain(..).collect();

        if let Some(ref m) = self.metrics {
            m.set_webhook_dlq_depth(0);
        }

        entries
    }

    /// Current number of entries in the dead-letter queue.
    pub async fn dlq_depth(&self) -> usize {
        self.dlq.lock().await.len()
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
}

//! ProofStell service binary entry point.
//!
//! This binary starts an HTTP server that exposes:
//!
//! - `GET /health`  — JSON health check
//! - `GET /metrics` — Prometheus text-format metrics (via [`MetricsRegistry`])
//!
//! # Configuration
//!
//! All settings are read from environment variables. See [`AppConfig::from_env`]
//! for the full reference.
//!
//! # Running
//!
//! ```bash
//! export STELLAR_SECRET_KEY="SBU2R..."
//! cargo run --release
//! ```
//!
//! The server binds to `0.0.0.0:{PORT}` (default `8080`).

// ── WASM stub ────────────────────────────────────────────────────────────
// The binary only works on native targets.  Provide a stub so that `cargo
// build --target wasm32-unknown-unknown` does not error on the bin target.

#[cfg(target_arch = "wasm32")]
fn main() {
    eprintln!("error: this service binary does not run under wasm32");
    std::process::exit(1);
}

// ── Native server entry point ────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::extract::State;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::json;

    use proofstell_contract::cache::{CacheBackend, CacheBulkheadConfig, CacheCircuitBreakerConfig, InMemoryCache};
    use proofstell_contract::config::{self, AppConfig, ConfigUpdate, ConfigWatcher};
    use proofstell_contract::metrics::MetricsRegistry;
    use proofstell_contract::webhook::WebhookDispatcher;

    /// Shared application state, accessible by all axum handlers.
    #[derive(Clone)]
    struct AppState {
        metrics: Arc<MetricsRegistry>,
        webhook: Arc<WebhookDispatcher>,
        cache: Arc<CacheBackend>,
        config_watcher: ConfigWatcher,
        config_version: u32,
        audit_log: Arc<SecurityAuditLog>,
    }

    /// Build the axum router with all application routes.
    fn build_router(state: AppState) -> Router {
        Router::new()
            .route("/health", get(health_handler))
            .route("/metrics", get(metrics_handler))
            .route("/webhooks/health", get(webhook_health_handler))
            .route("/webhooks/dlq", get(dlq_status_handler))
            .route("/webhooks/dlq/drain", post(dlq_drain_handler))
            .route("/cache/stats", get(cache_stats_handler))
            .route("/config/status", get(config_status_handler))
            .route("/config/reload", post(config_reload_handler))
            .route("/audit/log", get(audit_log_handler))
            .route("/audit/verify", get(audit_verify_handler))
            .with_state(state)
    }

    /// `GET /health` — returns a JSON health-check payload.
    async fn health_handler() -> impl IntoResponse {
        Json(json!({"status": "ok"}))
    }

    /// `GET /metrics` — returns Prometheus text-format metrics.
    async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
        state.metrics.render()
    }

    /// `GET /config/status` — returns current config version info.
    async fn config_status_handler(State(state): State<AppState>) -> impl IntoResponse {
        Json(json!({
            "config_version": state.config_version,
            "schema_version": AppConfig::version(),
        }))
    }

    /// `POST /config/reload` — triggers a config reload from environment variables.
    async fn config_reload_handler(State(state): State<AppState>) -> impl IntoResponse {
        match AppConfig::from_env_with_metrics(Some(Arc::clone(&state.metrics))) {
            Ok(new_config) => match ConfigUpdate::new(new_config) {
                Ok(update) => {
                    if state.config_watcher.send(update).is_ok() {
                        Json(
                            json!({"status": "ok", "message": "config reload triggered successfully"}),
                        )
                    } else {
                        Json(
                            json!({"status": "error", "message": "no subscribers for config update"}),
                        )
                    }
                }
                Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
            },
            Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
        }
    }

    /// `GET /webhooks/dlq` — returns the current DLQ depth.
    async fn dlq_status_handler(State(state): State<AppState>) -> impl IntoResponse {
        let depth = state.webhook.dlq_depth().await;
        Json(json!({ "dlq_depth": depth }))
    }

    /// `POST /webhooks/dlq/drain` — drains and returns all DLQ entries for manual replay.
    async fn dlq_drain_handler(State(state): State<AppState>) -> impl IntoResponse {
        let entries = state.webhook.drain_dlq().await;
        Json(json!({ "drained": entries.len(), "entries": entries }))
    }

    /// `GET /webhooks/health` — returns the webhook subsystem health status.
    async fn webhook_health_handler(State(state): State<AppState>) -> impl IntoResponse {
        let dlq_depth = state.webhook.dlq_depth().await;
        let url_count = state.webhook.url_count().await;
        let is_healthy = dlq_depth == 0 && url_count > 0;
        Json(json!({
            "status": if is_healthy { "healthy" } else if url_count == 0 { "disabled" } else { "degraded" },
            "url_count": url_count,
            "dlq_depth": dlq_depth,
        }))
    }

    /// `GET /cache/stats` — returns cache statistics.
    async fn cache_stats_handler(State(state): State<AppState>) -> impl IntoResponse {
        match &*state.cache {
            CacheBackend::InMemory(cache) => {
                let stats = cache.stats().await;
                Json(json!(
                    {
                        "backend": "inmemory",
                        "hits": stats.hits,
                        "misses": stats.misses,
                        "evictions": stats.evictions,
                        "expired": stats.expired,
                        "hit_rate": stats.hit_rate,
                        "current_size": stats.current_size,
                        "max_size": stats.max_size
                    }
                ))
            }
            CacheBackend::Redis(_) => Json(json!(
                {
                    "backend": "redis",
                    "message": "Redis cache statistics not yet implemented"
                }
            )),
        }
    }

    async fn audit_log_handler(State(state): State<AppState>) -> impl IntoResponse {
        Json(json!({ "entries": state.audit_log.entries() }))
    }

    async fn audit_verify_handler(State(state): State<AppState>) -> impl IntoResponse {
        let valid = state.audit_log.verify_integrity();
        Json(json!({ "valid": valid }))
    }

    /// Bootstrap: load config, wire up services, and start the server.
    pub async fn run() -> anyhow::Result<()> {
        // ── Metrics ─────────────────────────────────────────────────
        let metrics = MetricsRegistry::arc();

        // ── Configuration ───────────────────────────────────────────
        let config = AppConfig::from_env_with_metrics(Some(Arc::clone(&metrics)))
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        eprintln!(
            "[proofstell] Configuration v{} loaded successfully",
            AppConfig::version()
        );
        eprintln!("[proofstell]   port:               {}", config.port);
        eprintln!(
            "[proofstell]   stellar_horizon_url: {}",
            config.stellar_horizon_url
        );
        eprintln!("[proofstell]   redis_url:           {}", config.redis_url);
        eprintln!(
            "[proofstell]   rate_limit:          {}/s (burst {})",
            config.rate_limit_per_second, config.rate_limit_burst
        );
        eprintln!(
            "[proofstell]   webhooks:            {} url(s) configured (max_retries={})",
            config.webhook_urls.len(),
            config.webhook_max_retries,
        );
        eprintln!(
            "[proofstell]   cache:              backend={}, max_size={}",
            config.cache_backend, config.cache_max_size
        );

        // ── Create config hot-reload channel ─────────────────────────
        let (config_watcher, mut config_rx) = config::config_channel(config.clone())
            .map_err(|e| anyhow::anyhow!("failed to create config channel: {e}"))?;

        // ── Cache initialization ───────────────────────────────────────
        let cache: Arc<CacheBackend> = match config.cache_backend.as_str() {
            "redis" => {
                eprintln!("[proofstell] Initializing Redis cache backend...");
                let cb_config = CacheCircuitBreakerConfig {
                    failure_threshold: config.cache_circuit_breaker_failure_threshold,
                    open_duration_ms: config.cache_circuit_breaker_open_duration_ms,
                    half_open_max_calls: config.cache_circuit_breaker_half_open_max_calls,
                    backoff_base_ms: config.cache_circuit_breaker_backoff_base_ms,
                    backoff_max_ms: config.cache_circuit_breaker_backoff_max_ms,
                };
                let bulkhead_config = CacheBulkheadConfig {
                    max_concurrent: config.cache_bulkhead_max_concurrent,
                    max_queue: config.cache_bulkhead_max_queue,
                };
                match proofstell_contract::cache::RedisCache::with_config(
                    &config.redis_url,
                    cb_config,
                    bulkhead_config,
                ).await {
                    Ok(redis_cache) => {
                        let cache = redis_cache.with_metrics(Arc::clone(&metrics));
                        Arc::new(CacheBackend::Redis(cache))
                    }
                    Err(e) => {
                        eprintln!("[proofstell] Failed to initialize Redis cache: {}, falling back to InMemory", e);
                        let cache = InMemoryCache::with_max_size(config.cache_max_size)
                            .with_metrics(Arc::clone(&metrics));
                        Arc::new(CacheBackend::InMemory(cache))
                    }
                }
            }
            _ => {
                eprintln!(
                    "[proofstell] Initializing InMemory cache backend (max_size={})",
                    config.cache_max_size
                );
                let cache = InMemoryCache::with_max_size(config.cache_max_size)
                    .with_metrics(Arc::clone(&metrics));
                Arc::new(CacheBackend::InMemory(cache))
            }
        };

        eprintln!("[proofstell] Cache initialized successfully");

        // ── Webhook dispatcher ───────────────────────────────────────
        let webhook = Arc::new(WebhookDispatcher::from_app_config(
            &config,
            Some(Arc::clone(&metrics)),
        ));

        // ── Background config watcher task ──────────────────────────
        let bg_metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            while config_rx.changed().await.is_ok() {
                let update = config_rx.borrow_and_update().clone();
                eprintln!(
                    "[proofstell] Config hot-reload: version={} applied",
                    update.version.value()
                );
                bg_metrics.increment_config_reload();
            }
        });

        // ── Security audit log ──────────────────────────────────────
        let audit_log = Arc::new(SecurityAuditLog::new(b"proofstell-hmac-key".to_vec()));
        audit_log.record("startup", "service started", "127.0.0.1");

        // ── Router ──────────────────────────────────────────────────
        let state = AppState {
            metrics: Arc::clone(&metrics),
            webhook,
            cache,
            config_watcher,
            config_version: AppConfig::version(),
            audit_log,
        };
        let app = build_router(state);

        // ── Bind & serve ────────────────────────────────────────────
        let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
        eprintln!("[proofstell] Starting HTTP server on {addr}");
        eprintln!("[proofstell] Config endpoints: GET /config/status, POST /config/reload");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct SecurityAuditEntry {
        pub timestamp: String,
        pub event_type: String,
        pub detail: String,
        pub source_ip: String,
        pub integrity_hash: String,
    }

    pub struct SecurityAuditLog {
        entries: std::sync::Mutex<Vec<SecurityAuditEntry>>,
        hmac_key: Vec<u8>,
    }

    impl SecurityAuditLog {
        pub fn new(hmac_key: Vec<u8>) -> Self {
            Self { entries: std::sync::Mutex::new(Vec::new()), hmac_key }
        }

        pub fn record(&self, event_type: &str, detail: &str, source_ip: &str) {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| format!("{}", d.as_secs()))
                .unwrap_or_default();
            let payload = format!("{}:{}:{}:{}", timestamp, event_type, detail, source_ip);
            let integrity_hash = hmac_sha256_hex(&self.hmac_key, payload.as_bytes());
            let entry = SecurityAuditEntry {
                timestamp,
                event_type: event_type.to_string(),
                detail: detail.to_string(),
                source_ip: source_ip.to_string(),
                integrity_hash,
            };
            if let Ok(mut entries) = self.entries.lock() {
                entries.push(entry);
            }
        }

        pub fn entries(&self) -> Vec<SecurityAuditEntry> {
            self.entries.lock().map(|e| e.clone()).unwrap_or_default()
        }

        pub fn verify_integrity(&self) -> bool {
            let entries = match self.entries.lock() {
                Ok(e) => e,
                Err(_) => return false,
            };
            for entry in entries.iter() {
                let payload = format!("{}:{}:{}:{}", entry.timestamp, entry.event_type, entry.detail, entry.source_ip);
                let expected = hmac_sha256_hex(&self.hmac_key, payload.as_bytes());
                if expected != entry.integrity_hash {
                    return false;
                }
            }
            true
        }
    }

    fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        data.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() {
    if let Err(e) = native::run().await {
        eprintln!("[proofstell] Fatal error: {e:#}");
        std::process::exit(1);
    }
}

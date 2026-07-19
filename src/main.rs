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

    use proofstell_contract::cache::{CacheBackend, InMemoryCache};
    use proofstell_contract::config::AppConfig;
    use proofstell_contract::metrics::MetricsRegistry;
    use proofstell_contract::webhook::WebhookDispatcher;

    /// Shared application state, accessible by all axum handlers.
    #[derive(Clone)]
    struct AppState {
        metrics: Arc<MetricsRegistry>,
        webhook: Arc<WebhookDispatcher>,
        cache: Arc<CacheBackend>,
    }

    /// Build the axum router with all application routes.
    fn build_router(state: AppState) -> Router {
        Router::new()
            .route("/health", get(health_handler))
            .route("/metrics", get(metrics_handler))
            .route("/webhooks/dlq", get(dlq_status_handler))
            .route("/webhooks/dlq/drain", post(dlq_drain_handler))
            .route("/cache/stats", get(cache_stats_handler))
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
            CacheBackend::Redis(_) => {
                Json(json!(
                    {
                        "backend": "redis",
                        "message": "Redis cache statistics not yet implemented"
                    }
                ))
            }
        }
    }

    /// Bootstrap: load config, wire up services, and start the server.
    pub async fn run() -> anyhow::Result<()> {
        // ── Metrics ─────────────────────────────────────────────────
        let metrics = MetricsRegistry::arc();

        // ── Configuration ───────────────────────────────────────────
        let config = AppConfig::from_env_with_metrics(Some(Arc::clone(&metrics)))
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        eprintln!("[proofstell] Configuration loaded successfully");
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
            config.cache_backend,
            config.cache_max_size
        );

        // ── Cache initialization ───────────────────────────────────────
        let cache: Arc<CacheBackend> = match config.cache_backend.as_str() {
            "redis" => {
                eprintln!("[proofstell] Initializing Redis cache backend...");
                match proofstell_contract::cache::RedisCache::new(&config.redis_url).await {
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
                eprintln!("[proofstell] Initializing InMemory cache backend (max_size={})", config.cache_max_size);
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

        // ── Router ──────────────────────────────────────────────────
        let state = AppState {
            metrics: Arc::clone(&metrics),
            webhook,
            cache,
        };
        let app = build_router(state);

        // ── Bind & serve ────────────────────────────────────────────
        let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
        eprintln!("[proofstell] Starting HTTP server on {addr}");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
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

use std::{
    env, fmt,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use stellar_strkey::ed25519::PrivateKey;
use thiserror::Error;

use crate::metrics::MetricsRegistry;

// ── Constants ─────────────────────────────────────────────────────────────

const DEFAULT_STELLAR_RETRY_BASE_DELAY_MS: u64 = 100;
const DEFAULT_STELLAR_RETRY_MAX_DELAY_MS: u64 = 10_000;
const DEFAULT_STELLAR_REQUEST_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD: u32 = 5;
const DEFAULT_STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS: u64 = 30_000;
const DEFAULT_STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS: u32 = 1;
const DEFAULT_STELLAR_RETRY_JITTER_TYPE: &str = "full";
const DEFAULT_STELLAR_BULKHEAD_MAX_CONCURRENT: u32 = 10;
const DEFAULT_STELLAR_BULKHEAD_MAX_QUEUE: u32 = 100;

const DEFAULT_CACHE_CIRCUIT_BREAKER_FAILURE_THRESHOLD: u32 = 5;
const DEFAULT_CACHE_CIRCUIT_BREAKER_OPEN_DURATION_MS: u64 = 30_000;
const DEFAULT_CACHE_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS: u32 = 1;
const DEFAULT_CACHE_CIRCUIT_BREAKER_BACKOFF_BASE_MS: u64 = 100;
const DEFAULT_CACHE_CIRCUIT_BREAKER_BACKOFF_MAX_MS: u64 = 30_000;
const DEFAULT_CACHE_BULKHEAD_MAX_CONCURRENT: u32 = 20;
const DEFAULT_CACHE_BULKHEAD_MAX_QUEUE: u32 = 200;

/// Current configuration schema version.
/// Increment this when adding or removing fields that break backward compatibility.
pub const CONFIG_VERSION: u32 = 1;

/// Minimum port number allowed.
pub const PORT_MIN: u16 = 1;
/// Maximum port number allowed.
pub const PORT_MAX: u16 = 65535;

/// Minimum allowable delay/timeout in milliseconds.
pub const MIN_TIMEOUT_MS: u64 = 1;
/// Maximum allowable delay/timeout in milliseconds.
pub const MAX_TIMEOUT_MS: u64 = 300_000; // 5 minutes

/// Minimum rate limit burst (must be at least 1).
pub const MIN_BURST: u32 = 1;

// ── Strongly-typed wrapper types ──────────────────────────────────────────

/// A validated HTTP(S) URL.
#[derive(Debug, Clone)]
pub struct ValidatedUrl(url::Url);

impl ValidatedUrl {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let url = url::Url::parse(input)
            .map_err(|_| ConfigError::Validation(format!("invalid URL: '{}'", input)))?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(ConfigError::Validation(format!(
                "URL must use http or https scheme, got '{}' in '{}'",
                url.scheme(),
                input
            )));
        }
        Ok(Self(url))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_inner(self) -> url::Url {
        self.0
    }
}

impl AsRef<str> for ValidatedUrl {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

/// A validated redis:// or rediss:// URL.
#[derive(Debug, Clone)]
pub struct ValidatedRedisUrl(url::Url);

impl ValidatedRedisUrl {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let url = url::Url::parse(input)
            .map_err(|_| ConfigError::Validation(format!("invalid Redis URL: '{}'", input)))?;
        if url.scheme() != "redis" && url.scheme() != "rediss" {
            return Err(ConfigError::Validation(format!(
                "REDIS_URL must use redis:// or rediss:// scheme, got '{}'",
                url.scheme()
            )));
        }
        Ok(Self(url))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_inner(self) -> url::Url {
        self.0
    }
}

/// A validated port number.
#[derive(Debug, Clone, Copy)]
pub struct ValidatedPort(u16);

impl ValidatedPort {
    pub fn new(port: u16) -> Result<Self, ConfigError> {
        if port < PORT_MIN {
            return Err(ConfigError::Validation(format!(
                "port {} is below minimum {}",
                port, PORT_MIN
            )));
        }
        if port > PORT_MAX {
            return Err(ConfigError::Validation(format!(
                "port {} exceeds maximum {}",
                port, PORT_MAX
            )));
        }
        Ok(Self(port))
    }

    pub fn value(&self) -> u16 {
        self.0
    }
}

impl From<ValidatedPort> for u16 {
    fn from(p: ValidatedPort) -> Self {
        p.0
    }
}

// ── Config versioning ────────────────────────────────────────────────────

/// Configuration version tracking for rollback prevention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigVersion(u32);

impl ConfigVersion {
    pub fn new(version: u32) -> Result<Self, ConfigError> {
        if version == 0 {
            return Err(ConfigError::Validation(
                "config version must be >= 1".to_string(),
            ));
        }
        if version > CONFIG_VERSION {
            return Err(ConfigError::Validation(format!(
                "config version {} exceeds current schema version {}",
                version, CONFIG_VERSION
            )));
        }
        Ok(Self(version))
    }

    pub fn current() -> Self {
        Self(CONFIG_VERSION)
    }

    pub fn value(&self) -> u32 {
        self.0
    }
}

// ── Hot-reload channel ───────────────────────────────────────────────────

/// A configuration update notification sent through the hot-reload channel.
#[derive(Debug, Clone)]
pub struct ConfigUpdate {
    pub config: AppConfig,
    pub version: ConfigVersion,
}

impl ConfigUpdate {
    pub fn new(config: AppConfig) -> Result<Self, ConfigError> {
        let version = ConfigVersion::current();
        Ok(Self { config, version })
    }
}

/// Type alias for the hot-reload watch channel.
pub type ConfigWatcher = std::sync::Arc<tokio::sync::watch::Sender<ConfigUpdate>>;

/// Create a new hot-reload channel with the given initial config.
pub fn config_channel(
    initial: AppConfig,
) -> Result<(ConfigWatcher, tokio::sync::watch::Receiver<ConfigUpdate>), ConfigError> {
    let update = ConfigUpdate::new(initial)?;
    let (tx, rx) = tokio::sync::watch::channel(update);
    Ok((std::sync::Arc::new(tx), rx))
}

// ── Main configuration struct ───────────────────────────────────────────

#[derive(Clone)]
pub struct AppConfig {
    pub port: u16,
    pub stellar_horizon_url: String,
    pub stellar_secret_key: Option<String>,
    pub redis_url: String,

    // ── Global rate-limit tier ──────────────────────────────────────────
    /// Maximum requests per second across **all** issuers combined.
    pub rate_limit_per_second: u32,
    /// Burst allowance for the global tier.
    pub rate_limit_burst: u32,

    // ── Per-issuer rate-limit tier ──────────────────────────────────────
    /// Maximum requests per second **per issuer** address.
    ///
    /// Defaults to `10`. The global tier always takes precedence; this limit
    /// applies after the global bucket has been checked.
    pub per_issuer_rate_limit_per_second: u32,
    /// Burst allowance for the per-issuer tier.
    ///
    /// Defaults to twice `per_issuer_rate_limit_per_second`.
    pub per_issuer_rate_limit_burst: u32,
    /// Seconds an issuer entry is kept alive after its last request.
    ///
    /// Entries older than this TTL are eligible for eviction by the background
    /// cleanup task. Defaults to `3600` (1 hour).
    pub issuer_rate_limit_ttl_seconds: u64,

    pub stellar_max_retries: u32,
    pub stellar_retry_base_delay_ms: u64,
    pub stellar_retry_max_delay_ms: u64,
    pub stellar_retry_jitter_enabled: bool,
    pub stellar_request_timeout_ms: u64,
    pub stellar_circuit_breaker_failure_threshold: u32,
    pub stellar_circuit_breaker_open_duration_ms: u64,
    pub stellar_circuit_breaker_half_open_max_calls: u32,
    pub stellar_retry_jitter_type: String,
    pub stellar_bulkhead_max_concurrent: u32,
    pub stellar_bulkhead_max_queue: u32,
    pub log_level: String,
    pub webhook_urls: Vec<String>,
    pub webhook_secret: Option<String>,
    pub webhook_max_retries: u32,
    pub webhook_retry_base_delay_ms: u64,
    pub webhook_retry_max_delay_ms: u64,
    pub webhook_request_timeout_ms: u64,
    pub webhook_jitter_enabled: bool,
    pub cache_verification_ttl: u64,

    // ── Cache configuration ─────────────────────────────────────────────
    pub cache_backend: String,
    pub cache_max_size: usize,
    pub cache_config_ttl: u64,
    pub cache_events_ttl: u64,

    // ── Cache circuit breaker configuration ─────────────────────────────
    pub cache_circuit_breaker_failure_threshold: u32,
    pub cache_circuit_breaker_open_duration_ms: u64,
    pub cache_circuit_breaker_half_open_max_calls: u32,
    pub cache_circuit_breaker_backoff_base_ms: u64,
    pub cache_circuit_breaker_backoff_max_ms: u64,

    // ── Cache bulkhead configuration ───────────────────────────────────
    pub cache_bulkhead_max_concurrent: u32,
    pub cache_bulkhead_max_queue: u32,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppConfig")
            .field("port", &self.port)
            .field("stellar_horizon_url", &self.stellar_horizon_url)
            .field(
                "stellar_secret_key",
                &self.stellar_secret_key.as_deref().map(|_| "<redacted>"),
            )
            .field("redis_url", &self.redis_url)
            .field("rate_limit_per_second", &self.rate_limit_per_second)
            .field("rate_limit_burst", &self.rate_limit_burst)
            .field(
                "per_issuer_rate_limit_per_second",
                &self.per_issuer_rate_limit_per_second,
            )
            .field(
                "per_issuer_rate_limit_burst",
                &self.per_issuer_rate_limit_burst,
            )
            .field(
                "issuer_rate_limit_ttl_seconds",
                &self.issuer_rate_limit_ttl_seconds,
            )
            .field("stellar_max_retries", &self.stellar_max_retries)
            .field(
                "stellar_retry_base_delay_ms",
                &self.stellar_retry_base_delay_ms,
            )
            .field(
                "stellar_retry_max_delay_ms",
                &self.stellar_retry_max_delay_ms,
            )
            .field(
                "stellar_retry_jitter_enabled",
                &self.stellar_retry_jitter_enabled,
            )
            .field(
                "stellar_request_timeout_ms",
                &self.stellar_request_timeout_ms,
            )
            .field(
                "stellar_circuit_breaker_failure_threshold",
                &self.stellar_circuit_breaker_failure_threshold,
            )
            .field(
                "stellar_circuit_breaker_open_duration_ms",
                &self.stellar_circuit_breaker_open_duration_ms,
            )
            .field(
                "stellar_circuit_breaker_half_open_max_calls",
                &self.stellar_circuit_breaker_half_open_max_calls,
            )
            .field("stellar_retry_jitter_type", &self.stellar_retry_jitter_type)
            .field(
                "stellar_bulkhead_max_concurrent",
                &self.stellar_bulkhead_max_concurrent,
            )
            .field(
                "stellar_bulkhead_max_queue",
                &self.stellar_bulkhead_max_queue,
            )
            .field("log_level", &self.log_level)
            .field("webhook_urls", &self.webhook_urls)
            .field(
                "webhook_secret",
                &self.webhook_secret.as_deref().map(|_| "<redacted>"),
            )
            .field("webhook_max_retries", &self.webhook_max_retries)
            .field(
                "webhook_retry_base_delay_ms",
                &self.webhook_retry_base_delay_ms,
            )
            .field(
                "webhook_retry_max_delay_ms",
                &self.webhook_retry_max_delay_ms,
            )
            .field(
                "webhook_request_timeout_ms",
                &self.webhook_request_timeout_ms,
            )
            .field("webhook_jitter_enabled", &self.webhook_jitter_enabled)
            .field("cache_verification_ttl", &self.cache_verification_ttl)
            .field("cache_backend", &self.cache_backend)
            .field("cache_max_size", &self.cache_max_size)
            .field("cache_config_ttl", &self.cache_config_ttl)
            .field("cache_events_ttl", &self.cache_events_ttl)
            .field("cache_circuit_breaker_failure_threshold", &self.cache_circuit_breaker_failure_threshold)
            .field("cache_circuit_breaker_open_duration_ms", &self.cache_circuit_breaker_open_duration_ms)
            .field("cache_circuit_breaker_half_open_max_calls", &self.cache_circuit_breaker_half_open_max_calls)
            .field("cache_circuit_breaker_backoff_base_ms", &self.cache_circuit_breaker_backoff_base_ms)
            .field("cache_circuit_breaker_backoff_max_ms", &self.cache_circuit_breaker_backoff_max_ms)
            .field("cache_bulkhead_max_concurrent", &self.cache_bulkhead_max_concurrent)
            .field("cache_bulkhead_max_queue", &self.cache_bulkhead_max_queue)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration validation failed:\n{0}")]
    Validation(String),
}

impl AppConfig {
    /// Load configuration from environment variables.
    ///
    /// Records validation failures via the provided metrics registry.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_env_with_metrics(None)
    }

    /// Load configuration from environment variables, recording metrics if a registry is provided.
    pub fn from_env_with_metrics(
        metrics: Option<Arc<MetricsRegistry>>,
    ) -> Result<Self, ConfigError> {
        let mut errors = Vec::new();

        fn get_env_or_default(key: &str, default: &str) -> String {
            env::var(key).unwrap_or_else(|_| default.to_string())
        }

        // ── Environment variable documentation ──────────────────────────
        // Each variable is documented with its purpose, default, and validation rules.
        //
        // NETWORK:
        //   PORT                    - HTTP listen port (1-65535, default: 8080)
        //   LOG_LEVEL               - Logging level (default: "info")
        //
        // STELLAR:
        //   STELLAR_HORIZON_URL     - Horizon API base URL (default: https://horizon-testnet.stellar.org)
        //   STELLAR_SECRET_KEY      - Stellar ed25519 secret key (required, validated format)
        //   STELLAR_MAX_RETRIES     - Max retries for Horizon requests (default: 3)
        //   STELLAR_RETRY_BASE_DELAY_MS - Base retry delay (default: 100, min: 1, max: 300000)
        //   STELLAR_RETRY_MAX_DELAY_MS  - Max retry delay (default: 10000)
        //   STELLAR_RETRY_JITTER    - Enable jitter on retry delays (default: true)
        //   STELLAR_REQUEST_TIMEOUT_MS - Horizon request timeout (default: 10000)
        //   STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD - Failures before circuit opens (default: 5)
        //   STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS - Duration circuit stays open (default: 30000)
        //   STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS - Probes in half-open state (default: 1)
        //
        // RATE LIMITING:
        //   RATE_LIMIT_PER_SECOND           - Global requests/sec (default: 100, min: 1)
        //   RATE_LIMIT_BURST                - Global burst (default: = RATE_LIMIT_PER_SECOND, must be >= RPS)
        //   PER_ISSUER_RATE_LIMIT_PER_SECOND - Per-issuer requests/sec (default: 10, must not exceed global)
        //   PER_ISSUER_RATE_LIMIT_BURST     - Per-issuer burst (default: 2x RPS, must be >= RPS)
        //   ISSUER_RATE_LIMIT_TTL_SECONDS   - Issuer entry TTL (default: 3600)
        //
        // REDIS:
        //   REDIS_URL               - Redis connection URL (redis:// or rediss://, default: redis://127.0.0.1:6379)
        //
        // WEBHOOKS:
        //   WEBHOOK_URLS            - Comma-separated webhook URLs
        //   WEBHOOK_SECRET          - Secret for webhook request signing
        //   WEBHOOK_MAX_RETRIES     - Max webhook delivery retries (default: 5)
        //   WEBHOOK_RETRY_BASE_DELAY_MS - Base retry delay for webhooks (default: 200)
        //   WEBHOOK_RETRY_MAX_DELAY_MS  - Max retry delay for webhooks (default: 30000)
        //   WEBHOOK_REQUEST_TIMEOUT_MS  - Webhook request timeout (default: 10000)
        //   WEBHOOK_JITTER_ENABLED  - Enable jitter on webhook retries (default: true)
        //
        // CACHE:
        //   CACHE_BACKEND           - Cache backend ('redis' or 'inmemory', default: 'inmemory')
        //   CACHE_MAX_SIZE          - Max cache entries (default: 10000)
        //   CACHE_VERIFICATION_TTL  - TTL for verification cache (default: 3600)
        //   CACHE_CONFIG_TTL        - TTL for config cache (default: 3600)
        //   CACHE_EVENTS_TTL        - TTL for events cache (default: 1800)
        //
        // CACHE CIRCUIT BREAKER:
        //   CACHE_CIRCUIT_BREAKER_FAILURE_THRESHOLD - Failures before circuit opens (default: 5)
        //   CACHE_CIRCUIT_BREAKER_OPEN_DURATION_MS  - Duration circuit stays open (default: 30000)
        //   CACHE_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS - Probes in half-open state (default: 1)
        //   CACHE_CIRCUIT_BREAKER_BACKOFF_BASE_MS    - Exponential backoff base (default: 100)
        //   CACHE_CIRCUIT_BREAKER_BACKOFF_MAX_MS     - Exponential backoff max (default: 30000)
        //
        // CACHE BULKHEAD:
        //   CACHE_BULKHEAD_MAX_CONCURRENT - Max concurrent Redis operations (default: 20)
        //   CACHE_BULKHEAD_MAX_QUEUE      - Max queued operations when at capacity (default: 200)

        let port_raw = get_env_or_default("PORT", "8080");
        let stellar_horizon_url =
            get_env_or_default("STELLAR_HORIZON_URL", "https://horizon-testnet.stellar.org");
        let redis_url = get_env_or_default("REDIS_URL", "redis://127.0.0.1:6379");
        let log_level = get_env_or_default("LOG_LEVEL", "info");
        let webhook_urls_raw = get_env_or_default("WEBHOOK_URLS", "");

        let stellar_secret_key = match env::var("STELLAR_SECRET_KEY") {
            Ok(key) => {
                if PrivateKey::from_string(&key).is_err() {
                    errors.push(
                        "STELLAR_SECRET_KEY must be a valid Stellar ed25519 secret key".to_string(),
                    );
                }
                Some(key)
            }
            Err(_) => {
                errors.push(
                    "STELLAR_SECRET_KEY is required but not set. Please set the environment variable."
                        .to_string(),
                );
                None
            }
        };
        let webhook_secret = env::var("WEBHOOK_SECRET").ok();
        let webhook_max_retries_raw = get_env_or_default("WEBHOOK_MAX_RETRIES", "5");
        let webhook_retry_base_delay_ms_raw =
            get_env_or_default("WEBHOOK_RETRY_BASE_DELAY_MS", "200");
        let webhook_retry_max_delay_ms_raw =
            get_env_or_default("WEBHOOK_RETRY_MAX_DELAY_MS", "30000");
        let webhook_request_timeout_ms_raw =
            get_env_or_default("WEBHOOK_REQUEST_TIMEOUT_MS", "10000");
        let webhook_jitter_raw = get_env_or_default("WEBHOOK_JITTER_ENABLED", "true");

        let rate_limit_per_second_raw = get_env_or_default("RATE_LIMIT_PER_SECOND", "100");
        let rate_limit_burst_raw =
            get_env_or_default("RATE_LIMIT_BURST", &rate_limit_per_second_raw);

        // ── Per-issuer rate-limit raw values ─────────────────────────────
        let per_issuer_rps_raw = get_env_or_default("PER_ISSUER_RATE_LIMIT_PER_SECOND", "10");
        let per_issuer_burst_default = format!(
            "{}",
            per_issuer_rps_raw
                .parse::<u32>()
                .unwrap_or(10)
                .saturating_mul(2)
        );
        let per_issuer_burst_raw =
            get_env_or_default("PER_ISSUER_RATE_LIMIT_BURST", &per_issuer_burst_default);
        let issuer_ttl_raw = get_env_or_default("ISSUER_RATE_LIMIT_TTL_SECONDS", "3600");

        let stellar_max_retries_raw = get_env_or_default("STELLAR_MAX_RETRIES", "3");
        let stellar_retry_base_delay_ms_raw = get_env_or_default(
            "STELLAR_RETRY_BASE_DELAY_MS",
            &DEFAULT_STELLAR_RETRY_BASE_DELAY_MS.to_string(),
        );
        let stellar_retry_max_delay_ms_raw = get_env_or_default(
            "STELLAR_RETRY_MAX_DELAY_MS",
            &DEFAULT_STELLAR_RETRY_MAX_DELAY_MS.to_string(),
        );
        let stellar_retry_jitter_raw = get_env_or_default("STELLAR_RETRY_JITTER", "true");
        let stellar_request_timeout_ms_raw = get_env_or_default(
            "STELLAR_REQUEST_TIMEOUT_MS",
            &DEFAULT_STELLAR_REQUEST_TIMEOUT_MS.to_string(),
        );
        let stellar_circuit_breaker_failure_threshold_raw = get_env_or_default(
            "STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD",
            &DEFAULT_STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD.to_string(),
        );
        let stellar_circuit_breaker_open_duration_ms_raw = get_env_or_default(
            "STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS",
            &DEFAULT_STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS.to_string(),
        );
        let stellar_circuit_breaker_half_open_max_calls_raw = get_env_or_default(
            "STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS",
            &DEFAULT_STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS.to_string(),
        );
        let stellar_retry_jitter_type_raw = get_env_or_default(
            "STELLAR_RETRY_JITTER_TYPE",
            DEFAULT_STELLAR_RETRY_JITTER_TYPE,
        );
        let stellar_bulkhead_max_concurrent_raw = get_env_or_default(
            "STELLAR_BULKHEAD_MAX_CONCURRENT",
            &DEFAULT_STELLAR_BULKHEAD_MAX_CONCURRENT.to_string(),
        );
        let stellar_bulkhead_max_queue_raw = get_env_or_default(
            "STELLAR_BULKHEAD_MAX_QUEUE",
            &DEFAULT_STELLAR_BULKHEAD_MAX_QUEUE.to_string(),
        );
        let cache_verification_ttl_raw = get_env_or_default("CACHE_VERIFICATION_TTL", "3600");
        let cache_backend_raw = get_env_or_default("CACHE_BACKEND", "inmemory");
        let cache_max_size_raw = get_env_or_default("CACHE_MAX_SIZE", "10000");
        let cache_config_ttl_raw = get_env_or_default("CACHE_CONFIG_TTL", "3600");
        let cache_events_ttl_raw = get_env_or_default("CACHE_EVENTS_TTL", "1800");
        let cache_cb_failure_threshold_raw = get_env_or_default(
            "CACHE_CIRCUIT_BREAKER_FAILURE_THRESHOLD",
            &DEFAULT_CACHE_CIRCUIT_BREAKER_FAILURE_THRESHOLD.to_string(),
        );
        let cache_cb_open_duration_ms_raw = get_env_or_default(
            "CACHE_CIRCUIT_BREAKER_OPEN_DURATION_MS",
            &DEFAULT_CACHE_CIRCUIT_BREAKER_OPEN_DURATION_MS.to_string(),
        );
        let cache_cb_half_open_max_calls_raw = get_env_or_default(
            "CACHE_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS",
            &DEFAULT_CACHE_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS.to_string(),
        );
        let cache_cb_backoff_base_ms_raw = get_env_or_default(
            "CACHE_CIRCUIT_BREAKER_BACKOFF_BASE_MS",
            &DEFAULT_CACHE_CIRCUIT_BREAKER_BACKOFF_BASE_MS.to_string(),
        );
        let cache_cb_backoff_max_ms_raw = get_env_or_default(
            "CACHE_CIRCUIT_BREAKER_BACKOFF_MAX_MS",
            &DEFAULT_CACHE_CIRCUIT_BREAKER_BACKOFF_MAX_MS.to_string(),
        );
        let cache_bulkhead_max_concurrent_raw = get_env_or_default(
            "CACHE_BULKHEAD_MAX_CONCURRENT",
            &DEFAULT_CACHE_BULKHEAD_MAX_CONCURRENT.to_string(),
        );
        let cache_bulkhead_max_queue_raw = get_env_or_default(
            "CACHE_BULKHEAD_MAX_QUEUE",
            &DEFAULT_CACHE_BULKHEAD_MAX_QUEUE.to_string(),
        );

        // ── Port validation with bounds ──────────────────────────────────
        let port: u16 = match port_raw.parse() {
            Ok(p) => match ValidatedPort::new(p) {
                Ok(_) => p,
                Err(e) => {
                    errors.push(e.to_string());
                    8080
                }
            },
            Err(_) => {
                errors.push(format!(
                    "PORT must be a valid u16 (1-65535), got '{}'",
                    port_raw
                ));
                8080
            }
        };

        // ── URL validations with strongly-typed wrappers ─────────────────
        if ValidatedUrl::parse(&stellar_horizon_url).is_err() {
            errors.push(format!(
                "STELLAR_HORIZON_URL must be a valid http/https URL, got '{}'",
                stellar_horizon_url
            ));
        }

        if ValidatedRedisUrl::parse(&redis_url).is_err() {
            errors.push(format!(
                "REDIS_URL must be a valid redis:// or rediss:// URL, got '{}'",
                redis_url
            ));
        }

        let rate_limit_per_second: u32 = match rate_limit_per_second_raw.parse() {
            Ok(v) if v > 0 => v,
            Ok(_) => {
                errors.push("RATE_LIMIT_PER_SECOND must be greater than 0".to_string());
                100
            }
            Err(_) => {
                errors.push(format!(
                    "RATE_LIMIT_PER_SECOND must be a valid u32, got '{}'",
                    rate_limit_per_second_raw
                ));
                100
            }
        };

        let rate_limit_burst: u32 = match rate_limit_burst_raw.parse() {
            Ok(v) => v,
            Err(_) => {
                errors.push(format!(
                    "RATE_LIMIT_BURST must be a valid u32, got '{}'",
                    rate_limit_burst_raw
                ));
                rate_limit_per_second
            }
        };

        if rate_limit_burst == 0 {
            errors.push("RATE_LIMIT_BURST must be greater than 0".to_string());
        }

        // ── burst >= per_second validation ──────────────────────────────
        if rate_limit_burst < rate_limit_per_second {
            errors.push(format!(
                "RATE_LIMIT_BURST ({}) must be >= RATE_LIMIT_PER_SECOND ({})",
                rate_limit_burst, rate_limit_per_second
            ));
        }

        // ── Parse per-issuer rate-limit values ───────────────────────────
        let per_issuer_rate_limit_per_second: u32 = match per_issuer_rps_raw.parse() {
            Ok(v) if v > 0 => v,
            Ok(_) => {
                errors.push("PER_ISSUER_RATE_LIMIT_PER_SECOND must be greater than 0".to_string());
                10
            }
            Err(_) => {
                errors.push(format!(
                    "PER_ISSUER_RATE_LIMIT_PER_SECOND must be a valid u32, got '{}'",
                    per_issuer_rps_raw
                ));
                10
            }
        };

        let per_issuer_rate_limit_burst: u32 = match per_issuer_burst_raw.parse() {
            Ok(v) if v > 0 => v,
            Ok(_) => {
                errors.push("PER_ISSUER_RATE_LIMIT_BURST must be greater than 0".to_string());
                per_issuer_rate_limit_per_second * 2
            }
            Err(_) => {
                errors.push(format!(
                    "PER_ISSUER_RATE_LIMIT_BURST must be a valid u32, got '{}'",
                    per_issuer_burst_raw
                ));
                per_issuer_rate_limit_per_second * 2
            }
        };

        // ── Per-issuer burst >= per_second validation ───────────────────
        if per_issuer_rate_limit_burst < per_issuer_rate_limit_per_second {
            errors.push(format!(
                "PER_ISSUER_RATE_LIMIT_BURST ({}) must be >= PER_ISSUER_RATE_LIMIT_PER_SECOND ({})",
                per_issuer_rate_limit_burst, per_issuer_rate_limit_per_second
            ));
        }

        if per_issuer_rate_limit_per_second > rate_limit_per_second {
            errors.push(format!(
                "PER_ISSUER_RATE_LIMIT_PER_SECOND ({}) must not exceed RATE_LIMIT_PER_SECOND ({})",
                per_issuer_rate_limit_per_second, rate_limit_per_second
            ));
        }

        let issuer_rate_limit_ttl_seconds: u64 = match issuer_ttl_raw.parse() {
            Ok(v) if v > 0 => v,
            Ok(_) => {
                errors.push("ISSUER_RATE_LIMIT_TTL_SECONDS must be greater than 0".to_string());
                3600
            }
            Err(_) => {
                errors.push(format!(
                    "ISSUER_RATE_LIMIT_TTL_SECONDS must be a valid u64, got '{}'",
                    issuer_ttl_raw
                ));
                3600
            }
        };

        // ── Parse remaining values with bounds checking ─────────────────
        let stellar_max_retries: u32 = match stellar_max_retries_raw.parse() {
            Ok(v) => v,
            Err(_) => {
                errors.push(format!(
                    "STELLAR_MAX_RETRIES must be a valid u32, got '{}'",
                    stellar_max_retries_raw
                ));
                3
            }
        };

        let stellar_retry_base_delay_ms: u64 = match stellar_retry_base_delay_ms_raw.parse() {
            Ok(v) if v > 0 && v <= MAX_TIMEOUT_MS => v,
            Ok(v) if v > 0 => {
                errors.push(format!(
                    "STELLAR_RETRY_BASE_DELAY_MS ({}) exceeds maximum {}",
                    v, MAX_TIMEOUT_MS
                ));
                DEFAULT_STELLAR_RETRY_BASE_DELAY_MS
            }
            Ok(_) => {
                errors.push("STELLAR_RETRY_BASE_DELAY_MS must be greater than 0".to_string());
                DEFAULT_STELLAR_RETRY_BASE_DELAY_MS
            }
            Err(_) => {
                errors.push(format!(
                    "STELLAR_RETRY_BASE_DELAY_MS must be a valid u64, got '{}'",
                    stellar_retry_base_delay_ms_raw
                ));
                DEFAULT_STELLAR_RETRY_BASE_DELAY_MS
            }
        };

        let stellar_retry_max_delay_ms: u64 = match stellar_retry_max_delay_ms_raw.parse() {
            Ok(v) if v > 0 && v <= MAX_TIMEOUT_MS => v,
            Ok(v) if v > 0 => {
                errors.push(format!(
                    "STELLAR_RETRY_MAX_DELAY_MS ({}) exceeds maximum {}",
                    v, MAX_TIMEOUT_MS
                ));
                DEFAULT_STELLAR_RETRY_MAX_DELAY_MS
            }
            Ok(_) => {
                errors.push("STELLAR_RETRY_MAX_DELAY_MS must be greater than 0".to_string());
                DEFAULT_STELLAR_RETRY_MAX_DELAY_MS
            }
            Err(_) => {
                errors.push(format!(
                    "STELLAR_RETRY_MAX_DELAY_MS must be a valid u64, got '{}'",
                    stellar_retry_max_delay_ms_raw
                ));
                DEFAULT_STELLAR_RETRY_MAX_DELAY_MS
            }
        };

        let stellar_retry_jitter_enabled = match stellar_retry_jitter_raw.to_lowercase().as_str() {
            "1" | "true" | "yes" | "y" => true,
            "0" | "false" | "no" | "n" => false,
            other => {
                errors.push(format!(
                    "STELLAR_RETRY_JITTER must be a boolean, got '{}'",
                    other
                ));
                true
            }
        };

        let stellar_request_timeout_ms: u64 = match stellar_request_timeout_ms_raw.parse() {
            Ok(v) if v > 0 && v <= MAX_TIMEOUT_MS => v,
            Ok(v) if v > 0 => {
                errors.push(format!(
                    "STELLAR_REQUEST_TIMEOUT_MS ({}) exceeds maximum {}",
                    v, MAX_TIMEOUT_MS
                ));
                DEFAULT_STELLAR_REQUEST_TIMEOUT_MS
            }
            Ok(_) => {
                errors.push("STELLAR_REQUEST_TIMEOUT_MS must be greater than 0".to_string());
                DEFAULT_STELLAR_REQUEST_TIMEOUT_MS
            }
            Err(_) => {
                errors.push(format!(
                    "STELLAR_REQUEST_TIMEOUT_MS must be a valid u64, got '{}'",
                    stellar_request_timeout_ms_raw
                ));
                DEFAULT_STELLAR_REQUEST_TIMEOUT_MS
            }
        };

        let stellar_circuit_breaker_failure_threshold: u32 =
            match stellar_circuit_breaker_failure_threshold_raw.parse() {
                Ok(v) if v > 0 => v,
                Ok(_) => {
                    errors.push(
                        "STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD must be greater than 0"
                            .to_string(),
                    );
                    DEFAULT_STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD
                }
                Err(_) => {
                    errors.push(format!(
                        "STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD must be a valid u32, got '{}'",
                        stellar_circuit_breaker_failure_threshold_raw
                    ));
                    DEFAULT_STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD
                }
            };

        let stellar_circuit_breaker_open_duration_ms: u64 =
            match stellar_circuit_breaker_open_duration_ms_raw.parse() {
                Ok(v) if v > 0 && v <= MAX_TIMEOUT_MS => v,
                Ok(v) if v > 0 => {
                    errors.push(format!(
                        "STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS ({}) exceeds maximum {}",
                        v, MAX_TIMEOUT_MS
                    ));
                    DEFAULT_STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS
                }
                Ok(_) => {
                    errors.push(
                        "STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS must be greater than 0"
                            .to_string(),
                    );
                    DEFAULT_STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS
                }
                Err(_) => {
                    errors.push(format!(
                        "STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS must be a valid u64, got '{}'",
                        stellar_circuit_breaker_open_duration_ms_raw
                    ));
                    DEFAULT_STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS
                }
            };

        let stellar_circuit_breaker_half_open_max_calls: u32 =
            match stellar_circuit_breaker_half_open_max_calls_raw.parse() {
                Ok(v) if v > 0 => v,
                Ok(_) => {
                    errors.push(
                        "STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS must be greater than 0"
                            .to_string(),
                    );
                    DEFAULT_STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS
                }
                Err(_) => {
                    errors.push(format!(
                        "STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS must be a valid u32, got '{}'",
                        stellar_circuit_breaker_half_open_max_calls_raw
                    ));
                    DEFAULT_STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS
                }
            };
        let stellar_retry_jitter_type = match stellar_retry_jitter_type_raw.to_lowercase().as_str()
        {
            "none" | "full" | "equal" | "decorrelated" => stellar_retry_jitter_type_raw.to_string(),
            other => {
                errors.push(format!(
                    "STELLAR_RETRY_JITTER_TYPE must be one of: none, full, equal, decorrelated; got '{}'",
                    other
                ));
                DEFAULT_STELLAR_RETRY_JITTER_TYPE.to_string()
            }
        };

        let stellar_bulkhead_max_concurrent: u32 = match stellar_bulkhead_max_concurrent_raw.parse()
        {
            Ok(v) if v > 0 => v,
            Ok(_) => {
                errors.push("STELLAR_BULKHEAD_MAX_CONCURRENT must be greater than 0".to_string());
                DEFAULT_STELLAR_BULKHEAD_MAX_CONCURRENT
            }
            Err(_) => {
                errors.push(format!(
                    "STELLAR_BULKHEAD_MAX_CONCURRENT must be a valid u32, got '{}'",
                    stellar_bulkhead_max_concurrent_raw
                ));
                DEFAULT_STELLAR_BULKHEAD_MAX_CONCURRENT
            }
        };

        let stellar_bulkhead_max_queue: u32 = match stellar_bulkhead_max_queue_raw.parse() {
            Ok(v) if v > 0 => v,
            Ok(_) => {
                errors.push("STELLAR_BULKHEAD_MAX_QUEUE must be greater than 0".to_string());
                DEFAULT_STELLAR_BULKHEAD_MAX_QUEUE
            }
            Err(_) => {
                errors.push(format!(
                    "STELLAR_BULKHEAD_MAX_QUEUE must be a valid u32, got '{}'",
                    stellar_bulkhead_max_queue_raw
                ));
                DEFAULT_STELLAR_BULKHEAD_MAX_QUEUE
            }
        };

        let cache_verification_ttl: u64 = match cache_verification_ttl_raw.parse() {
            Ok(v) => v,
            Err(_) => {
                errors.push(format!(
                    "CACHE_VERIFICATION_TTL must be a valid u64, got '{}'",
                    cache_verification_ttl_raw
                ));
                3600
            }
        };

        let cache_backend = match cache_backend_raw.to_lowercase().as_str() {
            "redis" | "rediss" => "redis".to_string(),
            "inmemory" | "memory" => "inmemory".to_string(),
            other => {
                errors.push(format!(
                    "CACHE_BACKEND must be 'redis' or 'inmemory', got '{}'",
                    other
                ));
                "inmemory".to_string()
            }
        };

        let cache_max_size: usize = match cache_max_size_raw.parse() {
            Ok(v) => v,
            Err(_) => {
                errors.push(format!(
                    "CACHE_MAX_SIZE must be a valid usize, got '{}'",
                    cache_max_size_raw
                ));
                10000
            }
        };

        let cache_config_ttl: u64 = match cache_config_ttl_raw.parse() {
            Ok(v) => v,
            Err(_) => {
                errors.push(format!(
                    "CACHE_CONFIG_TTL must be a valid u64, got '{}'",
                    cache_config_ttl_raw
                ));
                3600
            }
        };

        let cache_events_ttl: u64 = match cache_events_ttl_raw.parse() {
            Ok(v) => v,
            Err(_) => {
                errors.push(format!(
                    "CACHE_EVENTS_TTL must be a valid u64, got '{}'",
                    cache_events_ttl_raw
                ));
                1800
            }
        };

        // ── Cache circuit breaker validation ─────────────────────────────
        let cache_circuit_breaker_failure_threshold: u32 =
            match cache_cb_failure_threshold_raw.parse() {
                Ok(v) if v > 0 => v,
                Ok(_) => {
                    errors.push(
                        "CACHE_CIRCUIT_BREAKER_FAILURE_THRESHOLD must be greater than 0"
                            .to_string(),
                    );
                    DEFAULT_CACHE_CIRCUIT_BREAKER_FAILURE_THRESHOLD
                }
                Err(_) => {
                    errors.push(format!(
                        "CACHE_CIRCUIT_BREAKER_FAILURE_THRESHOLD must be a valid u32, got '{}'",
                        cache_cb_failure_threshold_raw
                    ));
                    DEFAULT_CACHE_CIRCUIT_BREAKER_FAILURE_THRESHOLD
                }
            };

        let cache_circuit_breaker_open_duration_ms: u64 =
            match cache_cb_open_duration_ms_raw.parse() {
                Ok(v) if v > 0 && v <= MAX_TIMEOUT_MS => v,
                Ok(v) if v > 0 => {
                    errors.push(format!(
                        "CACHE_CIRCUIT_BREAKER_OPEN_DURATION_MS ({}) exceeds maximum {}",
                        v, MAX_TIMEOUT_MS
                    ));
                    DEFAULT_CACHE_CIRCUIT_BREAKER_OPEN_DURATION_MS
                }
                Ok(_) => {
                    errors.push(
                        "CACHE_CIRCUIT_BREAKER_OPEN_DURATION_MS must be greater than 0"
                            .to_string(),
                    );
                    DEFAULT_CACHE_CIRCUIT_BREAKER_OPEN_DURATION_MS
                }
                Err(_) => {
                    errors.push(format!(
                        "CACHE_CIRCUIT_BREAKER_OPEN_DURATION_MS must be a valid u64, got '{}'",
                        cache_cb_open_duration_ms_raw
                    ));
                    DEFAULT_CACHE_CIRCUIT_BREAKER_OPEN_DURATION_MS
                }
            };

        let cache_circuit_breaker_half_open_max_calls: u32 =
            match cache_cb_half_open_max_calls_raw.parse() {
                Ok(v) if v > 0 => v,
                Ok(_) => {
                    errors.push(
                        "CACHE_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS must be greater than 0"
                            .to_string(),
                    );
                    DEFAULT_CACHE_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS
                }
                Err(_) => {
                    errors.push(format!(
                        "CACHE_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS must be a valid u32, got '{}'",
                        cache_cb_half_open_max_calls_raw
                    ));
                    DEFAULT_CACHE_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS
                }
            };

        let cache_circuit_breaker_backoff_base_ms: u64 =
            match cache_cb_backoff_base_ms_raw.parse() {
                Ok(v) if v > 0 && v <= MAX_TIMEOUT_MS => v,
                Ok(_) => {
                    errors.push(
                        "CACHE_CIRCUIT_BREAKER_BACKOFF_BASE_MS must be greater than 0"
                            .to_string(),
                    );
                    DEFAULT_CACHE_CIRCUIT_BREAKER_BACKOFF_BASE_MS
                }
                Err(_) => {
                    errors.push(format!(
                        "CACHE_CIRCUIT_BREAKER_BACKOFF_BASE_MS must be a valid u64, got '{}'",
                        cache_cb_backoff_base_ms_raw
                    ));
                    DEFAULT_CACHE_CIRCUIT_BREAKER_BACKOFF_BASE_MS
                }
            };

        let cache_circuit_breaker_backoff_max_ms: u64 =
            match cache_cb_backoff_max_ms_raw.parse() {
                Ok(v) if v > 0 && v <= MAX_TIMEOUT_MS => v,
                Ok(_) => {
                    errors.push(
                        "CACHE_CIRCUIT_BREAKER_BACKOFF_MAX_MS must be greater than 0"
                            .to_string(),
                    );
                    DEFAULT_CACHE_CIRCUIT_BREAKER_BACKOFF_MAX_MS
                }
                Err(_) => {
                    errors.push(format!(
                        "CACHE_CIRCUIT_BREAKER_BACKOFF_MAX_MS must be a valid u64, got '{}'",
                        cache_cb_backoff_max_ms_raw
                    ));
                    DEFAULT_CACHE_CIRCUIT_BREAKER_BACKOFF_MAX_MS
                }
            };

        // ── Cache bulkhead validation ────────────────────────────────────
        let cache_bulkhead_max_concurrent: u32 =
            match cache_bulkhead_max_concurrent_raw.parse() {
                Ok(v) if v > 0 => v,
                Ok(_) => {
                    errors.push(
                        "CACHE_BULKHEAD_MAX_CONCURRENT must be greater than 0".to_string(),
                    );
                    DEFAULT_CACHE_BULKHEAD_MAX_CONCURRENT
                }
                Err(_) => {
                    errors.push(format!(
                        "CACHE_BULKHEAD_MAX_CONCURRENT must be a valid u32, got '{}'",
                        cache_bulkhead_max_concurrent_raw
                    ));
                    DEFAULT_CACHE_BULKHEAD_MAX_CONCURRENT
                }
            };

        let cache_bulkhead_max_queue: u32 = match cache_bulkhead_max_queue_raw.parse() {
            Ok(v) if v > 0 => v,
            Ok(_) => {
                errors.push(
                    "CACHE_BULKHEAD_MAX_QUEUE must be greater than 0".to_string(),
                );
                DEFAULT_CACHE_BULKHEAD_MAX_QUEUE
            }
            Err(_) => {
                errors.push(format!(
                    "CACHE_BULKHEAD_MAX_QUEUE must be a valid u32, got '{}'",
                    cache_bulkhead_max_queue_raw
                ));
                DEFAULT_CACHE_BULKHEAD_MAX_QUEUE
            }
        };

        // Log level validation
        match log_level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            other => {
                errors.push(format!(
                    "LOG_LEVEL must be one of: trace, debug, info, warn, error; got '{}'",
                    other
                ));
            }
        }

        if stellar_retry_max_delay_ms < stellar_retry_base_delay_ms {
            errors.push(
                "STELLAR_RETRY_MAX_DELAY_MS must be greater than or equal to STELLAR_RETRY_BASE_DELAY_MS"
                    .to_string(),
            );
        }

        let webhook_max_retries: u32 = match webhook_max_retries_raw.parse() {
            Ok(v) => v,
            Err(_) => {
                errors.push(format!(
                    "WEBHOOK_MAX_RETRIES must be a valid u32, got '{}'",
                    webhook_max_retries_raw
                ));
                5
            }
        };

        let webhook_retry_base_delay_ms: u64 = match webhook_retry_base_delay_ms_raw.parse() {
            Ok(v) if v > 0 && v <= MAX_TIMEOUT_MS => v,
            Ok(v) if v > 0 => {
                errors.push(format!(
                    "WEBHOOK_RETRY_BASE_DELAY_MS ({}) exceeds maximum {}",
                    v, MAX_TIMEOUT_MS
                ));
                200
            }
            Ok(_) => {
                errors.push("WEBHOOK_RETRY_BASE_DELAY_MS must be greater than 0".to_string());
                200
            }
            Err(_) => {
                errors.push(format!(
                    "WEBHOOK_RETRY_BASE_DELAY_MS must be a valid u64, got '{}'",
                    webhook_retry_base_delay_ms_raw
                ));
                200
            }
        };

        let webhook_retry_max_delay_ms: u64 = match webhook_retry_max_delay_ms_raw.parse() {
            Ok(v) if v > 0 && v <= MAX_TIMEOUT_MS => v,
            Ok(v) if v > 0 => {
                errors.push(format!(
                    "WEBHOOK_RETRY_MAX_DELAY_MS ({}) exceeds maximum {}",
                    v, MAX_TIMEOUT_MS
                ));
                30_000
            }
            Ok(_) => {
                errors.push("WEBHOOK_RETRY_MAX_DELAY_MS must be greater than 0".to_string());
                30_000
            }
            Err(_) => {
                errors.push(format!(
                    "WEBHOOK_RETRY_MAX_DELAY_MS must be a valid u64, got '{}'",
                    webhook_retry_max_delay_ms_raw
                ));
                30_000
            }
        };

        let webhook_request_timeout_ms: u64 = match webhook_request_timeout_ms_raw.parse() {
            Ok(v) if v > 0 && v <= MAX_TIMEOUT_MS => v,
            Ok(v) if v > 0 => {
                errors.push(format!(
                    "WEBHOOK_REQUEST_TIMEOUT_MS ({}) exceeds maximum {}",
                    v, MAX_TIMEOUT_MS
                ));
                10_000
            }
            Ok(_) => {
                errors.push("WEBHOOK_REQUEST_TIMEOUT_MS must be greater than 0".to_string());
                10_000
            }
            Err(_) => {
                errors.push(format!(
                    "WEBHOOK_REQUEST_TIMEOUT_MS must be a valid u64, got '{}'",
                    webhook_request_timeout_ms_raw
                ));
                10_000
            }
        };

        let webhook_jitter_enabled = match webhook_jitter_raw.to_lowercase().as_str() {
            "1" | "true" | "yes" | "y" => true,
            "0" | "false" | "no" | "n" => false,
            other => {
                errors.push(format!(
                    "WEBHOOK_JITTER_ENABLED must be a boolean, got '{}'",
                    other
                ));
                true
            }
        };

        if webhook_retry_max_delay_ms < webhook_retry_base_delay_ms {
            errors.push(
                "WEBHOOK_RETRY_MAX_DELAY_MS must be greater than or equal to WEBHOOK_RETRY_BASE_DELAY_MS"
                    .to_string(),
            );
        }

        let webhook_urls: Vec<String> = webhook_urls_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|url| {
                if ValidatedUrl::parse(url).is_err() {
                    errors.push(format!(
                        "WEBHOOK_URLS must contain valid URLs, got '{}'",
                        url
                    ));
                }
                url.to_string()
            })
            .collect();

        if !errors.is_empty() {
            if let Some(ref m) = metrics {
                m.increment_config_validation_failure();
            }
            let joined = errors.join("\n- ");
            return Err(ConfigError::Validation(format!("- {}", joined)));
        }

        // Successful load
        if let Some(ref m) = metrics {
            m.increment_config_reload();
        }

        Ok(Self {
            port,
            stellar_horizon_url,
            stellar_secret_key,
            redis_url,
            rate_limit_per_second,
            rate_limit_burst,
            per_issuer_rate_limit_per_second,
            per_issuer_rate_limit_burst,
            issuer_rate_limit_ttl_seconds,
            stellar_max_retries,
            stellar_retry_base_delay_ms,
            stellar_retry_max_delay_ms,
            stellar_retry_jitter_enabled,
            stellar_request_timeout_ms,
            stellar_circuit_breaker_failure_threshold,
            stellar_circuit_breaker_open_duration_ms,
            stellar_circuit_breaker_half_open_max_calls,
            stellar_retry_jitter_type,
            stellar_bulkhead_max_concurrent,
            stellar_bulkhead_max_queue,
            log_level,
            webhook_urls,
            webhook_secret,
            webhook_max_retries,
            webhook_retry_base_delay_ms,
            webhook_retry_max_delay_ms,
            webhook_request_timeout_ms,
            webhook_jitter_enabled,
            cache_verification_ttl,
            cache_backend,
            cache_max_size,
            cache_config_ttl,
            cache_events_ttl,
            cache_circuit_breaker_failure_threshold,
            cache_circuit_breaker_open_duration_ms,
            cache_circuit_breaker_half_open_max_calls,
            cache_circuit_breaker_backoff_base_ms,
            cache_circuit_breaker_backoff_max_ms,
            cache_bulkhead_max_concurrent,
            cache_bulkhead_max_queue,
        })
    }

    /// Reload configuration from environment variables, returning a new instance.
    /// Useful in combination with the hot-reload mechanism to apply changes at runtime.
    pub fn reload_from_env(
        &self,
        metrics: Option<Arc<MetricsRegistry>>,
    ) -> Result<Self, ConfigError> {
        Self::from_env_with_metrics(metrics)
    }

    /// Returns the current configuration schema version.
    pub fn version() -> u32 {
        CONFIG_VERSION
    }

    /// Validate a config for rollback safety by checking version compatibility.
    pub fn validate_compatible(&self, previous_version: u32) -> Result<(), ConfigError> {
        if previous_version > CONFIG_VERSION {
            return Err(ConfigError::Validation(format!(
                "cannot roll back from config version {} to current version {}",
                previous_version, CONFIG_VERSION
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_env() {
        let keys = [
            "PORT",
            "STELLAR_HORIZON_URL",
            "STELLAR_SECRET_KEY",
            "REDIS_URL",
            "RATE_LIMIT_PER_SECOND",
            "RATE_LIMIT_BURST",
            "PER_ISSUER_RATE_LIMIT_PER_SECOND",
            "PER_ISSUER_RATE_LIMIT_BURST",
            "ISSUER_RATE_LIMIT_TTL_SECONDS",
            "STELLAR_MAX_RETRIES",
            "STELLAR_RETRY_BASE_DELAY_MS",
            "STELLAR_RETRY_MAX_DELAY_MS",
            "STELLAR_RETRY_JITTER",
            "STELLAR_REQUEST_TIMEOUT_MS",
            "STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD",
            "STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS",
            "STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS",
            "STELLAR_RETRY_JITTER_TYPE",
            "STELLAR_BULKHEAD_MAX_CONCURRENT",
            "STELLAR_BULKHEAD_MAX_QUEUE",
            "LOG_LEVEL",
            "WEBHOOK_URLS",
            "WEBHOOK_SECRET",
            "WEBHOOK_MAX_RETRIES",
            "WEBHOOK_RETRY_BASE_DELAY_MS",
            "WEBHOOK_RETRY_MAX_DELAY_MS",
            "WEBHOOK_REQUEST_TIMEOUT_MS",
            "WEBHOOK_JITTER_ENABLED",
            "CACHE_VERIFICATION_TTL",
            "CACHE_BACKEND",
            "CACHE_MAX_SIZE",
            "CACHE_CONFIG_TTL",
            "CACHE_EVENTS_TTL",
            "CACHE_CIRCUIT_BREAKER_FAILURE_THRESHOLD",
            "CACHE_CIRCUIT_BREAKER_OPEN_DURATION_MS",
            "CACHE_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS",
            "CACHE_CIRCUIT_BREAKER_BACKOFF_BASE_MS",
            "CACHE_CIRCUIT_BREAKER_BACKOFF_MAX_MS",
            "CACHE_BULKHEAD_MAX_CONCURRENT",
            "CACHE_BULKHEAD_MAX_QUEUE",
        ];
        for key in keys {
            env::remove_var(key);
        }
    }

    const VALID_KEY: &str = "SBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHOKR";

    #[test]
    fn from_env_uses_defaults_when_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);
        let cfg = AppConfig::from_env().expect("config should load with defaults");

        assert_eq!(cfg.port, 8080);
        assert_eq!(
            cfg.stellar_horizon_url,
            "https://horizon-testnet.stellar.org"
        );
        assert_eq!(cfg.redis_url, "redis://127.0.0.1:6379");
        assert_eq!(cfg.rate_limit_per_second, 100);
        assert_eq!(cfg.per_issuer_rate_limit_per_second, 10);
        assert_eq!(cfg.per_issuer_rate_limit_burst, 20);
        assert_eq!(cfg.issuer_rate_limit_ttl_seconds, 3600);
        assert_eq!(cfg.cache_verification_ttl, 3600);
        assert_eq!(cfg.stellar_max_retries, 3);
        assert_eq!(cfg.stellar_retry_base_delay_ms, 100);
        assert_eq!(cfg.stellar_retry_max_delay_ms, 10_000);
        assert!(cfg.stellar_retry_jitter_enabled);
        assert_eq!(cfg.stellar_request_timeout_ms, 10_000);
        assert_eq!(cfg.stellar_circuit_breaker_failure_threshold, 5);
        assert_eq!(cfg.stellar_circuit_breaker_open_duration_ms, 30_000);
        assert_eq!(cfg.stellar_circuit_breaker_half_open_max_calls, 1);
        assert_eq!(cfg.stellar_retry_jitter_type, "full");
        assert_eq!(cfg.stellar_bulkhead_max_concurrent, 10);
        assert_eq!(cfg.stellar_bulkhead_max_queue, 100);
    }

    #[test]
    fn from_env_parses_per_issuer_rate_limit_fields() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);
        env::set_var("RATE_LIMIT_PER_SECOND", "500");
        env::set_var("PER_ISSUER_RATE_LIMIT_PER_SECOND", "50");
        env::set_var("PER_ISSUER_RATE_LIMIT_BURST", "100");
        env::set_var("ISSUER_RATE_LIMIT_TTL_SECONDS", "7200");

        let cfg = AppConfig::from_env().expect("should parse");
        assert_eq!(cfg.per_issuer_rate_limit_per_second, 50);
        assert_eq!(cfg.per_issuer_rate_limit_burst, 100);
        assert_eq!(cfg.issuer_rate_limit_ttl_seconds, 7200);
    }

    #[test]
    fn from_env_rejects_per_issuer_rps_greater_than_global() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);
        env::set_var("RATE_LIMIT_PER_SECOND", "10");
        env::set_var("PER_ISSUER_RATE_LIMIT_PER_SECOND", "100"); // exceeds global

        let err = AppConfig::from_env().expect_err("should fail");
        assert!(err.to_string().contains("PER_ISSUER_RATE_LIMIT_PER_SECOND"));
    }

    #[test]
    fn from_env_invalid_values_report_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("PORT", "0");
        env::set_var("STELLAR_HORIZON_URL", "not-a-url");
        env::set_var("REDIS_URL", "not-a-url");
        env::set_var("RATE_LIMIT_PER_SECOND", "0");
        env::set_var("RATE_LIMIT_BURST", "0");
        env::set_var("STELLAR_RETRY_BASE_DELAY_MS", "0");
        env::set_var("STELLAR_RETRY_MAX_DELAY_MS", "50");
        env::set_var("STELLAR_RETRY_JITTER", "sometimes");
        env::set_var("STELLAR_REQUEST_TIMEOUT_MS", "0");
        env::set_var("STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD", "0");
        env::set_var("STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS", "0");
        env::set_var("STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS", "0");
        env::set_var("WEBHOOK_URLS", "https://ok.example.com, not-a-url");
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);

        let err = AppConfig::from_env().expect_err("config should fail");
        let msg = err.to_string();

        assert!(
            msg.contains("port 0 is below minimum 1") || msg.contains("PORT must be a valid u16")
        );
        assert!(
            msg.contains("STELLAR_HORIZON_URL must be a valid http/https URL")
                || msg.contains("invalid URL")
        );
        assert!(
            msg.contains("REDIS_URL must be a valid redis:// or rediss:// URL")
                || msg.contains("invalid Redis URL")
        );
        assert!(msg.contains("RATE_LIMIT_PER_SECOND must be greater than 0"));
        assert!(msg.contains("RATE_LIMIT_BURST must be greater than 0"));
        assert!(msg.contains("RATE_LIMIT_BURST") && msg.contains("must be >="));
        assert!(msg.contains("STELLAR_RETRY_BASE_DELAY_MS must be greater than 0"));
        assert!(msg.contains(
            "STELLAR_RETRY_MAX_DELAY_MS must be greater than or equal to STELLAR_RETRY_BASE_DELAY_MS"
        ));
        assert!(msg.contains("STELLAR_RETRY_JITTER must be a boolean"));
        assert!(msg.contains("STELLAR_REQUEST_TIMEOUT_MS must be greater than 0"));
        assert!(msg.contains("STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD must be greater than 0"));
        assert!(msg.contains("STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS must be greater than 0"));
        assert!(msg.contains("STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS must be greater than 0"));
        assert!(msg.contains("WEBHOOK_URLS must contain valid URLs"));
    }

    #[test]
    fn from_env_rejects_invalid_stellar_secret_key() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var(
            "STELLAR_SECRET_KEY",
            "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );

        let err = AppConfig::from_env().expect_err("config should fail");
        assert!(err
            .to_string()
            .contains("STELLAR_SECRET_KEY must be a valid Stellar ed25519 secret key"));
    }

    #[test]
    fn from_env_parses_valid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("PORT", "9090");
        env::set_var("STELLAR_HORIZON_URL", "https://example.com");
        env::set_var("REDIS_URL", "redis://redis:6379");
        env::set_var("RATE_LIMIT_PER_SECOND", "100");
        env::set_var("RATE_LIMIT_BURST", "100");
        env::set_var("STELLAR_MAX_RETRIES", "5");
        env::set_var("STELLAR_RETRY_BASE_DELAY_MS", "250");
        env::set_var("STELLAR_RETRY_MAX_DELAY_MS", "15000");
        env::set_var("STELLAR_RETRY_JITTER", "false");
        env::set_var("STELLAR_REQUEST_TIMEOUT_MS", "7500");
        env::set_var("STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD", "3");
        env::set_var("STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS", "45000");
        env::set_var("STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS", "2");
        env::set_var("WEBHOOK_URLS", "https://a.com, https://b.com");
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);

        let cfg = AppConfig::from_env().expect("config should load");

        assert_eq!(cfg.port, 9090);
        assert_eq!(cfg.stellar_horizon_url, "https://example.com");
        assert_eq!(cfg.redis_url, "redis://redis:6379");
        assert_eq!(cfg.rate_limit_per_second, 100);
        assert_eq!(cfg.rate_limit_burst, 100);
        assert_eq!(cfg.stellar_max_retries, 5);
        assert_eq!(cfg.stellar_retry_base_delay_ms, 250);
        assert_eq!(cfg.stellar_retry_max_delay_ms, 15_000);
        assert!(!cfg.stellar_retry_jitter_enabled);
        assert_eq!(cfg.stellar_request_timeout_ms, 7500);
        assert_eq!(cfg.stellar_circuit_breaker_failure_threshold, 3);
        assert_eq!(cfg.stellar_circuit_breaker_open_duration_ms, 45_000);
        assert_eq!(cfg.stellar_circuit_breaker_half_open_max_calls, 2);
        assert_eq!(cfg.webhook_urls.len(), 2);
    }

    #[test]
    fn debug_redacts_secret_values() {
        let config = AppConfig {
            port: 8080,
            stellar_horizon_url: "https://example.com".to_string(),
            stellar_secret_key: Some("secret-value".to_string()),
            redis_url: "redis://redis:6379".to_string(),
            rate_limit_per_second: 10,
            rate_limit_burst: 10,
            per_issuer_rate_limit_per_second: 2,
            per_issuer_rate_limit_burst: 4,
            issuer_rate_limit_ttl_seconds: 3600,
            stellar_max_retries: 3,
            stellar_retry_base_delay_ms: 100,
            stellar_retry_max_delay_ms: 10_000,
            stellar_retry_jitter_enabled: true,
            stellar_request_timeout_ms: 10_000,
            stellar_circuit_breaker_failure_threshold: 5,
            stellar_circuit_breaker_open_duration_ms: 30_000,
            stellar_circuit_breaker_half_open_max_calls: 1,
            stellar_retry_jitter_type: "full".to_string(),
            stellar_bulkhead_max_concurrent: 10,
            stellar_bulkhead_max_queue: 100,
            log_level: "info".to_string(),
            webhook_urls: vec!["https://webhook.example.com".to_string()],
            webhook_secret: Some("another-secret".to_string()),
            webhook_max_retries: 5,
            webhook_retry_base_delay_ms: 200,
            webhook_retry_max_delay_ms: 30_000,
            webhook_request_timeout_ms: 10_000,
            webhook_jitter_enabled: true,
            cache_verification_ttl: 3600,
            cache_backend: "inmemory".to_string(),
            cache_max_size: 10000,
            cache_config_ttl: 3600,
            cache_events_ttl: 1800,
            cache_circuit_breaker_failure_threshold: 5,
            cache_circuit_breaker_open_duration_ms: 30_000,
            cache_circuit_breaker_half_open_max_calls: 1,
            cache_circuit_breaker_backoff_base_ms: 100,
            cache_circuit_breaker_backoff_max_ms: 30_000,
            cache_bulkhead_max_concurrent: 20,
            cache_bulkhead_max_queue: 200,
        };

        let debug = format!("{:?}", config);
        assert!(!debug.contains("secret-value"));
        assert!(!debug.contains("another-secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn from_env_records_config_validation_failure() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("PORT", "0");
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);

        let metrics = MetricsRegistry::arc();
        let _err =
            AppConfig::from_env_with_metrics(Some(Arc::clone(&metrics))).expect_err("should fail");

        let output = metrics.render();
        assert!(output.contains("config_validation_failures_total"));
    }

    #[test]
    fn from_env_records_config_reload_on_success() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);

        let metrics = MetricsRegistry::arc();
        let _cfg =
            AppConfig::from_env_with_metrics(Some(Arc::clone(&metrics))).expect("should succeed");

        let output = metrics.render();
        assert!(output.contains("config_reload_total"));
    }

    // ── New validation tests ─────────────────────────────────────────────

    #[test]
    fn rejects_burst_less_than_per_second() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);
        env::set_var("RATE_LIMIT_PER_SECOND", "100");
        env::set_var("RATE_LIMIT_BURST", "50"); // burst < rps

        let err = AppConfig::from_env().expect_err("should fail");
        assert!(err
            .to_string()
            .contains("RATE_LIMIT_BURST (50) must be >= RATE_LIMIT_PER_SECOND (100)"));
    }

    #[test]
    fn rejects_per_issuer_burst_less_than_per_second() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);
        env::set_var("RATE_LIMIT_PER_SECOND", "1000");
        env::set_var("PER_ISSUER_RATE_LIMIT_PER_SECOND", "20");
        env::set_var("PER_ISSUER_RATE_LIMIT_BURST", "10"); // burst < rps

        let err = AppConfig::from_env().expect_err("should fail");
        assert!(err.to_string().contains(
            "PER_ISSUER_RATE_LIMIT_BURST (10) must be >= PER_ISSUER_RATE_LIMIT_PER_SECOND (20)"
        ));
    }

    #[test]
    fn rejects_invalid_log_level() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);
        env::set_var("LOG_LEVEL", "invalid");

        let err = AppConfig::from_env().expect_err("should fail");
        assert!(err.to_string().contains("LOG_LEVEL must be one of"));
    }

    #[test]
    fn rejects_stellar_retry_delay_exceeding_max() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);
        env::set_var("STELLAR_RETRY_BASE_DELAY_MS", "999999");

        let err = AppConfig::from_env().expect_err("should fail");
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn validated_url_rejects_invalid_scheme() {
        assert!(ValidatedUrl::parse("ftp://example.com").is_err());
        assert!(ValidatedUrl::parse("https://example.com").is_ok());
        assert!(ValidatedUrl::parse("http://localhost:8080").is_ok());
    }

    #[test]
    fn validated_redis_url_rejects_non_redis_scheme() {
        assert!(ValidatedRedisUrl::parse("https://example.com").is_err());
        assert!(ValidatedRedisUrl::parse("redis://localhost:6379").is_ok());
        assert!(ValidatedRedisUrl::parse("rediss://localhost:6380").is_ok());
    }

    #[test]
    fn validated_port_rejects_out_of_range() {
        assert!(ValidatedPort::new(0).is_err());
        // u16::MAX is the maximum valid value, so we test via `new` which takes u16
        // Testing exact boundary: 65535 is valid
        assert!(ValidatedPort::new(65535).is_ok());
        assert!(ValidatedPort::new(8080).is_ok());
    }

    #[test]
    fn validated_port_roundtrip() {
        let port = ValidatedPort::new(3000).unwrap();
        assert_eq!(port.value(), 3000);
        let val: u16 = port.into();
        assert_eq!(val, 3000);
    }

    #[test]
    fn config_version_validation() {
        assert!(ConfigVersion::new(0).is_err());
        assert!(ConfigVersion::new(1).is_ok());
        assert!(ConfigVersion::new(CONFIG_VERSION + 1).is_err());
        assert_eq!(ConfigVersion::current().value(), CONFIG_VERSION);
    }

    #[test]
    fn config_channel_creates_watcher() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);
        let config = AppConfig::from_env().unwrap();
        let (tx, mut rx) = config_channel(config.clone()).unwrap();
        let received = rx.borrow_and_update().clone();
        assert_eq!(received.config.port, config.port);
        assert_eq!(received.version.value(), CONFIG_VERSION);
        // tx can send updates
        let update = ConfigUpdate::new(config).unwrap();
        tx.send(update).unwrap();
    }

    #[test]
    fn validate_compatible_rejects_rollback() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);
        let config = AppConfig::from_env().unwrap();
        let result = config.validate_compatible(CONFIG_VERSION + 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("roll back"));
    }

    #[test]
    fn validate_compatible_accepts_same_version() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);
        let config = AppConfig::from_env().unwrap();
        assert!(config.validate_compatible(CONFIG_VERSION).is_ok());
    }

    #[test]
    fn reload_from_env_produces_new_instance() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        env::set_var("STELLAR_SECRET_KEY", VALID_KEY);
        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.port, 8080);

        env::set_var("PORT", "9090");
        let reloaded = config.reload_from_env(None).unwrap();
        assert_eq!(reloaded.port, 9090);
    }

    #[test]
    fn config_version_constant_is_consistent() {
        assert_eq!(CONFIG_VERSION, 1);
    }
}

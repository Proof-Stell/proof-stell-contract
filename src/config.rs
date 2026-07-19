use std::{env, fmt, string::{String, ToString}, sync::Arc, vec::Vec};
use thiserror::Error;
use stellar_strkey::ed25519::PrivateKey;
use url::Url;

const DEFAULT_STELLAR_RETRY_BASE_DELAY_MS: u64 = 100;
const DEFAULT_STELLAR_RETRY_MAX_DELAY_MS: u64 = 10_000;
const DEFAULT_STELLAR_REQUEST_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD: u32 = 5;
const DEFAULT_STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS: u64 = 30_000;
const DEFAULT_STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS: u32 = 1;
use crate::metrics::MetricsRegistry;

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
            .field("per_issuer_rate_limit_per_second", &self.per_issuer_rate_limit_per_second)
            .field("per_issuer_rate_limit_burst", &self.per_issuer_rate_limit_burst)
            .field("issuer_rate_limit_ttl_seconds", &self.issuer_rate_limit_ttl_seconds)
            .field("stellar_max_retries", &self.stellar_max_retries)
            .field(
                "stellar_retry_base_delay_ms",
                &self.stellar_retry_base_delay_ms,
            )
            .field("stellar_retry_max_delay_ms", &self.stellar_retry_max_delay_ms)
            .field(
                "stellar_retry_jitter_enabled",
                &self.stellar_retry_jitter_enabled,
            )
            .field("stellar_request_timeout_ms", &self.stellar_request_timeout_ms)
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
            .field("log_level", &self.log_level)
            .field("webhook_urls", &self.webhook_urls)
            .field(
                "webhook_secret",
                &self.webhook_secret.as_deref().map(|_| "<redacted>"),
            )
            .field("webhook_max_retries", &self.webhook_max_retries)
            .field("webhook_retry_base_delay_ms", &self.webhook_retry_base_delay_ms)
            .field("webhook_retry_max_delay_ms", &self.webhook_retry_max_delay_ms)
            .field("webhook_request_timeout_ms", &self.webhook_request_timeout_ms)
            .field("webhook_jitter_enabled", &self.webhook_jitter_enabled)
            .field("cache_verification_ttl", &self.cache_verification_ttl)
            .field("cache_backend", &self.cache_backend)
            .field("cache_max_size", &self.cache_max_size)
            .field("cache_config_ttl", &self.cache_config_ttl)
            .field("cache_events_ttl", &self.cache_events_ttl)
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
                        "STELLAR_SECRET_KEY must be a valid Stellar ed25519 secret key"
                            .to_string(),
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
        let cache_verification_ttl_raw = get_env_or_default("CACHE_VERIFICATION_TTL", "3600");
        let cache_backend_raw = get_env_or_default("CACHE_BACKEND", "inmemory");
        let cache_max_size_raw = get_env_or_default("CACHE_MAX_SIZE", "10000");
        let cache_config_ttl_raw = get_env_or_default("CACHE_CONFIG_TTL", "3600");
        let cache_events_ttl_raw = get_env_or_default("CACHE_EVENTS_TTL", "1800");

        let port: u16 = match port_raw.parse() {
            Ok(p) if p > 0 => p,
            Ok(_) => {
                errors.push("PORT must be between 1 and 65535".to_string());
                8080
            }
            Err(_) => {
                errors.push(format!("PORT must be a valid u16, got '{}'", port_raw));
                8080
            }
        };

        if Url::parse(&stellar_horizon_url).is_err() {
            errors.push(format!(
                "STELLAR_HORIZON_URL must be a valid URL, got '{}'",
                stellar_horizon_url
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

        // ── Parse per-issuer rate-limit values ───────────────────────────
        let per_issuer_rate_limit_per_second: u32 = match per_issuer_rps_raw.parse() {
            Ok(v) if v > 0 => v,
            Ok(_) => {
                errors.push(
                    "PER_ISSUER_RATE_LIMIT_PER_SECOND must be greater than 0".to_string(),
                );
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
                errors.push(
                    "PER_ISSUER_RATE_LIMIT_BURST must be greater than 0".to_string(),
                );
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

        if per_issuer_rate_limit_per_second > rate_limit_per_second {
            errors.push(format!(
                "PER_ISSUER_RATE_LIMIT_PER_SECOND ({}) must not exceed RATE_LIMIT_PER_SECOND ({})",
                per_issuer_rate_limit_per_second, rate_limit_per_second
            ));
        }

        let issuer_rate_limit_ttl_seconds: u64 = match issuer_ttl_raw.parse() {
            Ok(v) if v > 0 => v,
            Ok(_) => {
                errors.push(
                    "ISSUER_RATE_LIMIT_TTL_SECONDS must be greater than 0".to_string(),
                );
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

        // ── Parse remaining values ────────────────────────────────────────
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
            Ok(v) if v > 0 => v,
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
            Ok(v) if v > 0 => v,
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
            Ok(v) if v > 0 => v,
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
                Ok(v) if v > 0 => v,
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

        match Url::parse(&redis_url) {
            Ok(url) if matches!(url.scheme(), "redis" | "rediss") => {}
            Ok(_) | Err(_) => {
                errors.push(format!(
                    "REDIS_URL must be a valid redis:// or rediss:// URL, got '{}'",
                    redis_url
                ));
            }
        }

        if rate_limit_burst == 0 {
            errors.push("RATE_LIMIT_BURST must be greater than 0".to_string());
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
            Ok(v) if v > 0 => v,
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
            Ok(v) if v > 0 => v,
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
            Ok(v) if v > 0 => v,
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
                if Url::parse(url).is_err() {
                    errors.push(format!("WEBHOOK_URLS must contain valid URLs, got '{}'", url));
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
        })
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
        assert_eq!(cfg.stellar_horizon_url, "https://horizon-testnet.stellar.org");
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

        assert!(msg.contains("PORT must be between 1 and 65535"));
        assert!(msg.contains("STELLAR_HORIZON_URL must be a valid URL"));
        assert!(msg.contains("REDIS_URL must be a valid redis:// or rediss:// URL"));
        assert!(msg.contains("RATE_LIMIT_PER_SECOND must be greater than 0"));
        assert!(msg.contains("RATE_LIMIT_BURST must be greater than 0"));
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
        let _cfg = AppConfig::from_env_with_metrics(Some(Arc::clone(&metrics)))
            .expect("should succeed");

        let output = metrics.render();
        assert!(output.contains("config_reload_total"));
    }
}
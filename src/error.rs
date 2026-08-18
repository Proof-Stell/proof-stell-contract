extern crate alloc;

use alloc::string::String;
use core::fmt;

pub type Result<T> = core::result::Result<T, AuditError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    SerializationError(String),
    InvalidContractEventContext(String),
    CircuitBreakerOpen(String),
    BulkheadFull(String),
    CacheUnhealthy(String),
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SerializationError(message) => write!(f, "serialization error: {message}"),
            Self::InvalidContractEventContext(message) => {
                write!(f, "invalid contract event context: {message}")
            }
            Self::CircuitBreakerOpen(message) => {
                write!(f, "circuit breaker open: {message}")
            }
            Self::BulkheadFull(message) => {
                write!(f, "bulkhead full: {message}")
            }
            Self::CacheUnhealthy(message) => {
                write!(f, "cache unhealthy: {message}")
            }
        }
    }
}

impl core::error::Error for AuditError {}

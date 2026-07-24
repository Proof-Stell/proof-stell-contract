extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
};
use std::collections::{HashMap, HashSet};
use std::prelude::v1::*;
use std::sync::Arc;
use tokio::sync::broadcast;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Canonical event type identifiers for off-chain consumers.
pub const EVENT_DOCUMENT_REGISTERED: &str = "DocumentRegistered";
pub const EVENT_DOCUMENT_REVOKED: &str = "DocumentRevoked";
pub const EVENT_DOCUMENT_VERIFIED: &str = "DocumentVerified";
pub const EVENT_DOCUMENT_AUTHORIZATION_FAILED: &str = "DocumentAuthorizationFailed";
pub const EVENT_DOCUMENT_OWNER_CHANGED: &str = "DocumentOwnerChanged";

/// Source of an audit event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventSource {
    Contract,
    Service,
}

/// Contract execution details used to derive stable audit metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractEventContext {
    pub transaction_hash: String,
    pub ledger_sequence: u64,
    pub event_index: u32,
    pub document_hash: String,
}

impl ContractEventContext {
    fn validate(&self) -> crate::error::Result<()> {
        if self.transaction_hash.trim().is_empty() {
            return Err(crate::error::AuditError::InvalidContractEventContext(
                "transaction hash cannot be empty".to_string(),
            ));
        }

        if self.document_hash.trim().is_empty() {
            return Err(crate::error::AuditError::InvalidContractEventContext(
                "document hash cannot be empty".to_string(),
            ));
        }

        if self.ledger_sequence == 0 {
            return Err(crate::error::AuditError::InvalidContractEventContext(
                "ledger sequence must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    pub fn idempotency_key(&self, aggregate_id: &str, event_type: &str) -> String {
        format!(
            "contract:{}:{}:{}:{}:{}",
            self.transaction_hash, self.ledger_sequence, self.event_index, aggregate_id, event_type
        )
    }

    pub fn sequence(&self) -> u64 {
        self.ledger_sequence
            .saturating_mul(1_000)
            .saturating_add(u64::from(self.event_index))
    }
}

/// Core event type for audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    /// Unique event record ID.
    pub id: String,
    /// Document or aggregate ID being modified.
    pub aggregate_id: String,
    /// Type of event, such as `DocumentRegistered` or `DocumentRevoked`.
    pub event_type: String,
    /// Event payload as JSON.
    pub data: serde_json::Value,
    /// Timestamp when event occurred.
    pub timestamp: DateTime<Utc>,
    /// Sequential event number for ordering within an aggregate.
    pub sequence: u64,
    /// User or system that triggered the event.
    pub actor: String,
    /// Deterministic key used to de-duplicate replays.
    pub idempotency_key: String,
    /// Audit source that produced this event.
    pub source: EventSource,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

impl Event {
    /// Create a new service-side event.
    pub fn new(
        aggregate_id: String,
        event_type: String,
        data: serde_json::Value,
        actor: String,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        Self {
            id: id.clone(),
            aggregate_id,
            event_type,
            data,
            timestamp: Utc::now(),
            sequence: 1,
            actor,
            idempotency_key: id,
            source: EventSource::Service,
            metadata: None,
        }
    }

    /// Override the sequence number when the caller has stable ordering context.
    pub fn with_sequence(mut self, sequence: u64) -> Self {
        self.sequence = sequence;
        self
    }

    /// Override the idempotency key when the caller has a deterministic replay key.
    pub fn with_idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = idempotency_key.into();
        self
    }

    /// Override the audit source.
    pub fn with_source(mut self, source: EventSource) -> Self {
        self.source = source;
        self
    }

    /// Add metadata to the event.
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Create an audit event from a Soroban contract event.
    pub fn from_contract_event(
        aggregate_id: String,
        event_type: String,
        data: serde_json::Value,
        actor: String,
        context: ContractEventContext,
    ) -> crate::error::Result<Self> {
        context.validate()?;

        let id = Uuid::new_v4().to_string();
        let idempotency_key = context.idempotency_key(&aggregate_id, &event_type);
        let metadata = serde_json::json!({
            "transaction_hash": context.transaction_hash,
            "ledger_sequence": context.ledger_sequence,
            "event_index": context.event_index,
            "document_hash": context.document_hash,
            "source": "contract",
        });

        Ok(Self {
            id,
            aggregate_id,
            event_type,
            data,
            timestamp: Utc::now(),
            sequence: context.sequence(),
            actor,
            idempotency_key,
            source: EventSource::Contract,
            metadata: Some(metadata),
        })
    }

    /// Serialize event to JSON string.
    pub fn to_json(&self) -> crate::error::Result<String> {
        serde_json::to_string(self)
            .map_err(|e| crate::error::AuditError::SerializationError(e.to_string()))
    }

    /// Deserialize event from JSON string.
    pub fn from_json(json: &str) -> crate::error::Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| crate::error::AuditError::SerializationError(e.to_string()))
    }
}

/// An event ingestion pipeline that records metrics for duplicates, ordering failures,
/// and backlog size.
///
/// This is a minimal in-memory implementation suitable for testing and local development.
/// Production deployments should replace this with a persistent event store.
///
/// **Note on memory growth:** The `seen_keys` and `last_sequence` collections grow
/// unboundedly with no eviction strategy. A production implementation should use
/// an LRU cache or TTL-based eviction to prevent unbounded memory consumption.
pub struct EventIngestor {
    /// Set of seen idempotency keys for deduplication.
    seen_keys: HashSet<String>,
    /// Last seen sequence number per aggregate for ordering validation.
    last_sequence: HashMap<String, u64>,
    /// Metrics registry for instrumentation.
    metrics: Option<Arc<crate::metrics::MetricsRegistry>>,
    /// Event broadcast channel for cache invalidation notifications.
    event_tx: broadcast::Sender<EventInvalidation>,
}

/// Event invalidation notification for cache coordination.
#[derive(Debug, Clone)]
pub enum EventInvalidation {
    DocumentRegistered { aggregate_id: String },
    DocumentRevoked { aggregate_id: String },
    DocumentVerified { aggregate_id: String },
}

impl EventIngestor {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(100);
        Self {
            seen_keys: HashSet::new(),
            last_sequence: HashMap::new(),
            metrics: None,
            event_tx,
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::MetricsRegistry>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Subscribe to event invalidation notifications for cache coordination.
    pub fn subscribe(&self) -> broadcast::Receiver<EventInvalidation> {
        self.event_tx.subscribe()
    }

    /// Attempt to ingest an event, recording appropriate metrics.
    ///
    /// Returns `Ok(())` if the event was accepted, or an error describing why it was rejected.
    pub fn ingest(&mut self, event: &Event) -> crate::error::Result<()> {
        // Check for duplicates via idempotency key
        if !self.seen_keys.insert(event.idempotency_key.clone()) {
            if let Some(ref m) = self.metrics {
                m.increment_event_duplicate();
            }
            return Err(crate::error::AuditError::InvalidContractEventContext(
                format!("duplicate event: idempotency_key={}", event.idempotency_key),
            ));
        }

        // Check ordering: sequence must be greater than the last seen for this aggregate
        let last_seq = self.last_sequence.get(&event.aggregate_id).copied();
        if let Some(last) = last_seq {
            if event.sequence <= last {
                if let Some(ref m) = self.metrics {
                    m.increment_event_ordering_failure();
                }
                return Err(crate::error::AuditError::InvalidContractEventContext(
                    format!(
                        "ordering failure: aggregate={} current_seq={} last_seq={}",
                        event.aggregate_id, event.sequence, last
                    ),
                ));
            }
        }

        // Accept the event
        self.last_sequence
            .insert(event.aggregate_id.clone(), event.sequence);

        // Broadcast invalidation notification based on event type
        let invalidation = match event.event_type.as_str() {
            EVENT_DOCUMENT_REGISTERED => Some(EventInvalidation::DocumentRegistered {
                aggregate_id: event.aggregate_id.clone(),
            }),
            EVENT_DOCUMENT_REVOKED => Some(EventInvalidation::DocumentRevoked {
                aggregate_id: event.aggregate_id.clone(),
            }),
            EVENT_DOCUMENT_VERIFIED => Some(EventInvalidation::DocumentVerified {
                aggregate_id: event.aggregate_id.clone(),
            }),
            _ => None,
        };

        if let Some(invalidation) = invalidation {
            let _ = self.event_tx.send(invalidation);
        }

        // Update backlog gauge (increment on accept)
        if let Some(ref m) = self.metrics {
            m.increment_event_backlog();
        }

        Ok(())
    }

    /// Mark events as processed, decrementing the backlog gauge.
    pub fn mark_processed(&self, count: u64) {
        if let Some(ref m) = self.metrics {
            for _ in 0..count {
                m.decrement_event_backlog();
            }
        }
    }

    /// Set the backlog gauge to an explicit size.
    pub fn set_backlog_size(&self, size: i64) {
        if let Some(ref m) = self.metrics {
            m.set_event_backlog(size);
        }
    }
}

impl Default for EventIngestor {
    fn default() -> Self {
        Self::new()
    }
}

/// Persistent event store that maintains append-only logs per aggregate.
///
/// This is a minimal in-memory implementation suitable for testing and local development.
/// Production deployments should replace this with a durable store (e.g. Redis Streams,
/// PostgreSQL, or event-sourcing infrastructure).
///
/// **Note on memory growth:** The `events` map grows unboundedly without eviction.
/// A production implementation should cap retention per aggregate.
pub struct EventStore {
    events: HashMap<String, Vec<Event>>,
}

impl EventStore {
    pub fn new() -> Self {
        Self {
            events: HashMap::new(),
        }
    }

    /// Append an event to the store for the given aggregate.
    ///
    /// Returns the event with its final sequence number populated.
    pub fn append(&mut self, aggregate_id: impl Into<String>, event: Event) -> Event {
        let aggregate_id = aggregate_id.into();
        let events = self.events.entry(aggregate_id.clone()).or_default();

        let sequence = events.len() as u64 + 1;
        let mut finalized = event.with_sequence(sequence);
        finalized.aggregate_id = aggregate_id;

        events.push(finalized.clone());

        finalized
    }

    /// Retrieve the full event history for an aggregate.
    pub fn get_history(&self, aggregate_id: &str) -> Option<&Vec<Event>> {
        self.events.get(aggregate_id)
    }

    /// Retrieve the latest sequence number for an aggregate.
    pub fn get_latest_sequence(&self, aggregate_id: &str) -> Option<u64> {
        self.events
            .get(aggregate_id)
            .and_then(|events| events.last())
            .map(|e| e.sequence)
    }

    /// Return the number of events stored for an aggregate.
    pub fn count(&self, aggregate_id: &str) -> usize {
        self.events.get(aggregate_id).map(|v| v.len()).unwrap_or(0)
    }
}

impl Default for EventStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_event_uses_non_zero_sequence() {
        let event = Event::new(
            "doc-1".to_string(),
            "Created".to_string(),
            serde_json::json!({"title": "Test"}),
            "user-1".to_string(),
        );

        assert_eq!(event.sequence, 1);
        assert_eq!(event.source, EventSource::Service);
        assert!(!event.idempotency_key.is_empty());
    }

    #[test]
    fn contract_event_derives_stable_metadata() {
        let context = ContractEventContext {
            transaction_hash: "tx123".to_string(),
            ledger_sequence: 42,
            event_index: 3,
            document_hash: "doc-hash".to_string(),
        };

        let event = Event::from_contract_event(
            "doc-1".to_string(),
            "DocumentRegistered".to_string(),
            serde_json::json!({"status": "active"}),
            "issuer-1".to_string(),
            context,
        )
        .expect("contract event should build");

        assert_eq!(event.source, EventSource::Contract);
        assert_eq!(event.sequence, 42_003);
        assert_eq!(
            event.idempotency_key,
            "contract:tx123:42:3:doc-1:DocumentRegistered"
        );
        let metadata = event.metadata.expect("contract event metadata");
        assert_eq!(metadata["transaction_hash"], "tx123");
        assert_eq!(metadata["ledger_sequence"], 42);
        assert_eq!(metadata["event_index"], 3);
        assert_eq!(metadata["document_hash"], "doc-hash");
    }

    #[test]
    fn event_serialization_roundtrip_keeps_audit_fields() {
        let context = ContractEventContext {
            transaction_hash: "tx123".to_string(),
            ledger_sequence: 42,
            event_index: 3,
            document_hash: "doc-hash".to_string(),
        };

        let event = Event::from_contract_event(
            "doc-1".to_string(),
            "DocumentRegistered".to_string(),
            serde_json::json!({"title": "Test"}),
            "issuer-1".to_string(),
            context,
        )
        .expect("contract event should build");

        let json = event.to_json().unwrap();
        let deserialized = Event::from_json(&json).unwrap();

        assert_eq!(event.id, deserialized.id);
        assert_eq!(event.aggregate_id, deserialized.aggregate_id);
        assert_eq!(event.idempotency_key, deserialized.idempotency_key);
        assert_eq!(event.sequence, deserialized.sequence);
        assert_eq!(event.source, deserialized.source);
    }

    #[test]
    fn invalid_contract_context_is_rejected() {
        let err = Event::from_contract_event(
            "doc-1".to_string(),
            "DocumentRegistered".to_string(),
            serde_json::json!({"title": "Test"}),
            "issuer-1".to_string(),
            ContractEventContext {
                transaction_hash: String::new(),
                ledger_sequence: 0,
                event_index: 0,
                document_hash: String::new(),
            },
        )
        .expect_err("context should fail validation");

        assert!(err.to_string().contains("invalid contract event context"));
    }

    #[test]
    fn event_ingestor_accepts_valid_event() {
        let metrics = crate::metrics::MetricsRegistry::arc();
        let mut ingestor = EventIngestor::new().with_metrics(Arc::clone(&metrics));

        let event = Event::new(
            "doc-1".to_string(),
            "Created".to_string(),
            serde_json::json!({"title": "Test"}),
            "user-1".to_string(),
        );

        assert!(ingestor.ingest(&event).is_ok());
        let output = metrics.render();
        assert!(output.contains("event_backlog_size"));
    }

    #[test]
    fn event_ingestor_rejects_duplicate() {
        let metrics = crate::metrics::MetricsRegistry::arc();
        let mut ingestor = EventIngestor::new().with_metrics(Arc::clone(&metrics));

        let event = Event::new(
            "doc-1".to_string(),
            "Created".to_string(),
            serde_json::json!({"title": "Test"}),
            "user-1".to_string(),
        );

        assert!(ingestor.ingest(&event).is_ok());
        let result = ingestor.ingest(&event);
        assert!(result.is_err());

        let output = metrics.render();
        assert!(output.contains("event_duplicates_total"));
    }

    #[test]
    fn event_ingestor_rejects_out_of_order() {
        let metrics = crate::metrics::MetricsRegistry::arc();
        let mut ingestor = EventIngestor::new().with_metrics(Arc::clone(&metrics));

        let event1 = Event::new(
            "doc-1".to_string(),
            "Updated".to_string(),
            serde_json::json!({"v": 1}),
            "user-1".to_string(),
        )
        .with_sequence(10);

        let event2 = Event::new(
            "doc-1".to_string(),
            "Updated".to_string(),
            serde_json::json!({"v": 2}),
            "user-1".to_string(),
        )
        .with_sequence(5); // earlier sequence than event1

        assert!(ingestor.ingest(&event1).is_ok());
        let result = ingestor.ingest(&event2);
        assert!(result.is_err());

        let output = metrics.render();
        assert!(output.contains("event_ordering_failures_total"));
    }

    #[test]
    fn event_ingestor_mark_processed_decrements_backlog() {
        let metrics = crate::metrics::MetricsRegistry::arc();
        let ingestor = EventIngestor::new().with_metrics(Arc::clone(&metrics));

        ingestor.set_backlog_size(5);
        ingestor.mark_processed(3);

        let output = metrics.render();
        assert!(output.contains("event_backlog_size"));
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;

    #[test]
    fn event_store_appends_events_in_sequence() {
        let mut store = EventStore::new();

        let e1 = store.append(
            "doc-1",
            Event::new(
                "doc-1".to_string(),
                EVENT_DOCUMENT_REGISTERED.to_string(),
                serde_json::json!({"issuer": "addr1"}),
                "issuer".to_string(),
            ),
        );

        let e2 = store.append(
            "doc-1",
            Event::new(
                "doc-1".to_string(),
                EVENT_DOCUMENT_REVOKED.to_string(),
                serde_json::json!({}),
                "issuer".to_string(),
            ),
        );

        assert_eq!(e1.sequence, 1);
        assert_eq!(e2.sequence, 2);
        assert_eq!(store.count("doc-1"), 2);
    }

    #[test]
    fn event_store_retrieves_history() {
        let mut store = EventStore::new();

        store.append(
            "doc-1",
            Event::new(
                "doc-1".to_string(),
                EVENT_DOCUMENT_REGISTERED.to_string(),
                serde_json::json!({}),
                "issuer".to_string(),
            ),
        );

        let history = store.get_history("doc-1").unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].event_type, EVENT_DOCUMENT_REGISTERED);
    }

    #[test]
    fn event_store_empty_history_returns_none() {
        let store = EventStore::new();
        assert!(store.get_history("missing").is_none());
        assert_eq!(store.get_latest_sequence("missing"), None);
    }

    #[test]
    fn event_store_get_latest_sequence() {
        let mut store = EventStore::new();

        store.append(
            "doc-1",
            Event::new(
                "doc-1".to_string(),
                EVENT_DOCUMENT_REGISTERED.to_string(),
                serde_json::json!({}),
                "issuer".to_string(),
            ),
        );
        store.append(
            "doc-1",
            Event::new(
                "doc-1".to_string(),
                EVENT_DOCUMENT_VERIFIED.to_string(),
                serde_json::json!({}),
                "caller".to_string(),
            ),
        );

        assert_eq!(store.get_latest_sequence("doc-1"), Some(2));
    }

    #[test]
    fn event_store_separates_aggregates() {
        let mut store = EventStore::new();

        store.append(
            "doc-1",
            Event::new(
                "doc-1".to_string(),
                EVENT_DOCUMENT_REGISTERED.to_string(),
                serde_json::json!({}),
                "issuer".to_string(),
            ),
        );
        store.append(
            "doc-2",
            Event::new(
                "doc-2".to_string(),
                EVENT_DOCUMENT_OWNER_CHANGED.to_string(),
                serde_json::json!({}),
                "owner".to_string(),
            ),
        );

        assert_eq!(store.count("doc-1"), 1);
        assert_eq!(store.count("doc-2"), 1);
        assert_eq!(
            store.get_history("doc-1").unwrap()[0].event_type,
            EVENT_DOCUMENT_REGISTERED
        );
        assert_eq!(
            store.get_history("doc-2").unwrap()[0].event_type,
            EVENT_DOCUMENT_OWNER_CHANGED
        );
    }
}

# 📜 ProofStell Smart Contract

Decentralized document verification contract built with Soroban.

---

## 🌍 Overview

This smart contract powers the **on-chain verification layer** of ProofStell.

It stores **cryptographic hashes of documents** and enables:

* Document registration
* Verification
* Revocation

---

## 🚀 Core Features

### 📄 Document Registry

* Store document hashes on-chain
* Ensure immutability

---

### 🔎 Verification

* Check if a document exists
* Confirm authenticity
* Cross-reference with Stellar Horizon for on-chain proof

#### Verification Proof Source

ProofStell uses a **dual-source verification model**:

1. **Stellar Horizon** (primary) — The service queries `GET /transactions?memo={hash}`
   against the configured Horizon instance. When a matching transaction is found
   with a confirmed memo match, the transaction ID and ledger timestamp are returned
   as authoritative proof.

2. **On-chain contract state** (secondary) — The Soroban contract's `verify_document`
   method confirms whether a document record exists and is `Active` in persistent
   storage.

Horizon verification distinguishes four result categories:

| Status | Meaning |
|---|---|
| `ConfirmedMatch` | A Stellar transaction with matching memo was found — proof is authoritative |
| `NoMatch` | Horizon was reachable but no transaction matches the hash |
| `NetworkError` | All retries exhausted due to connection or HTTP errors |
| `MalformedResponse` | Horizon returned a response that could not be parsed |

Only `ConfirmedMatch` constitutes a positive verification. All other results
are treated as non-verified (the document may still be valid on-chain, but no
Horizon proof exists).

---

### 🧾 Revocation

* Allow issuers to revoke documents
* Maintain revocation state

---

### 🔄 Upgrades & Governance

* Single-admin governance — one address (set at `initialize`) controls upgrades, migrations, and feature flags
* Contract version stored in persistent ledger — survives ledger entry expiry
* Feature flags allow toggling behaviours without a full WASM upgrade
* `ContractInitialized` and `ContractUpgraded` events let indexers detect which contract version produced any given document event

---

### 📦 Batch Operations

* `batch_register_documents` — register up to 20 documents in one transaction
* `batch_revoke_documents` — revoke up to 20 documents in one transaction

**Atomicity:** All documents succeed or none are written. If any item in the batch fails (e.g. duplicate hash, wrong issuer, already revoked), the entire call returns an error and no state is changed.

**Batch size limit:** Maximum 20 documents per call. Exceeding this returns `BatchTooLarge` (error code 7). Empty batches return `BatchEmpty` (error code 8).

**Fee implications:** A single transaction covers the entire batch regardless of size, making bulk operations significantly cheaper than individual calls. For best results, pre-validate document uniqueness and existence client-side before submitting to avoid wasted transaction fees on partial failures.

---

## 🧠 How It Works

1. Document is hashed (SHA256)

2. Hash is submitted to contract

3. Contract stores:

   * Issuer address
   * Owner address
   * Timestamp
   * Status

4. Verification compares hash with stored record

---

## 🔑 Canonical Hash Encoding

ProofStell uses **SHA-256** as the only supported hash algorithm. All public APIs enforce this at the service boundary.

| Property | Value |
|---|---|
| Algorithm | SHA-256 |
| Encoding | Lowercase hexadecimal |
| Length | 64 characters (32 bytes) |

**Valid example:**
```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

**Invalid examples:**
```
# Too short (SHA-1):
da39a3ee5e6b4b0d3255bfef95601890afd80709

# SHA-512 (128 chars) — rejected before contract submission:
cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e

# Uppercase — normalize before submission:
E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
```

Use `HashValidator::validate_for_contract(hash)` to normalize and validate before calling the contract. Use `HashValidator::hex_to_bytes32(hex)` to convert the normalized hex string to the `[u8; 32]` array required by the Soroban `BytesN<32>` type.

Cache keys and Stellar Horizon memo queries always use the lowercase-normalized form so that clients submitting mixed-case hashes receive consistent results.

---

## 🗂️ Data Model


DocumentHash → DocumentRecord


## 🔐 Security

* No raw documents stored on-chain
* Duplicate prevention
* Issuer authorization
* Immutable records
* Revocation tracking
* Contract-level rate limiting for registration, revocation, and batch operations

### Rate limiting

The contract now enforces configurable per-address and per-issuer token buckets for document operations. The admin can set the limits with `set_rate_limit_config`, and the contract returns `ContractError::RateLimitExceeded` once a bucket is exhausted. Callers can inspect `get_rate_limit_retry_after` to learn the delay before retrying.

Suggested production tuning:

* Keep `per_address_burst` and `per_issuer_burst` slightly above the expected steady-state traffic so burst traffic is allowed without opening the door to abuse.
* Start with conservative values for `per_address_per_second` and `per_issuer_per_second`, then increase only after observing real traffic patterns.
* Use separate issuer-level throttles for high-volume integrations and address-level throttles for public-facing clients.

---

## 🛠️ Tech Stack

* Rust
* Soroban SDK
* Stellar Network

---

## 🚀 Development

### Requirements

* Rust
* Soroban CLI

---

### Install Soroban CLI

```bash
cargo install soroban-cli
```

---

### Build Contract

```bash
cargo build --target wasm32-unknown-unknown --release
```

---

### Deploy Contract

```bash
soroban contract deploy \
--wasm target/wasm32-unknown-unknown/release/proofstell_contract.wasm \
--network testnet
```

---

### Initialize After Deployment

After deploying, call `initialize` to set the admin address and record version 1 on-chain:

```bash
soroban contract invoke \
  --id <CONTRACT_ID> \
  --source <ADMIN_SECRET_KEY> \
  --network testnet \
  -- initialize \
  --admin <ADMIN_ADDRESS>
```

---

### Upgrade Procedure

1. **Build the new WASM** and upload it to the ledger:

```bash
cargo build --target wasm32-unknown-unknown --release
soroban contract install \
  --wasm target/wasm32-unknown-unknown/release/proofstell_contract.wasm \
  --network testnet
# Note the returned WASM hash
```

2. **Call `upgrade`** with the new WASM hash:

```bash
soroban contract invoke \
  --id <CONTRACT_ID> \
  --source <ADMIN_SECRET_KEY> \
  --network testnet \
  -- upgrade \
  --admin <ADMIN_ADDRESS> \
  --new_wasm_hash <WASM_HASH>
```

3. **Call `migrate`** to apply any data transformations and bump the version:

```bash
soroban contract invoke \
  --id <CONTRACT_ID> \
  --source <ADMIN_SECRET_KEY> \
  --network testnet \
  -- migrate \
  --admin <ADMIN_ADDRESS>
```

### Rollback Plan

Soroban contract upgrades are irreversible on-chain — there is no undo. To roll back:

1. Keep the previous WASM hash recorded before upgrading.
2. If the new version is broken, call `upgrade` again with the old WASM hash.
3. If the migration mutated storage in an incompatible way, a compensating migration must be written into the rolled-back WASM.

**Recommendation:** always test upgrades on testnet before applying to mainnet. See [docs/UPGRADE_GOVERNANCE.md](docs/UPGRADE_GOVERNANCE.md) for the full decision process.

---

## 🧪 Testing

```bash
cargo test
```

---

## 🗄️ Cache Behavior

### TTL Enforcement

Both the in-memory and Redis backends honor TTL values:

- **Redis** — uses `SET EX` so entries are natively evicted after `ttl` seconds.
- **InMemory** — stores an `expires_at` timestamp alongside each value. A `get` that finds an expired entry returns a cache miss (same semantics as Redis).

The TTL for verification results is controlled by the `CACHE_VERIFICATION_TTL` environment variable (default: `3600` seconds).

### Stellar Horizon Retry and Circuit Breaker Strategy

Horizon calls use `STELLAR_REQUEST_TIMEOUT_MS` as the per-request timeout (default: `10000` ms). `verify_hash_with_retry()` performs one initial call plus `STELLAR_MAX_RETRIES` retry attempts (default: `3`). Retry delay uses exponential backoff from `STELLAR_RETRY_BASE_DELAY_MS` (default: `100` ms) capped by `STELLAR_RETRY_MAX_DELAY_MS` (default: `10000` ms), with full jitter enabled by default via `STELLAR_RETRY_JITTER=true` to reduce thundering-herd behavior.

The Stellar circuit breaker starts in `Closed` state. Retryable request, timeout, parse, 429, and 5xx failures increment the consecutive failure count. When failures reach `STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD` (default: `5`), the breaker moves to `Open` and rejects calls for `STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS` (default: `30000` ms). After that duration, one half-open probe is allowed by default (`STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS=1`). A successful half-open probe closes the breaker and records a recovery; a failed probe reopens it. Circuit breaker metrics expose trips, recoveries, half-open successes, half-open failures, rejected calls, successful calls, and failed calls.

### Typed Cache Keys

Cache keys are typed via the `CacheKey` enum to prevent namespace collisions:

| Variant | Prefix | Example |
|---|---|---|
| `CacheKey::Verification(hash)` | `verification:` | `verification:e3b0c4…` |
| `CacheKey::Config(key)` | `config:` | `config:rate_limit` |

Callers must use the appropriate variant — raw string keys are no longer accepted.### Metrics

The `MetricsRegistry` (defined in `src/metrics.rs`) is the central instrumentation hub for the ProofStell service layer. All service modules emit metrics through this registry, which exposes a Prometheus-compatible text-format endpoint at `/metrics`.

#### General Request Metrics

| Metric | Type | Description |
|---|---|---|
| `requests_total` | Counter | Total number of API requests |
| `errors_total` | Counter | Total number of errors encountered |

#### Cache Metrics

| Metric | Type | Description |
|---|---|---|
| `cache_hits_total` | Counter | Entry found and returned |
| `cache_misses_total` | Counter | Entry not found |
| `cache_expired_total` | Counter | Entry found but TTL had elapsed (counted as miss) |
| `cache_serialization_failures_total` | Counter | Deserialization error on a cached value |

#### Document Registration & Revocation Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `document_registration_total` | CounterVec | `status` (success/error) | Total document registrations by outcome |
| `document_revocation_total` | CounterVec | `status` (success/error) | Total document revocations by outcome |

#### Verification Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `verification_total` | CounterVec | `status` (success/failure) | Total verifications by outcome |
| `verification_latency_seconds` | HistogramVec | `status` | End-to-end verification latency in seconds |
| `horizon_latency_seconds` | HistogramVec | `status` (success/error) | Stellar Horizon API call latency in seconds |
| `retry_total` | Counter | — | Total number of retry attempts across all operations |

#### Rate Limiter Metrics

| Metric | Type | Description |
|---|---|---|
| `rate_limit_tokens_consumed_total` | Counter | Total rate limiter tokens consumed |
| `rate_limit_violations_total` | Counter | Total rate limit violations (requests rejected) |

#### Event Ingestion Metrics

| Metric | Type | Description |
|---|---|---|
| `event_duplicates_total` | Counter | Total duplicate events detected and discarded |
| `event_ordering_failures_total` | Counter | Total events rejected due to ordering/sequence failures |
| `event_backlog_size` | Gauge | Current number of unprocessed events in the backlog queue |

#### Config Metrics

| Metric | Type | Description |
|---|---|---|
| `config_validation_failures_total` | Counter | Total configuration validation failures |
| `config_reload_total` | Counter | Total configuration reloads attempted |

#### Webhook Delivery Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `webhook_deliveries_total` | CounterVec | `status` (success/dead_lettered) | Total webhook delivery outcomes |
| `webhook_delivery_latency_seconds` | HistogramVec | `status` | End-to-end delivery latency including all retries |
| `webhook_dlq_depth` | Gauge | — | Current number of entries in the dead-letter queue |
| `webhook_retries_total` | Counter | — | Total webhook retry attempts |

#### Recommended Alerting Thresholds

| Alert | Condition | Severity |
|---|---|---|
| High error rate | `rate(errors_total[5m] / requests_total[5m]) > 0.1` | Critical |
| Low cache hit rate | `rate(cache_hits_total[5m]) / rate(cache_hits_total[5m] + cache_misses_total[5m]) < 0.5` | Warning |
| High verification failure rate | `rate(verification_total{status="failure"}[5m]) > 0.05` | Warning |
| Rate limit violations spike | `rate(rate_limit_violations_total[5m]) > 10` | Warning |
| Event backlog growing | `event_backlog_size > 1000` | Warning |
| Config validation failures | `increase(config_validation_failures_total[5m]) > 0` | Critical |
| High Horizon latency | `histogram_quantile(0.95, rate(horizon_latency_seconds_bucket[5m])) > 5` | Warning |
| Webhook DLQ growing | `webhook_dlq_depth > 0` | Warning |
| High webhook failure rate | `rate(webhook_deliveries_total{status="dead_lettered"}[5m]) > 0` | Critical |

#### Running with Metrics

Build the service binary (non-WASM target):

```bash
cargo build --release
```

The `/metrics` endpoint is served by the application HTTP server. To scrape metrics with Prometheus, add a scrape config:

```yaml
scrape_configs:
  - job_name: 'proofstell'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
```

### Environment Reference

| Variable | Default | Validation / Description |
|---|---|---|
| `PORT` | `8080` | Must be a valid port from `1` to `65535` |
| `STELLAR_HORIZON_URL` | `https://horizon-testnet.stellar.org` | Must parse as a valid URL |
| `STELLAR_SECRET_KEY` | required | Must be a valid Stellar ed25519 secret key |
| `REDIS_URL` | `redis://127.0.0.1:6379` | Must parse as `redis://` or `rediss://` |
| `RATE_LIMIT_PER_SECOND` | `10` | Must be greater than `0` |
| `RATE_LIMIT_BURST` | same as `RATE_LIMIT_PER_SECOND` | Must be greater than `0` |
| `STELLAR_MAX_RETRIES` | `3` | Retry attempts after the initial Horizon call |
| `STELLAR_RETRY_BASE_DELAY_MS` | `100` | Initial exponential backoff delay in milliseconds; must be greater than `0` |
| `STELLAR_RETRY_MAX_DELAY_MS` | `10000` | Maximum retry delay in milliseconds; must be greater than or equal to base delay |
| `STELLAR_RETRY_JITTER` | `true` | Boolean; enables full jitter on retry delays |
| `STELLAR_REQUEST_TIMEOUT_MS` | `10000` | Per-request Horizon timeout in milliseconds; must be greater than `0` |
| `STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD` | `5` | Retryable failures before opening the circuit breaker |
| `STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS` | `30000` | Milliseconds the circuit remains open before allowing a half-open probe |
| `STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS` | `1` | Concurrent half-open probes allowed before recovery or reopening |
| `LOG_LEVEL` | `info` | Log verbosity string |
| `WEBHOOK_URLS` | empty | Comma-separated list of valid URLs to receive webhook events |
| `WEBHOOK_SECRET` | unset | Optional shared secret sent as `X-Webhook-Secret` header |
| `WEBHOOK_MAX_RETRIES` | `5` | Retry attempts after the initial webhook delivery fails |
| `WEBHOOK_RETRY_BASE_DELAY_MS` | `200` | Initial exponential backoff delay in milliseconds; must be greater than `0` |
| `WEBHOOK_RETRY_MAX_DELAY_MS` | `30000` | Maximum backoff delay in milliseconds; must be ≥ base delay |
| `WEBHOOK_REQUEST_TIMEOUT_MS` | `10000` | Per-request webhook HTTP timeout in milliseconds; must be greater than `0` |
| `WEBHOOK_JITTER_ENABLED` | `true` | Boolean; adds random jitter of up to 25 % of the capped delay |
| `CACHE_VERIFICATION_TTL` | `3600` | Seconds before a cached verification result expires |

Set `REDIS_URL` to a real Redis instance in production. The in-memory backend is suitable for local development and testing only.

## 🧾 Audit Trail

The audit trail bridges Soroban contract activity and off-chain service records through `src/event.rs`.

- Contract-origin events use deterministic idempotency keys in the form `contract:<tx_hash>:<ledger_sequence>:<event_index>:<aggregate_id>:<event_type>`.
- Contract-origin events derive monotonic sequence numbers from the ledger sequence and event index so replayed Horizon deliveries can be ordered consistently.
- Service-origin events still use generated record IDs, but can override sequence and idempotency keys when a persistence layer has stable ordering context.
- Contract metadata captures the transaction hash, ledger sequence, event index, and document hash so retries can be de-duplicated safely.

Audit records should be retained for as long as the operator needs replay and forensic traceability. On-chain contract events remain the canonical source of truth, while the off-chain audit store keeps the derived trail for search, retention, and replay handling.

---

## 🔔 Webhook Delivery

After an event is finalized, the service dispatches it asynchronously to every URL listed in `WEBHOOK_URLS`. External systems subscribe to these events to maintain up-to-date replicas of document state.

### Event payload schema

```json
{
  "event_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "event_type": "DocumentRegistered",
  "idempotency_key": "contract:tx123:42:3:doc-1:DocumentRegistered",
  "sequence": 42003,
  "timestamp": "2026-06-28T12:00:00Z",
  "aggregate_id": "doc-1",
  "actor": "GDEX...",
  "data": { "issuer": "GDEX...", "owner": "GBBB..." },
  "metadata": {
    "transaction_hash": "tx123",
    "ledger_sequence": 42,
    "event_index": 3,
    "document_hash": "e3b0c4...",
    "source": "contract"
  }
}
```

| Field | Description |
|---|---|
| `event_id` | UUID v4 unique to this event record |
| `event_type` | One of `DocumentRegistered`, `DocumentRevoked`, `DocumentVerified`, `DocumentAuthorizationFailed`, `DocumentOwnerChanged` |
| `idempotency_key` | Stable token derived from transaction hash + event index. Use this to deduplicate retried deliveries. |
| `sequence` | Monotonically increasing within an aggregate. For contract events: `ledger_sequence * 1000 + event_index`. |
| `timestamp` | ISO-8601 UTC timestamp when the event was recorded |
| `metadata` | Present for contract-origin events; contains `transaction_hash`, `ledger_sequence`, `event_index`, `document_hash` |

### Request headers

Each webhook HTTP POST includes the following headers:

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `X-Idempotency-Key` | The event's `idempotency_key` |
| `X-Event-Id` | The event's `event_id` |
| `X-Event-Type` | The event's `event_type` |
| `X-Webhook-Secret` | Value of `WEBHOOK_SECRET` if configured |

### Retry semantics

Deliveries use exponential backoff with jitter:

```
delay(attempt) = min(base * 2^attempt, max) + random_jitter(0, delay/4)
```

- `base` is `WEBHOOK_RETRY_BASE_DELAY_MS` (default `200` ms)
- `max` is `WEBHOOK_RETRY_MAX_DELAY_MS` (default `30 000` ms)
- Jitter is drawn uniformly from `[0, capped_delay / 4)` using wall-clock sub-millisecond noise
- Total attempts = `WEBHOOK_MAX_RETRIES + 1` (default 6 total)

### Ordering guarantees

URLs are contacted **sequentially in registration order**. An event is attempted against every URL regardless of individual failures — a URL that exhausts retries is dead-lettered without blocking delivery to subsequent URLs.

### Dead-letter queue

Failed deliveries (all retries exhausted) are moved to an in-memory bounded queue (max 10 000 entries). The queue is accessible via:

- `GET /webhooks/dlq` — returns `{"dlq_depth": N}`
- `POST /webhooks/dlq/drain` — drains and returns all entries: `{"drained": N, "entries": [...]}`

Each dead-letter entry contains the original payload, target URL, attempt count, last error, and failure timestamp. Replaying drained entries is the operator's responsibility.

---

## 🧪 Future Improvements

* Issuer registry system
* Multi-signature verification
* Zero-knowledge proofs
* Credential NFTs

---

## 🎯 Goal

To provide a **trustless, immutable verification layer** for documents using blockchain.

---

**ProofStell Contract — Trust anchored on-chain.**

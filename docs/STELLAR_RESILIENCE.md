# Stellar Client Circuit Breaker Recovery Runbook

## Overview

The Stellar client implements a circuit breaker pattern to protect against cascading failures when the Horizon API is degraded. This runbook documents the recovery procedure, state transitions, and operational metrics.

## Circuit Breaker States

| State | Description | Behavior |
|-------|-------------|----------|
| `Closed` | Normal operation | All requests pass through |
| `Open` | Failure threshold exceeded | All requests are rejected with `CircuitOpen` error |
| `HalfOpen` | Recovery probe phase | Limited concurrent requests allowed to test recovery |

## State Transitions

```
Closed ──(failure_threshold exceeded)──► Open
   ▲                                       │
   │                                       │
   └────(half_open_max_calls successes)────┘
                   │
                   ▼
              HalfOpen
                   │
                   ├──(success)──► stays HalfOpen until max_calls reached
                   │
                   └──(failure)──► Open
```

## Recovery Procedure

### Automatic Recovery

1. **Detection**: The circuit breaker trips to `Open` after `failure_threshold` consecutive failures.
2. **Wait**: The circuit stays `Open` for `open_duration` (default: 30s).
3. **Probe**: After `open_duration`, the circuit transitions to `HalfOpen`.
4. **Test**: Up to `half_open_max_calls` (default: 1) concurrent probe requests are allowed.
5. **Close**: If all probes succeed, the circuit returns to `Closed`.
6. **Reopen**: If any probe fails, the circuit returns to `Open` and the cycle repeats.

### Manual Recovery

If automatic recovery is not desired or is stuck:

1. **Check Metrics**: Inspect `circuit_breaker_state` and `circuit_breaker_transitions_total` Prometheus metrics.
2. **Verify Horizon**: Confirm Horizon API health via `GET /health` or direct probe.
3. **Restart Service**: Restarting the service resets the circuit breaker to `Closed`.
4. **Hot Reload**: Use `POST /config/reload` to apply new circuit breaker settings without restart.

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `STELLAR_CIRCUIT_BREAKER_FAILURE_THRESHOLD` | `5` | Failures before opening |
| `STELLAR_CIRCUIT_BREAKER_OPEN_DURATION_MS` | `30000` | Duration circuit stays open |
| `STELLAR_CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS` | `1` | Max concurrent probes in half-open |
| `STELLAR_RETRY_JITTER_TYPE` | `full` | Jitter strategy: `none`, `full`, `equal`, `decorrelated` |
| `STELLAR_BULKHEAD_MAX_CONCURRENT` | `10` | Max concurrent Stellar requests |
| `STELLAR_BULKHEAD_MAX_QUEUE` | `100` | Max queued requests when bulkhead is full |

## Metrics

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `circuit_breaker_state` | Gauge | Current state (0=closed, 1=open, 2=half_open) |
| `circuit_breaker_transitions_total{to_state}` | Counter | State transitions by target |
| `circuit_breaker_state_changes_total{from_state,to_state}` | Counter | State changes with source and target |
| `stellar_circuit_breaker_trips_total` | Counter | Times circuit opened |
| `stellar_circuit_breaker_recoveries_total` | Counter | Times circuit recovered to closed |
| `stellar_circuit_breaker_rejected_calls_total` | Counter | Calls rejected while open |
| `stellar_circuit_breaker_half_open_successes_total` | Counter | Successful half-open probes |
| `stellar_circuit_breaker_half_open_failures_total` | Counter | Failed half-open probes |
| `stellar_circuit_breaker_timeout_calls_total` | Counter | Timeout errors recorded |
| `stellar_circuit_breaker_retryable_http_calls_total` | Counter | Retryable HTTP errors recorded |

### Programmatic Access

```rust
let metrics = client.circuit_breaker_metrics();
println!("trips: {}", metrics.trips);
println!("recoveries: {}", metrics.recoveries);
println!("half_open_successes: {}", metrics.half_open_successes);
println!("half_open_failures: {}", metrics.half_open_failures);
println!("rejected_calls: {}", metrics.rejected_calls);
println!("timeout_calls: {}", metrics.timeout_calls);
println!("retryable_http_calls: {}", metrics.retryable_http_calls);
```

## Chaos Testing

The circuit breaker is designed to be chaos-monkey compatible:

1. **Inject Failures**: Use a proxy to return 503 for a subset of requests.
2. **Verify Trip**: After `failure_threshold` failures, confirm circuit opens.
3. **Verify Rejection**: Confirm subsequent calls return `CircuitOpen` error.
4. **Verify Recovery**: After `open_duration`, confirm half-open probes succeed.
5. **Verify Close**: Confirm circuit returns to `Closed` after successful probes.

## Graceful Degradation

When the bulkhead is saturated:

1. **Stale Cache Fallback**: If `graceful_degradation.stale_cache_ok` is enabled, return cached verification results.
2. **Network Error**: If no cache is available, return `VerificationStatus::NetworkError`.
3. **Metrics**: Bulkhead saturation is tracked via `rejected_calls` metric.

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|--------------|------------|
| Circuit stays open | Horizon is down | Wait for `open_duration` or restart |
| Frequent trips | Threshold too low | Increase `failure_threshold` |
| Slow recovery | `half_open_max_calls` too high | Reduce to 1 for faster probing |
| High latency | Retry backoff too aggressive | Reduce `base_delay` or disable jitter |
| Bulkhead saturated | Too many concurrent requests | Increase `max_concurrent` or add queue |

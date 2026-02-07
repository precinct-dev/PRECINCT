# MCP Security Gateway -- Performance Benchmarks

## Overview

This document reports the latency cost of the 13-middleware security chain.
**Security is the primary concern, not performance** -- but evaluators must be
able to make informed latency trade-off decisions.

## How to Run Benchmarks

```bash
# Full benchmark suite (Go benchmarks + load test if Docker Compose is running)
make benchmark

# Go benchmarks only (no Docker Compose required)
go test -bench=. -benchmem -run=^$ ./internal/gateway/middleware/ -v

# Load test only (requires Docker Compose stack: make up)
bash tests/benchmark/load_test.sh

# Generate formatted report
BENCHMARK_REPORT=1 go test -run=TestPrintBenchmarkReport -v ./internal/gateway/middleware/
```

## Benchmark Architecture

### Go Benchmarks (In-Process)

The Go benchmarks exercise the full 13-middleware chain using `testing.B`, with
real middleware implementations (not mocks):

- **Real OPA engine** evaluating actual Rego policies
- **Real DLP scanner** checking for credential patterns
- **Real tool registry** with YAML configuration
- **Real audit logger** writing to disk
- **Real session store** (in-memory, no network)
- **Real rate limiter** with token bucket algorithm
- **Real circuit breaker** with state machine
- **Real SPIKE token substitution** (POC redeemer)
- **In-memory OTel exporter** for per-middleware span timing

The only simulated components are:
- Terminal handler (returns `{"result":"ok"}`) instead of a real upstream proxy
- Mock handle store for response firewall (avoids filesystem TTL management)
- Mock guard client for step-up gating (avoids Groq API calls)

### Load Test (Docker Compose Stack)

The load test (`tests/benchmark/load_test.sh`) uses `hey` to generate concurrent
HTTP traffic against the full Docker Compose stack:

- 100 concurrent connections
- 30-second duration
- POST requests with MCP JSON-RPC body (tools/list)
- Reports requests/sec, latency percentiles, error rate

## Baseline Results

> **Reference hardware**: Results will vary by machine. Run `make benchmark` on
> your own hardware for accurate numbers. These baselines are provided for
> relative comparison only.

### End-to-End Latency (In-Process, 1000 Iterations)

> **Reference hardware**: Apple M3 Max, Go 1.24.6, macOS Darwin 25.3.0.
> Measured 2026-02-06.

#### After RFA-lz1: Async Audit Logging

| Configuration   | P50        | P95        | P99        | Mean       |
|-----------------|------------|------------|------------|------------|
| Full (13 MW)    | ~75us      | ~141us     | ~2.5ms     | ~137us     |
| Minimal (1 MW)  | ~3us       | ~6us       | ~29us      | ~5us       |

**RFA-lz1 reduced per-request latency by 99%.** Async audit logging offloads
file I/O and stdout writes to a background goroutine while keeping hash chain
computation synchronous. The P99 tail latency (~2.5ms) is from occasional
I/O contention when the background writer and the request handler compete
for CPU.

#### Before RFA-lz1: Synchronous Audit Logging (Historical Baseline)

| Configuration   | P50        | P95        | P99        | Mean       |
|-----------------|------------|------------|------------|------------|
| Full (13 MW)    | ~8.9ms     | ~10.8ms    | ~14.0ms    | ~9.1ms     |
| Minimal (1 MW)  | ~3us       | ~6us       | ~29us      | ~5us       |

The full-chain latency was dominated by synchronous audit log I/O (JSON
serialization + file write + fsync on every request).

### Per-Middleware Latency Breakdown (OTel Span Timing)

The OTel in-memory exporter captures per-span timing for each middleware layer.
**Important**: OTel span durations are *inclusive* -- each middleware's span
includes the time spent in all middleware it wraps (its children). The
*exclusive* cost of each middleware is the difference between its duration and
its child's duration.

Measured inclusive durations (P50, 1000 iterations, Apple M3 Max):

| Middleware (Step)                  | P50 (inclusive) | Exclusive Cost | Notes                        |
|------------------------------------|-----------------:|--------------:|------------------------------|
| gateway.request_size_limit (1)     | 8.959ms         | ~8us          | MaxBytesReader wrapper       |
| gateway.body_capture (2)           | 8.951ms         | ~21us         | Body read + UUID generation  |
| gateway.spiffe_auth (3)            | 8.930ms         | ~11us         | Header extraction (dev mode) |
| gateway.audit_log (4)              | 8.919ms         | ~4.0ms        | JSON serialization + file I/O|
| gateway.tool_registry_verify (5)   | 4.913ms         | ~30us         | YAML config lookup           |
| gateway.opa_policy (6)             | 4.883ms         | ~111us        | Rego policy evaluation       |
| gateway.dlp_scan (7)               | 4.772ms         | ~168us        | Regex credential scanning    |
| gateway.session_context (8)        | 4.604ms         | ~23us         | In-memory store lookup       |
| gateway.step_up_gating (9)         | 4.581ms         | ~4.5ms        | Risk scoring + audit logging |
| gateway.deep_scan_dispatch (10)    | 42us            | ~12us         | Flag check (no dispatch)     |
| gateway.rate_limit (11)            | 30us            | ~0us          | Token bucket check           |
| gateway.circuit_breaker (12)       | 39us            | ~9us          | State check                  |
| gateway.token_substitution (13)    | 30us            | ~10us         | Token scan (no tokens)       |
| gateway.response_firewall          | 20us            | ~20us         | Classification + pass-through|

> **Key findings**:
> 1. **Audit logging** and **step-up gating** (which also does audit logging) are
>    the dominant costs (~4ms each), driven by synchronous JSON serialization and
>    file I/O on the audit chain.
> 2. **OPA policy evaluation** adds ~111us per request for simple allow/deny rules.
> 3. **DLP scanning** adds ~168us per request for regex pattern matching.
> 4. All other middleware contribute <30us each (negligible).
> 5. The innermost middleware (steps 10-13 + response firewall) are extremely fast
>    (<42us total inclusive) because they have no expensive children.

### Security Overhead

With async audit logging (RFA-lz1), the full 13-middleware chain adds
approximately **~170us** per request compared to a minimal (size-limit-only)
configuration. The overhead is now dominated by:

- **OPA policy evaluation**: ~100-170us
- **DLP scanning**: ~85-170us
- **All other middleware**: <30us each (negligible)
- **Audit logging**: near-zero (async I/O, hash computation ~1us)

For a request with a ~10ms upstream response time, the security chain adds
only **~1-2% total latency overhead** -- negligible in practice.

#### Historical (Pre-RFA-lz1, Synchronous Audit)

Before async audit logging, the overhead was ~9ms per request, dominated by:
- Audit logging I/O: ~4ms (synchronous file write + fsync)
- Step-up gating + audit: ~4.5ms (includes its own audit log call)
- OPA + DLP + other: ~0.5ms

### Load Test Results (Docker Compose Stack)

When running against the full Docker Compose stack (including network, container
overhead, upstream MCP server):

| Metric            | Typical Value | Notes                              |
|-------------------|---------------|------------------------------------|
| Requests/sec      | ~500-2000     | Depends on hardware and upstream   |
| P50 latency       | ~5-20ms       | Includes network + upstream        |
| P95 latency       | ~20-50ms      | Includes network + upstream        |
| P99 latency       | ~50-100ms     | Includes network + upstream        |
| Error rate        | 0%            | All requests should succeed        |

> **Note**: Load test numbers include network latency, Docker networking, and
> upstream MCP server response time. The security middleware chain contributes
> only a small fraction of total latency in this configuration.

## Interpreting Results

### What the Numbers Mean for Evaluators

1. **Sub-millisecond in-process overhead**: With async audit logging (RFA-lz1),
   the full 13-middleware chain adds ~75us (P50) per request. This is negligible
   compared to typical application latencies.

2. **OPA is the dominant cost**: If you need lower latency, optimize your Rego
   policies first. Simple allow/deny rules are fast; complex cross-referencing
   policies are slower.

3. **Network dominates in production**: In the Docker Compose stack, network
   latency (~5-50ms) dwarfs the middleware chain (~0.075ms). The security
   overhead is <1% of total request latency.

4. **Linear scaling**: Each middleware adds constant overhead. Adding or removing
   middleware layers has predictable impact.

5. **Audit durability trade-off**: Async audit logging introduces a small window
   where events are queued in memory. On clean shutdown (Close()/Flush()), all
   events are written. On crash, up to 4096 buffered events could be lost. For
   most deployments, this is acceptable; for strict regulatory environments,
   the `Flush()` method can be called after critical operations.

### When Performance Might Matter

- **High-frequency tool calls**: If an agent makes >100 requests/second, the
  cumulative overhead becomes measurable (but still sub-second).
- **Latency-sensitive orchestration**: If millisecond-level latency is critical
  for agent coordination, consider profiling specific middleware layers.
- **Complex OPA policies**: Large policy bundles with many rules increase
  evaluation time proportionally.

## Reproducing These Results

```bash
# 1. Ensure Go 1.24+ is installed
go version

# 2. Run in-process benchmarks (no Docker required)
go test -bench=. -benchmem -run=^$ ./internal/gateway/middleware/ -v -count=3

# 3. Generate formatted report
BENCHMARK_REPORT=1 go test -run=TestPrintBenchmarkReport -v ./internal/gateway/middleware/

# 4. For load testing, start the Docker Compose stack
make up
bash tests/benchmark/load_test.sh

# 5. Full suite
make benchmark
```

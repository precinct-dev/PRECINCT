---
id: oc-4sr
title: "GAP-3: Add OTel application metrics for key operational signals"
status: closed
priority: 1
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T03:23:02Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:46Z
content_hash: "sha256:2da848705213fb2f1c0b3c778310cde0121b1e26b5037f86c9c8eac1331a0d76"
closed_at: 2026-02-21T10:14:13Z
close_reason: "DELIVERED: All 8 ACs met. 6 OTel metric instruments wired into middleware chain with unit + integration tests passing. go.opentelemetry.io/otel/metric promoted to direct dependency."
blocked_by: [oc-kxh, oc-vh5]
---

## Description
WHAT: Create a new internal/gateway/metrics/ package that defines and registers OTel application metrics for the gateway's key operational signals. Wire these metrics into the existing middleware chain. The gateway currently has 91 OTel trace spans but zero application-defined metrics.

WHY: Without metrics, operators cannot monitor request rates, denial rates by middleware, DLP hit rates, rate limiter saturation, circuit breaker state, or deep scan latency. Traces alone are insufficient for dashboards and alerting. OTel metrics are the standard for cloud-native observability. The metric SDK (go.opentelemetry.io/otel/metric v1.40.0) is already an indirect dependency -- it just needs to be promoted to direct and used.

HOW:

1. Create internal/gateway/metrics/metrics.go:
   - Define a Metrics struct that holds all the meter instruments
   - Create a constructor NewMetrics(meter metric.Meter) *Metrics
   - The meter will come from the global OTel MeterProvider, similar to how tracing uses otel.Tracer()
   - Define these instruments:
     a. request_total (Int64Counter): Total requests, attributes: method, path, status_code, spiffe_id
     b. denial_total (Int64Counter): Requests denied by middleware, attributes: middleware (opa|dlp|rate_limit|deep_scan|spiffe|circuit_breaker), reason, spiffe_id
     c. rate_limiter_utilization (Float64Gauge): Current rate limiter utilization as fraction 0.0-1.0, attributes: spiffe_id, limiter_name
     d. circuit_breaker_state (Int64Gauge): Circuit breaker state as int (0=closed, 1=half-open, 2=open), attributes: circuit_name
     e. deep_scan_latency_ms (Float64Histogram): Deep scan call latency in milliseconds, attributes: model, outcome (allowed|blocked|error)
     f. dlp_findings_total (Int64Counter): DLP pattern matches, attributes: pattern_name, action (redact|block)

2. Create internal/gateway/metrics/provider.go:
   - Define InitMeterProvider() that sets up the OTel MeterProvider
   - Use OTLP gRPC exporter (go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc) to match the existing trace exporter pattern
   - If OTEL_EXPORTER_OTLP_ENDPOINT is empty, use a no-op provider (same pattern as tracing)
   - Register the provider as global: otel.SetMeterProvider(provider)

3. Wire metrics into middleware:
   - In internal/gateway/middleware/otel.go: add a package-level meter variable similar to the existing tracer variable: var meter = otel.Meter('mcp-security-gateway')
   - In the middleware functions, record metrics at decision points:
     * OPA middleware (opa.go): increment denial_total on deny
     * DLP middleware (dlp.go): increment dlp_findings_total on pattern match, increment denial_total on block
     * Rate limiter (rate_limiter.go): increment denial_total on rate limit hit, record rate_limiter_utilization
     * Circuit breaker (circuit_breaker.go): record circuit_breaker_state on state transitions, increment denial_total on open
     * Deep scan (deep_scan.go): record deep_scan_latency_ms histogram after scan completes
     * Gateway request handler: increment request_total after response is written (wrap ResponseWriter to capture status code)

4. Promote go.opentelemetry.io/otel/metric from indirect to direct dependency:
   - Run: go get go.opentelemetry.io/otel/metric@v1.40.0
   - Add OTLP metric exporter: go get go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc
   - Add metric SDK: go get go.opentelemetry.io/otel/sdk/metric

TECHNICAL CONTEXT:
- OTel tracing is already configured in cmd/gateway/main.go (or equivalent) using OTLP gRPC exporter to OTEL_EXPORTER_OTLP_ENDPOINT
- The middleware package already has a tracer variable in otel.go (line 12): var tracer = otel.Tracer('mcp-security-gateway')
- Each middleware function receives an http.Handler and returns an http.Handler -- metrics recording happens inside the middleware wrapper
- The existing pattern: middleware functions are in individual files (opa.go, dlp.go, rate_limiter.go, etc.) and are chained in gateway.go around line 441
- OTel metric SDK uses Int64Counter, Float64Histogram, Float64Gauge etc. from go.opentelemetry.io/otel/metric

FILES TO MODIFY:
- CREATE: internal/gateway/metrics/metrics.go (metric instrument definitions)
- CREATE: internal/gateway/metrics/provider.go (MeterProvider initialization)
- MODIFY: internal/gateway/middleware/otel.go (add meter variable)
- MODIFY: internal/gateway/middleware/opa.go (record denial_total on deny)
- MODIFY: internal/gateway/middleware/dlp.go (record dlp_findings_total, denial_total)
- MODIFY: internal/gateway/middleware/rate_limiter.go (record rate_limiter_utilization, denial_total)
- MODIFY: internal/gateway/middleware/circuit_breaker.go (record circuit_breaker_state, denial_total)
- MODIFY: internal/gateway/middleware/deep_scan.go (record deep_scan_latency_ms)
- MODIFY: internal/gateway/gateway.go (record request_total, initialize metrics, pass to middleware)
- MODIFY: go.mod (promote metric dependency to direct)

TESTING REQUIREMENTS:
- Unit test: In internal/gateway/metrics/metrics_test.go, verify that NewMetrics() creates all instruments without error using a test MeterProvider (sdkmetric.NewMeterProvider with a ManualReader). Verify that recording a metric does not panic.
- Integration test: In tests/integration/, create a test that sends requests through the gateway (using httptest), triggers a denial (e.g., missing SPIFFE ID), and verifies that the OTel ManualReader captures the expected metric data points (request_total incremented, denial_total incremented with correct middleware attribute).
- Verify: 'go test -race ./...' passes
- Verify: The metrics package compiles and instruments are created at startup

MANDATORY SKILLS TO REVIEW:
- None identified. OTel Go metric SDK is well-documented at https://opentelemetry.io/docs/languages/go/instrumentation/`#metrics`

## Acceptance Criteria
AC1: internal/gateway/metrics/metrics.go defines at least 6 metric instruments: request_total, denial_total, rate_limiter_utilization, circuit_breaker_state, deep_scan_latency_ms, dlp_findings_total
AC2: internal/gateway/metrics/provider.go initializes MeterProvider with OTLP gRPC exporter (or no-op when endpoint not set)
AC3: OPA, DLP, rate limiter, circuit breaker, and deep scan middleware record metrics at decision points
AC4: request_total counter incremented in the gateway request handler with method, path, and status_code attributes
AC5: go.opentelemetry.io/otel/metric promoted to direct dependency in go.mod
AC6: Unit tests verify metric instrument creation and recording without panic
AC7: Integration test verifies metrics are captured when requests are processed through the middleware chain
AC8: 'go test -race ./...' passes with zero failures

## Design


## Notes


## History
- 2026-03-08T02:10:22Z dep_added: blocked_by oc-vh5

## Links
- Blocked by: [[oc-kxh]], [[oc-vh5]]

## Comments

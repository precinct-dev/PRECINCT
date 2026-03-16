// Benchmark tests for the 13-middleware security chain (RFA-lo1.2).
//
// These benchmarks measure the latency cost of the complete security middleware
// chain. Security is the primary concern, not performance -- but evaluators
// must be able to make informed latency trade-off decisions.
//
// Run with: go test -bench=. -benchmem -run=^$ ./internal/gateway/middleware/
// Or:       make benchmark
package middleware

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// buildFullMiddlewareChain constructs the 13-middleware chain identical to
// gateway.go Handler(), using real middleware implementations with minimal
// configuration for benchmarking.
//
// Returns the handler and a cleanup function.
func buildFullMiddlewareChain(b *testing.B) (http.Handler, func()) {
	b.Helper()

	tmpDir := b.TempDir()

	// Create minimal config files for middleware that need them
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "tools.yaml")
	opaDir := filepath.Join(tmpDir, "opa")
	_ = os.MkdirAll(opaDir, 0755)

	_ = os.WriteFile(bundlePath, []byte(`package test
default allow = false
`), 0644)

	// OPA engine reads from a directory -- write policy to opaDir
	_ = os.WriteFile(filepath.Join(opaDir, "mcp_policy.rego"), []byte(`package mcp
default allow := false
allow if { input.tool == "file_read" }
allow if { input.tool == "tools/list" }
`), 0644)

	_ = os.WriteFile(registryPath, []byte(`tools:
  - name: "file_read"
    description: "Read file contents"
    hash: "abc123"
    risk_level: "low"
`), 0644)

	// Create real middleware components
	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		b.Fatalf("Failed to create auditor: %v", err)
	}

	opaEngine, err := NewOPAEngine(opaDir, OPAEngineConfig{})
	if err != nil {
		b.Fatalf("Failed to create OPA engine: %v", err)
	}

	registry, err := NewToolRegistry(registryPath)
	if err != nil {
		b.Fatalf("Failed to create tool registry: %v", err)
	}

	dlpScanner := NewBuiltInScanner()

	deepScanner := NewDeepScannerWithConfig(DeepScannerConfig{
		APIKey:       "",
		Timeout:      5 * time.Second,
		FallbackMode: "fail_open",
	})
	// Start deep scan result processor (mirrors gateway.go)
	go deepScanner.ResultProcessor(context.Background())

	sessionStore := NewInMemoryStore()
	sessionContext := NewSessionContext(sessionStore)

	rateLimitStore := NewInMemoryRateLimitStore()
	// Use very high rate limit for benchmarks to avoid 429 during rapid iteration.
	// 1,000,000 RPM with 100,000 burst ensures benchmarks never hit rate limits.
	rateLimiter := NewRateLimiter(1000000, 100000, rateLimitStore)

	circuitBreaker := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 5,
		ResetTimeout:     30 * time.Second,
		SuccessThreshold: 2,
	}, nil)

	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}
	allowlist := defaultAllowlist()
	riskConfig := defaultRiskConfig()

	spikeRedeemer := NewPOCSecretRedeemer()
	handleStore := newMockHandleStore()

	// Terminal handler (simulates response from upstream proxy)
	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	})

	// Build chain identical to gateway.go Handler() (steps 14-15: response firewall + proxy)
	handler := ResponseFirewall(terminal, registry, handleStore, 300)

	// Apply middleware in reverse order (innermost first) -- same as gateway.go
	handler = TokenSubstitution(handler, spikeRedeemer, auditor, nil)                      // 13
	handler = CircuitBreakerMiddleware(handler, circuitBreaker)                            // 12
	handler = RateLimitMiddleware(handler, rateLimiter)                                    // 11
	handler = DeepScanMiddleware(handler, deepScanner, riskConfig)                         // 10
	handler = StepUpGating(handler, guardClient, allowlist, riskConfig, registry, auditor) // 9
	handler = SessionContextMiddleware(handler, sessionContext)                            // 8
	handler = DLPMiddleware(handler, dlpScanner)                                           // 7
	handler = OPAPolicy(handler, opaEngine)                                                // 6
	handler = ToolRegistryVerify(handler, registry, nil, nil)                              // 5
	handler = AuditLog(handler, auditor)                                                   // 4
	handler = SPIFFEAuth(handler, "dev")                                                   // 3
	handler = BodyCapture(handler)                                                         // 2
	handler = RequestSizeLimit(handler, 1024*1024)                                         // 1

	cleanup := func() {
		_ = auditor.Close()
		_ = opaEngine.Close()
	}

	return handler, cleanup
}

// buildMinimalChain creates a minimal chain with only size limit + proxy
// for comparison benchmarks.
func buildMinimalChain(b *testing.B) http.Handler {
	b.Helper()

	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	})

	// Minimal chain: only size limit + terminal
	handler := RequestSizeLimit(terminal, 1024*1024)
	return handler
}

// makeValidRequest creates a valid MCP JSON-RPC request with required headers.
func makeValidRequest() *http.Request {
	body := []byte(`{"jsonrpc":"2.0","method":"file_read","params":{"tool":"file_read"},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/benchmark/dev")
	return req
}

// BenchmarkFullMiddlewareChain measures end-to-end latency through all 13
// middleware layers plus response firewall and terminal handler.
//
// This is the primary benchmark for evaluating security chain cost.
func BenchmarkFullMiddlewareChain(b *testing.B) {
	handler, cleanup := buildFullMiddlewareChain(b)
	defer cleanup()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := makeValidRequest()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("Expected 200, got %d", rec.Code)
		}
	}
}

// BenchmarkMinimalChain measures latency through only the size limit
// middleware + terminal handler, establishing a baseline for comparison.
func BenchmarkMinimalChain(b *testing.B) {
	handler := buildMinimalChain(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		body := []byte(`{"jsonrpc":"2.0","method":"file_read","params":{},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("Expected 200, got %d", rec.Code)
		}
	}
}

// BenchmarkPerMiddlewareLatency measures per-middleware latency using OTel
// span timing. This uses an in-memory exporter (per story insight 3) to
// capture span durations without network overhead.
//
// Per story insight 2: reassign the package-level tracer in setup.
func BenchmarkPerMiddlewareLatency(b *testing.B) {
	// Set up in-memory OTel exporter for span capture
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter), // synchronous for deterministic capture
	)
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	// Per story insight 2: reassign the package-level tracer
	tracer = tp.Tracer("precinct-gateway")

	defer func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
		// Restore default tracer
		tracer = otel.Tracer("precinct-gateway")
	}()

	handler, cleanup := buildFullMiddlewareChain(b)
	defer cleanup()

	// Run N iterations and collect span durations
	const iterations = 100
	// Map from span name to list of durations
	spanDurations := make(map[string][]time.Duration)

	for i := 0; i < iterations; i++ {
		exporter.Reset()
		req := makeValidRequest()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("Iteration %d: Expected 200, got %d", i, rec.Code)
		}

		spans := exporter.GetSpans()
		for _, s := range spans {
			dur := s.EndTime.Sub(s.StartTime)
			spanDurations[s.Name] = append(spanDurations[s.Name], dur)
		}
	}

	// Report per-middleware latency with percentiles
	b.Logf("\n=== Per-Middleware Latency Breakdown (%d iterations) ===", iterations)
	b.Logf("%-35s %10s %10s %10s %10s", "Middleware", "P50", "P95", "P99", "Mean")
	b.Logf("%-35s %10s %10s %10s %10s", "---------", "---", "---", "---", "----")

	// Ordered list matching middleware chain execution order
	middlewareOrder := []string{
		"gateway.request_size_limit",
		"gateway.body_capture",
		"gateway.spiffe_auth",
		"gateway.audit_log",
		"gateway.tool_registry_verify",
		"gateway.opa_policy",
		"gateway.dlp_scan",
		"gateway.session_context",
		"gateway.step_up_gating",
		"gateway.deep_scan_dispatch",
		"gateway.rate_limit",
		"gateway.circuit_breaker",
		"gateway.token_substitution",
		"gateway.response_firewall",
	}

	for _, name := range middlewareOrder {
		durations, ok := spanDurations[name]
		if !ok {
			b.Logf("%-35s %10s %10s %10s %10s", name, "N/A", "N/A", "N/A", "N/A")
			continue
		}
		p50, p95, p99, mean := computePercentiles(durations)
		b.Logf("%-35s %10s %10s %10s %10s", name,
			p50.Truncate(time.Microsecond),
			p95.Truncate(time.Microsecond),
			p99.Truncate(time.Microsecond),
			mean.Truncate(time.Microsecond),
		)
	}

	// Also report any spans not in the ordered list
	for name, durations := range spanDurations {
		found := false
		for _, ordered := range middlewareOrder {
			if name == ordered {
				found = true
				break
			}
		}
		if !found {
			p50, p95, p99, mean := computePercentiles(durations)
			b.Logf("%-35s %10s %10s %10s %10s", name+" (extra)",
				p50.Truncate(time.Microsecond),
				p95.Truncate(time.Microsecond),
				p99.Truncate(time.Microsecond),
				mean.Truncate(time.Microsecond),
			)
		}
	}
}

// BenchmarkLatencyPercentiles runs the full chain many times and reports
// P50/P95/P99 end-to-end latency.
func BenchmarkLatencyPercentiles(b *testing.B) {
	handler, cleanup := buildFullMiddlewareChain(b)
	defer cleanup()

	const iterations = 1000
	durations := make([]time.Duration, 0, iterations)

	// Warm up
	for i := 0; i < 10; i++ {
		req := makeValidRequest()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// Measure
	for i := 0; i < iterations; i++ {
		req := makeValidRequest()
		rec := httptest.NewRecorder()

		start := time.Now()
		handler.ServeHTTP(rec, req)
		durations = append(durations, time.Since(start))

		if rec.Code != http.StatusOK {
			b.Fatalf("Iteration %d: Expected 200, got %d", i, rec.Code)
		}
	}

	p50, p95, p99, mean := computePercentiles(durations)
	b.Logf("\n=== End-to-End Latency (%d requests) ===", iterations)
	b.Logf("P50:  %s", p50.Truncate(time.Microsecond))
	b.Logf("P95:  %s", p95.Truncate(time.Microsecond))
	b.Logf("P99:  %s", p99.Truncate(time.Microsecond))
	b.Logf("Mean: %s", mean.Truncate(time.Microsecond))
}

// BenchmarkCompareFullVsMinimal runs both full and minimal chains for
// side-by-side comparison of security overhead.
func BenchmarkCompareFullVsMinimal(b *testing.B) {
	fullHandler, cleanup := buildFullMiddlewareChain(b)
	defer cleanup()
	minimalHandler := buildMinimalChain(b)

	const iterations = 500

	// Measure full chain
	fullDurations := make([]time.Duration, 0, iterations)
	for i := 0; i < iterations; i++ {
		req := makeValidRequest()
		rec := httptest.NewRecorder()
		start := time.Now()
		fullHandler.ServeHTTP(rec, req)
		fullDurations = append(fullDurations, time.Since(start))
	}

	// Measure minimal chain
	minimalDurations := make([]time.Duration, 0, iterations)
	for i := 0; i < iterations; i++ {
		body := []byte(`{"jsonrpc":"2.0","method":"file_read","params":{},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		rec := httptest.NewRecorder()
		start := time.Now()
		minimalHandler.ServeHTTP(rec, req)
		minimalDurations = append(minimalDurations, time.Since(start))
	}

	fp50, fp95, fp99, fmean := computePercentiles(fullDurations)
	mp50, mp95, mp99, mmean := computePercentiles(minimalDurations)

	b.Logf("\n=== Full Chain vs Minimal Chain (%d iterations) ===", iterations)
	b.Logf("%-15s %12s %12s %12s %12s", "", "P50", "P95", "P99", "Mean")
	b.Logf("%-15s %12s %12s %12s %12s", "Full (13 MW)", fp50.Truncate(time.Microsecond), fp95.Truncate(time.Microsecond), fp99.Truncate(time.Microsecond), fmean.Truncate(time.Microsecond))
	b.Logf("%-15s %12s %12s %12s %12s", "Minimal", mp50.Truncate(time.Microsecond), mp95.Truncate(time.Microsecond), mp99.Truncate(time.Microsecond), mmean.Truncate(time.Microsecond))

	// Calculate overhead
	if mmean > 0 {
		overheadPct := float64(fmean-mmean) / float64(mmean) * 100
		b.Logf("Security overhead: %s additional per request (%.1f%% increase)",
			(fmean - mmean).Truncate(time.Microsecond), overheadPct)
	}
}

// computePercentiles calculates P50, P95, P99, and mean from a list of durations.
func computePercentiles(durations []time.Duration) (p50, p95, p99, mean time.Duration) {
	if len(durations) == 0 {
		return 0, 0, 0, 0
	}

	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	n := len(sorted)
	p50 = sorted[percentileIndex(n, 50)]
	p95 = sorted[percentileIndex(n, 95)]
	p99 = sorted[percentileIndex(n, 99)]

	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	mean = total / time.Duration(n)

	return
}

// percentileIndex returns the index for the given percentile.
func percentileIndex(n, percentile int) int {
	idx := int(math.Ceil(float64(n)*float64(percentile)/100.0)) - 1
	if idx < 0 {
		return 0
	}
	if idx >= n {
		return n - 1
	}
	return idx
}

// TestBenchmarkSanity verifies the benchmark test infrastructure works
// correctly: the full chain processes requests successfully and OTel spans
// are captured for per-middleware breakdown.
func TestBenchmarkSanity(t *testing.T) {
	// Use testing.B adapter for benchmark helpers
	b := &testing.B{}
	_ = b

	// Set up in-memory OTel exporter
	exporter, teardown := setupTestTracer(t)
	defer teardown()

	// Build full chain using the same helpers
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "tools.yaml")
	opaDir := filepath.Join(tmpDir, "opa")
	_ = os.MkdirAll(opaDir, 0755)

	_ = os.WriteFile(bundlePath, []byte(`package test
default allow = false
`), 0644)
	_ = os.WriteFile(filepath.Join(opaDir, "mcp_policy.rego"), []byte(`package mcp
default allow := false
allow if { input.tool == "file_read" }
`), 0644)
	_ = os.WriteFile(registryPath, []byte(`tools:
  - name: "file_read"
    description: "Read file contents"
    hash: "abc123"
    risk_level: "low"
`), 0644)

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer func() {
		_ = auditor.Close()
	}()

	opaEngine, err := NewOPAEngine(opaDir, OPAEngineConfig{})
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer func() {
		_ = opaEngine.Close()
	}()

	registry, err := NewToolRegistry(registryPath)
	if err != nil {
		t.Fatalf("Failed to create tool registry: %v", err)
	}

	dlpScanner := NewBuiltInScanner()
	deepScanner := NewDeepScannerWithConfig(DeepScannerConfig{
		APIKey:       "",
		Timeout:      5 * time.Second,
		FallbackMode: "fail_open",
	})
	go deepScanner.ResultProcessor(context.Background())

	sessionStore := NewInMemoryStore()
	sessionCtx := NewSessionContext(sessionStore)
	rateLimitStore := NewInMemoryRateLimitStore()
	rateLimiter := NewRateLimiter(600, 100, rateLimitStore)
	circuitBreaker := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 5,
		ResetTimeout:     30 * time.Second,
		SuccessThreshold: 2,
	}, nil)
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}
	allowlist := defaultAllowlist()
	riskCfg := defaultRiskConfig()
	spikeRedeemer := NewPOCSecretRedeemer()
	handleStore := newMockHandleStore()

	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	})

	handler := ResponseFirewall(terminal, registry, handleStore, 300)
	handler = TokenSubstitution(handler, spikeRedeemer, auditor, nil)
	handler = CircuitBreakerMiddleware(handler, circuitBreaker)
	handler = RateLimitMiddleware(handler, rateLimiter)
	handler = DeepScanMiddleware(handler, deepScanner, riskCfg)
	handler = StepUpGating(handler, guardClient, allowlist, riskCfg, registry, auditor)
	handler = SessionContextMiddleware(handler, sessionCtx)
	handler = DLPMiddleware(handler, dlpScanner)
	handler = OPAPolicy(handler, opaEngine)
	handler = ToolRegistryVerify(handler, registry, nil, nil)
	handler = AuditLog(handler, auditor)
	handler = SPIFFEAuth(handler, "dev")
	handler = BodyCapture(handler)
	handler = RequestSizeLimit(handler, 1024*1024)

	// Send a request through the full chain
	req := makeValidRequest()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify OTel spans were captured for each middleware
	spans := exporter.GetSpans()
	expectedSpans := []string{
		"gateway.request_size_limit",
		"gateway.body_capture",
		"gateway.spiffe_auth",
		"gateway.audit_log",
		"gateway.tool_registry_verify",
		"gateway.opa_policy",
		"gateway.dlp_scan",
		"gateway.session_context",
		"gateway.step_up_gating",
		"gateway.deep_scan_dispatch",
		"gateway.rate_limit",
		"gateway.circuit_breaker",
		"gateway.token_substitution",
		"gateway.response_firewall",
	}

	t.Logf("Captured %d spans", len(spans))
	for _, name := range expectedSpans {
		s := findSpan(spans, name)
		if s == nil {
			t.Errorf("Missing expected span: %s", name)
		} else {
			dur := s.EndTime.Sub(s.StartTime)
			t.Logf("  %s: %s", name, dur.Truncate(time.Microsecond))
		}
	}

	if len(spans) < len(expectedSpans) {
		t.Errorf("Expected at least %d spans, got %d", len(expectedSpans), len(spans))
		for _, s := range spans {
			t.Logf("  Found span: %s", s.Name)
		}
	}
}

// TestComputePercentiles verifies the percentile calculation is correct.
func TestComputePercentiles(t *testing.T) {
	// 100 values: 1ms, 2ms, ..., 100ms
	durations := make([]time.Duration, 100)
	for i := 0; i < 100; i++ {
		durations[i] = time.Duration(i+1) * time.Millisecond
	}

	p50, p95, p99, mean := computePercentiles(durations)

	// P50 should be ~50ms
	if p50 < 49*time.Millisecond || p50 > 51*time.Millisecond {
		t.Errorf("P50 expected ~50ms, got %s", p50)
	}
	// P95 should be ~95ms
	if p95 < 94*time.Millisecond || p95 > 96*time.Millisecond {
		t.Errorf("P95 expected ~95ms, got %s", p95)
	}
	// P99 should be ~99ms
	if p99 < 98*time.Millisecond || p99 > 100*time.Millisecond {
		t.Errorf("P99 expected ~99ms, got %s", p99)
	}
	// Mean should be ~50.5ms
	if mean < 49*time.Millisecond || mean > 52*time.Millisecond {
		t.Errorf("Mean expected ~50.5ms, got %s", mean)
	}
}

// TestComputePercentilesEmpty verifies edge case: empty input.
func TestComputePercentilesEmpty(t *testing.T) {
	p50, p95, p99, mean := computePercentiles(nil)
	if p50 != 0 || p95 != 0 || p99 != 0 || mean != 0 {
		t.Errorf("Expected all zeros for empty input, got p50=%s p95=%s p99=%s mean=%s",
			p50, p95, p99, mean)
	}
}

// TestComputePercentilesSingle verifies edge case: single value.
func TestComputePercentilesSingle(t *testing.T) {
	durations := []time.Duration{42 * time.Millisecond}
	p50, p95, p99, mean := computePercentiles(durations)
	if p50 != 42*time.Millisecond {
		t.Errorf("P50 expected 42ms, got %s", p50)
	}
	if p95 != 42*time.Millisecond {
		t.Errorf("P95 expected 42ms, got %s", p95)
	}
	if p99 != 42*time.Millisecond {
		t.Errorf("P99 expected 42ms, got %s", p99)
	}
	if mean != 42*time.Millisecond {
		t.Errorf("Mean expected 42ms, got %s", mean)
	}
}

// TestPercentileIndex verifies the index calculation for percentiles.
func TestPercentileIndex(t *testing.T) {
	tests := []struct {
		n, pct, want int
	}{
		{100, 50, 49},
		{100, 95, 94},
		{100, 99, 98},
		{1, 50, 0},
		{1, 99, 0},
		{10, 50, 4},
		{10, 90, 8},
	}
	for _, tc := range tests {
		got := percentileIndex(tc.n, tc.pct)
		if got != tc.want {
			t.Errorf("percentileIndex(%d, %d) = %d, want %d", tc.n, tc.pct, got, tc.want)
		}
	}
}

// PrintBenchmarkReport is a test helper that runs the full chain and prints
// a formatted benchmark report to stdout. This is used by `make benchmark`.
func TestPrintBenchmarkReport(t *testing.T) {
	// Only run when explicitly requested (via make benchmark)
	if os.Getenv("BENCHMARK_REPORT") != "1" {
		t.Skip("Skipping benchmark report: set BENCHMARK_REPORT=1 to generate")
	}

	// Set up in-memory OTel exporter
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	tracer = tp.Tracer("precinct-gateway")

	defer func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
		tracer = otel.Tracer("precinct-gateway")
	}()

	// Build chains -- using a testing.B-like interface via testing.T
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "tools.yaml")
	opaDir := filepath.Join(tmpDir, "opa")
	_ = os.MkdirAll(opaDir, 0755)

	_ = os.WriteFile(bundlePath, []byte(`package test
default allow = false
`), 0644)
	_ = os.WriteFile(filepath.Join(opaDir, "mcp_policy.rego"), []byte(`package mcp
default allow := false
allow if { input.tool == "file_read" }
`), 0644)
	_ = os.WriteFile(registryPath, []byte(`tools:
  - name: "file_read"
    description: "Read file contents"
    hash: "abc123"
    risk_level: "low"
`), 0644)

	auditor, _ := NewAuditor(auditPath, bundlePath, registryPath)
	defer func() {
		_ = auditor.Close()
	}()
	opaEngine, _ := NewOPAEngine(opaDir, OPAEngineConfig{})
	defer func() {
		_ = opaEngine.Close()
	}()
	registry, _ := NewToolRegistry(registryPath)
	dlpScanner := NewBuiltInScanner()
	deepScanner := NewDeepScannerWithConfig(DeepScannerConfig{
		APIKey: "", Timeout: 5 * time.Second, FallbackMode: "fail_open",
	})
	go deepScanner.ResultProcessor(context.Background())

	sessionStore := NewInMemoryStore()
	sessionCtx := NewSessionContext(sessionStore)
	rateLimitStore := NewInMemoryRateLimitStore()
	rateLimiter := NewRateLimiter(600, 100, rateLimitStore)
	circuitBreaker := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 5, ResetTimeout: 30 * time.Second, SuccessThreshold: 2,
	}, nil)
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}
	al := defaultAllowlist()
	rc := defaultRiskConfig()
	spikeRedeemer := NewPOCSecretRedeemer()
	hs := newMockHandleStore()

	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	})

	fullHandler := ResponseFirewall(terminal, registry, hs, 300)
	fullHandler = TokenSubstitution(fullHandler, spikeRedeemer, auditor, nil)
	fullHandler = CircuitBreakerMiddleware(fullHandler, circuitBreaker)
	fullHandler = RateLimitMiddleware(fullHandler, rateLimiter)
	fullHandler = DeepScanMiddleware(fullHandler, deepScanner, rc)
	fullHandler = StepUpGating(fullHandler, guardClient, al, rc, registry, auditor)
	fullHandler = SessionContextMiddleware(fullHandler, sessionCtx)
	fullHandler = DLPMiddleware(fullHandler, dlpScanner)
	fullHandler = OPAPolicy(fullHandler, opaEngine)
	fullHandler = ToolRegistryVerify(fullHandler, registry, nil, nil)
	fullHandler = AuditLog(fullHandler, auditor)
	fullHandler = SPIFFEAuth(fullHandler, "dev")
	fullHandler = BodyCapture(fullHandler)
	fullHandler = RequestSizeLimit(fullHandler, 1024*1024)

	minimalHandler := RequestSizeLimit(terminal, 1024*1024)

	const iterations = 1000

	// Collect full chain durations and per-middleware spans
	fullDurations := make([]time.Duration, 0, iterations)
	spanDurations := make(map[string][]time.Duration)

	for i := 0; i < iterations; i++ {
		exporter.Reset()
		req := makeValidRequest()
		rec := httptest.NewRecorder()
		start := time.Now()
		fullHandler.ServeHTTP(rec, req)
		fullDurations = append(fullDurations, time.Since(start))

		for _, s := range exporter.GetSpans() {
			dur := s.EndTime.Sub(s.StartTime)
			spanDurations[s.Name] = append(spanDurations[s.Name], dur)
		}
	}

	// Collect minimal chain durations
	minimalDurations := make([]time.Duration, 0, iterations)
	for i := 0; i < iterations; i++ {
		body := []byte(`{"jsonrpc":"2.0","method":"file_read","params":{},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		rec := httptest.NewRecorder()
		start := time.Now()
		minimalHandler.ServeHTTP(rec, req)
		minimalDurations = append(minimalDurations, time.Since(start))
	}

	// Print report
	fp50, fp95, fp99, fmean := computePercentiles(fullDurations)
	mp50, mp95, mp99, mmean := computePercentiles(minimalDurations)

	fmt.Println("================================================================================")
	fmt.Println("  PRECINCT Gateway -- 13-Middleware Chain Performance Benchmark")
	fmt.Printf("  Iterations: %d\n", iterations)
	fmt.Println("================================================================================")
	fmt.Println()
	fmt.Println("  End-to-End Latency")
	fmt.Println("  ------------------")
	fmt.Printf("  %-15s %12s %12s %12s %12s\n", "", "P50", "P95", "P99", "Mean")
	fmt.Printf("  %-15s %12s %12s %12s %12s\n", "Full (13 MW)", fp50.Truncate(time.Microsecond), fp95.Truncate(time.Microsecond), fp99.Truncate(time.Microsecond), fmean.Truncate(time.Microsecond))
	fmt.Printf("  %-15s %12s %12s %12s %12s\n", "Minimal", mp50.Truncate(time.Microsecond), mp95.Truncate(time.Microsecond), mp99.Truncate(time.Microsecond), mmean.Truncate(time.Microsecond))
	fmt.Println()

	if mmean > 0 {
		overhead := fmean - mmean
		overheadPct := float64(overhead) / float64(mmean) * 100
		fmt.Printf("  Security overhead: %s additional per request (%.1f%% increase)\n", overhead.Truncate(time.Microsecond), overheadPct)
	}
	fmt.Println()

	fmt.Println("  Per-Middleware Latency Breakdown (OTel Span Timing)")
	fmt.Println("  ---------------------------------------------------")
	fmt.Printf("  %-35s %10s %10s %10s %10s\n", "Middleware", "P50", "P95", "P99", "Mean")

	middlewareOrder := []string{
		"gateway.request_size_limit",
		"gateway.body_capture",
		"gateway.spiffe_auth",
		"gateway.audit_log",
		"gateway.tool_registry_verify",
		"gateway.opa_policy",
		"gateway.dlp_scan",
		"gateway.session_context",
		"gateway.step_up_gating",
		"gateway.deep_scan_dispatch",
		"gateway.rate_limit",
		"gateway.circuit_breaker",
		"gateway.token_substitution",
		"gateway.response_firewall",
	}

	for _, name := range middlewareOrder {
		durations, ok := spanDurations[name]
		if !ok {
			continue
		}
		p50, p95, p99, mean := computePercentiles(durations)
		fmt.Printf("  %-35s %10s %10s %10s %10s\n", name,
			p50.Truncate(time.Microsecond),
			p95.Truncate(time.Microsecond),
			p99.Truncate(time.Microsecond),
			mean.Truncate(time.Microsecond),
		)
	}

	fmt.Println()
	fmt.Println("================================================================================")
}

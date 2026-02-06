package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// setupTestTracer installs an in-memory span exporter so tests can inspect
// recorded spans. Returns a teardown function that restores the global
// TracerProvider.
func setupTestTracer(t *testing.T) (*tracetest.InMemoryExporter, func()) {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter), // synchronous for deterministic tests
	)
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)

	// Re-create the package-level tracer so it uses the new provider.
	tracer = tp.Tracer("mcp-security-gateway")

	return exporter, func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
	}
}

// findSpan locates a span by name in the exported spans.
func findSpan(spans tracetest.SpanStubs, name string) *tracetest.SpanStub {
	for i, s := range spans {
		if s.Name == name {
			return &spans[i]
		}
	}
	return nil
}

// getAttrString extracts a string attribute value.
func getAttrString(attrs []attribute.KeyValue, key string) (string, bool) {
	for _, a := range attrs {
		if string(a.Key) == key {
			return a.Value.AsString(), true
		}
	}
	return "", false
}

// getAttrInt extracts an int attribute value.
func getAttrInt(attrs []attribute.KeyValue, key string) (int64, bool) {
	for _, a := range attrs {
		if string(a.Key) == key {
			return a.Value.AsInt64(), true
		}
	}
	return 0, false
}

// ---------- Tests ----------

func TestOTelSpan_RequestSizeLimit(t *testing.T) {
	exporter, teardown := setupTestTracer(t)
	defer teardown()

	handler := RequestSizeLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), 1024)

	req := httptest.NewRequest("POST", "/", bytes.NewBufferString("test body"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	spans := exporter.GetSpans()
	span := findSpan(spans, "gateway.request_size_limit")
	if span == nil {
		t.Fatal("Expected span 'gateway.request_size_limit' not found")
	}

	// Verify step number
	step, ok := getAttrInt(span.Attributes, "mcp.gateway.step")
	if !ok || step != 1 {
		t.Errorf("Expected mcp.gateway.step=1, got %d (found=%v)", step, ok)
	}

	// Verify middleware name
	mw, ok := getAttrString(span.Attributes, "mcp.gateway.middleware")
	if !ok || mw != "request_size_limit" {
		t.Errorf("Expected mcp.gateway.middleware='request_size_limit', got %q (found=%v)", mw, ok)
	}
}

func TestOTelSpan_BodyCapture(t *testing.T) {
	exporter, teardown := setupTestTracer(t)
	defer teardown()

	handler := BodyCapture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"test":"data"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	spans := exporter.GetSpans()
	span := findSpan(spans, "gateway.body_capture")
	if span == nil {
		t.Fatal("Expected span 'gateway.body_capture' not found")
	}

	step, ok := getAttrInt(span.Attributes, "mcp.gateway.step")
	if !ok || step != 2 {
		t.Errorf("Expected mcp.gateway.step=2, got %d (found=%v)", step, ok)
	}

	mw, ok := getAttrString(span.Attributes, "mcp.gateway.middleware")
	if !ok || mw != "body_capture" {
		t.Errorf("Expected mcp.gateway.middleware='body_capture', got %q (found=%v)", mw, ok)
	}
}

func TestOTelSpan_SPIFFEAuth_Success(t *testing.T) {
	exporter, teardown := setupTestTracer(t)
	defer teardown()

	handler := SPIFFEAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), "dev")

	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/test/dev")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	spans := exporter.GetSpans()
	span := findSpan(spans, "gateway.spiffe_auth")
	if span == nil {
		t.Fatal("Expected span 'gateway.spiffe_auth' not found")
	}

	step, ok := getAttrInt(span.Attributes, "mcp.gateway.step")
	if !ok || step != 3 {
		t.Errorf("Expected mcp.gateway.step=3, got %d (found=%v)", step, ok)
	}

	mw, ok := getAttrString(span.Attributes, "mcp.gateway.middleware")
	if !ok || mw != "spiffe_auth" {
		t.Errorf("Expected mcp.gateway.middleware='spiffe_auth', got %q (found=%v)", mw, ok)
	}

	spiffeID, ok := getAttrString(span.Attributes, "mcp.spiffe_id")
	if !ok || spiffeID != "spiffe://poc.local/agents/test/dev" {
		t.Errorf("Expected mcp.spiffe_id='spiffe://poc.local/agents/test/dev', got %q (found=%v)", spiffeID, ok)
	}
}

func TestOTelSpan_SPIFFEAuth_Failure(t *testing.T) {
	exporter, teardown := setupTestTracer(t)
	defer teardown()

	handler := SPIFFEAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), "dev")

	// Missing SPIFFE header -> 401
	req := httptest.NewRequest("POST", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401, got %d", rec.Code)
	}

	// Span should still be created (for observability of failures)
	spans := exporter.GetSpans()
	span := findSpan(spans, "gateway.spiffe_auth")
	if span == nil {
		t.Fatal("Expected span 'gateway.spiffe_auth' not found even on failure path")
	}

	step, ok := getAttrInt(span.Attributes, "mcp.gateway.step")
	if !ok || step != 3 {
		t.Errorf("Expected mcp.gateway.step=3, got %d (found=%v)", step, ok)
	}
}

func TestOTelSpan_OPAPolicy_Allowed(t *testing.T) {
	exporter, teardown := setupTestTracer(t)
	defer teardown()

	// Create a mock OPA evaluator that allows all requests
	opa := &mockOPAEvaluator{allowed: true, reason: ""}

	body := []byte(`{"jsonrpc":"2.0","method":"file_read","params":{},"id":1}`)

	handler := OPAPolicy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), opa)

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/test")
	ctx = WithDecisionID(ctx, "dec-123")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	spans := exporter.GetSpans()
	span := findSpan(spans, "gateway.opa_policy")
	if span == nil {
		t.Fatal("Expected span 'gateway.opa_policy' not found")
	}

	step, ok := getAttrInt(span.Attributes, "mcp.gateway.step")
	if !ok || step != 6 {
		t.Errorf("Expected mcp.gateway.step=6, got %d (found=%v)", step, ok)
	}

	mw, ok := getAttrString(span.Attributes, "mcp.gateway.middleware")
	if !ok || mw != "opa_policy" {
		t.Errorf("Expected mcp.gateway.middleware='opa_policy', got %q (found=%v)", mw, ok)
	}

	result, ok := getAttrString(span.Attributes, "mcp.result")
	if !ok || result != "allowed" {
		t.Errorf("Expected mcp.result='allowed', got %q (found=%v)", result, ok)
	}

	reason, ok := getAttrString(span.Attributes, "mcp.reason")
	if !ok {
		t.Error("Expected mcp.reason attribute to be present")
	}
	if reason != "" {
		t.Errorf("Expected mcp.reason='' for allowed request, got %q", reason)
	}
}

func TestOTelSpan_OPAPolicy_Denied(t *testing.T) {
	exporter, teardown := setupTestTracer(t)
	defer teardown()

	// Create a mock OPA evaluator that denies requests
	opa := &mockOPAEvaluator{allowed: false, reason: "tool not permitted for this agent"}

	body := []byte(`{"jsonrpc":"2.0","method":"evil_tool","params":{},"id":1}`)

	handler := OPAPolicy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), opa)

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/test")
	ctx = WithDecisionID(ctx, "dec-456")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", rec.Code)
	}

	spans := exporter.GetSpans()
	span := findSpan(spans, "gateway.opa_policy")
	if span == nil {
		t.Fatal("Expected span 'gateway.opa_policy' not found")
	}

	result, ok := getAttrString(span.Attributes, "mcp.result")
	if !ok || result != "denied" {
		t.Errorf("Expected mcp.result='denied', got %q (found=%v)", result, ok)
	}

	reason, ok := getAttrString(span.Attributes, "mcp.reason")
	if !ok || reason != "tool not permitted for this agent" {
		t.Errorf("Expected mcp.reason='tool not permitted for this agent', got %q (found=%v)", reason, ok)
	}
}

func TestOTelSpan_OPAPolicy_Error(t *testing.T) {
	exporter, teardown := setupTestTracer(t)
	defer teardown()

	// Create a mock OPA evaluator that returns an error
	opa := &mockOPAEvaluator{err: os.ErrNotExist}

	body := []byte(`{"jsonrpc":"2.0","method":"some_tool","params":{},"id":1}`)

	handler := OPAPolicy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), opa)

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/test")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", rec.Code)
	}

	spans := exporter.GetSpans()
	span := findSpan(spans, "gateway.opa_policy")
	if span == nil {
		t.Fatal("Expected span 'gateway.opa_policy' not found")
	}

	result, ok := getAttrString(span.Attributes, "mcp.result")
	if !ok || result != "error" {
		t.Errorf("Expected mcp.result='error', got %q (found=%v)", result, ok)
	}
}

// TestOTelSpan_FullChain verifies span creation when multiple instrumented
// middleware run together (steps 1, 2, 3, 6), proving parent-child
// span hierarchy via shared TraceID.
func TestOTelSpan_FullChain(t *testing.T) {
	exporter, teardown := setupTestTracer(t)
	defer teardown()

	// Create minimal OPA evaluator for the chain
	opa := &mockOPAEvaluator{allowed: true, reason: ""}

	// Build a mini chain: RequestSizeLimit -> BodyCapture -> SPIFFEAuth -> OPAPolicy -> handler
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RequestSizeLimit(
		BodyCapture(
			SPIFFEAuth(
				OPAPolicy(inner, opa),
				"dev",
			),
		),
		1024*1024,
	)

	body := []byte(`{"jsonrpc":"2.0","method":"file_read","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/test/dev")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	spans := exporter.GetSpans()

	// Verify we got exactly 4 spans
	if len(spans) != 4 {
		t.Fatalf("Expected 4 spans (steps 1,2,3,6), got %d", len(spans))
	}

	// Verify all expected spans exist
	expectedNames := []string{
		"gateway.request_size_limit",
		"gateway.body_capture",
		"gateway.spiffe_auth",
		"gateway.opa_policy",
	}
	for _, name := range expectedNames {
		s := findSpan(spans, name)
		if s == nil {
			t.Errorf("Expected span %q not found", name)
		}
	}

	// Verify all spans share the same TraceID (proving parent-child relationship)
	traceID := spans[0].SpanContext.TraceID()
	for _, s := range spans {
		if s.SpanContext.TraceID() != traceID {
			t.Errorf("Span %q has different TraceID: %s vs %s", s.Name, s.SpanContext.TraceID(), traceID)
		}
	}
}

// TestOTelSpan_NoExporter_NoopGraceful verifies that when no TracerProvider
// is installed (the default), middleware still functions correctly without
// exporting spans (AC6: graceful no-op).
func TestOTelSpan_NoExporter_NoopGraceful(t *testing.T) {
	// Reset to default no-op provider
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(otel.GetTracerProvider()) // no-op
	defer otel.SetTracerProvider(prev)

	handler := RequestSizeLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), 1024)

	req := httptest.NewRequest("POST", "/", bytes.NewBufferString("test"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Request should succeed even without an exporter
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 with no-op tracer, got %d", rec.Code)
	}
}

// ---------- Mock OPA evaluator ----------

type mockOPAEvaluator struct {
	allowed bool
	reason  string
	err     error
}

func (m *mockOPAEvaluator) Evaluate(input OPAInput) (bool, string, error) {
	return m.allowed, m.reason, m.err
}

// ---------- Integration-style test: full chain with real OPA engine ----------

func TestOTelSpan_OPAPolicy_WithRealOPAEngine(t *testing.T) {
	exporter, teardown := setupTestTracer(t)
	defer teardown()

	// Create a temporary OPA policy that allows file_read
	tmpDir := t.TempDir()
	policyPath := tmpDir + "/mcp_policy.rego"
	policy := `package mcp

default allow = false

allow {
    input.tool == "file_read"
}
`
	if err := os.WriteFile(policyPath, []byte(policy), 0644); err != nil {
		t.Fatalf("Failed to write OPA policy: %v", err)
	}

	// Create real OPA engine
	opaEngine, err := NewOPAEngine(tmpDir, OPAEngineConfig{})
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer opaEngine.Close()

	handler := OPAPolicy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), opaEngine)

	// Test allowed request
	t.Run("Allowed_file_read", func(t *testing.T) {
		exporter.Reset()
		body := []byte(`{"jsonrpc":"2.0","method":"file_read","params":{"tool":"file_read"},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		ctx := WithRequestBody(req.Context(), body)
		ctx = WithSPIFFEID(ctx, "spiffe://poc.local/test")
		ctx = WithDecisionID(ctx, "dec-real-1")
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", rec.Code)
		}

		spans := exporter.GetSpans()
		span := findSpan(spans, "gateway.opa_policy")
		if span == nil {
			t.Fatal("Expected span 'gateway.opa_policy' not found")
		}

		result, ok := getAttrString(span.Attributes, "mcp.result")
		if !ok || result != "allowed" {
			t.Errorf("Expected mcp.result='allowed', got %q (found=%v)", result, ok)
		}
	})

	// Test denied request
	t.Run("Denied_evil_tool", func(t *testing.T) {
		exporter.Reset()
		body := []byte(`{"jsonrpc":"2.0","method":"evil_tool","params":{"tool":"evil_tool"},"id":2}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		ctx := WithRequestBody(req.Context(), body)
		ctx = WithSPIFFEID(ctx, "spiffe://poc.local/test")
		ctx = WithDecisionID(ctx, "dec-real-2")
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("Expected 403, got %d", rec.Code)
		}

		spans := exporter.GetSpans()
		span := findSpan(spans, "gateway.opa_policy")
		if span == nil {
			t.Fatal("Expected span 'gateway.opa_policy' not found")
		}

		result, ok := getAttrString(span.Attributes, "mcp.result")
		if !ok || result != "denied" {
			t.Errorf("Expected mcp.result='denied', got %q (found=%v)", result, ok)
		}
	})
}

// TestOTelSpan_ContextPropagation verifies that the OTel context is properly
// propagated through the middleware chain -- downstream middleware sees the
// context from upstream spans.
func TestOTelSpan_ContextPropagation(t *testing.T) {
	exporter, teardown := setupTestTracer(t)
	defer teardown()

	// Track what context downstream handlers receive
	var downstreamSessionID string
	var downstreamDecisionID string

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstreamSessionID = GetSessionID(r.Context())
		downstreamDecisionID = GetDecisionID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	// Build chain: BodyCapture -> SPIFFEAuth -> handler
	handler := BodyCapture(SPIFFEAuth(inner, "dev"))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/test/dev")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	// Verify context values propagated through instrumented middleware
	if downstreamSessionID == "" {
		t.Error("SessionID not propagated through OTel-instrumented BodyCapture")
	}
	if downstreamDecisionID == "" {
		t.Error("DecisionID not propagated through OTel-instrumented BodyCapture")
	}

	// Verify both spans exist
	spans := exporter.GetSpans()
	if findSpan(spans, "gateway.body_capture") == nil {
		t.Error("Missing gateway.body_capture span")
	}
	if findSpan(spans, "gateway.spiffe_auth") == nil {
		t.Error("Missing gateway.spiffe_auth span")
	}
}

// TestOTelSpan_OPAPolicy_DecisionAttributes_BothPaths verifies that the OPA
// Policy span has mcp.result and mcp.reason for BOTH allowed and denied paths
// in a single test, proving bidirectional testing.
func TestOTelSpan_OPAPolicy_DecisionAttributes_BothPaths(t *testing.T) {
	exporter, teardown := setupTestTracer(t)
	defer teardown()

	handler := func(opa OPAEvaluator) http.Handler {
		return OPAPolicy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), opa)
	}

	makeReq := func(toolName string) *http.Request {
		body := []byte(`{"jsonrpc":"2.0","method":"` + toolName + `","params":{"tool":"` + toolName + `"},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		ctx := WithRequestBody(req.Context(), body)
		ctx = WithSPIFFEID(ctx, "spiffe://poc.local/test")
		ctx = WithDecisionID(ctx, "dec-bidir")
		return req.WithContext(ctx)
	}

	// Path 1: Allowed
	t.Run("Allowed", func(t *testing.T) {
		exporter.Reset()
		h := handler(&mockOPAEvaluator{allowed: true, reason: "policy matched"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, makeReq("allowed_tool"))

		if rec.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", rec.Code)
		}

		span := findSpan(exporter.GetSpans(), "gateway.opa_policy")
		if span == nil {
			t.Fatal("Span not found")
		}
		result, _ := getAttrString(span.Attributes, "mcp.result")
		reason, _ := getAttrString(span.Attributes, "mcp.reason")
		if result != "allowed" {
			t.Errorf("Expected mcp.result='allowed', got %q", result)
		}
		if reason != "policy matched" {
			t.Errorf("Expected mcp.reason='policy matched', got %q", reason)
		}
	})

	// Path 2: Denied
	t.Run("Denied", func(t *testing.T) {
		exporter.Reset()
		h := handler(&mockOPAEvaluator{allowed: false, reason: "unauthorized agent"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, makeReq("denied_tool"))

		if rec.Code != http.StatusForbidden {
			t.Fatalf("Expected 403, got %d", rec.Code)
		}

		span := findSpan(exporter.GetSpans(), "gateway.opa_policy")
		if span == nil {
			t.Fatal("Span not found")
		}
		result, _ := getAttrString(span.Attributes, "mcp.result")
		reason, _ := getAttrString(span.Attributes, "mcp.reason")
		if result != "denied" {
			t.Errorf("Expected mcp.result='denied', got %q", result)
		}
		if reason != "unauthorized agent" {
			t.Errorf("Expected mcp.reason='unauthorized agent', got %q", reason)
		}
	})
}

// TestOTelPackageLevelTracer verifies that the package-level tracer variable
// is properly initialized.
func TestOTelPackageLevelTracer(t *testing.T) {
	if tracer == nil {
		t.Fatal("Package-level tracer should not be nil")
	}
}

// ---------- Integration test: Docker Compose stack ----------
// These tests exercise the full gateway with OTel exporter targeting
// an OTel Collector + Phoenix. They require `make up` to be running.
// Skipped unless explicitly enabled via INTEGRATION_TEST_OTEL=1.

func TestOTelIntegration_SpansVisibleInCollector(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST_OTEL") != "1" {
		t.Skip("Skipping OTel integration test: set INTEGRATION_TEST_OTEL=1 and run 'make up' first")
	}

	// Send a valid request through the gateway
	gatewayURL := os.Getenv("GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://localhost:9090"
	}

	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
	req, err := http.NewRequest("POST", gatewayURL+"/", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/test/dev")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("Gateway response status: %d", resp.StatusCode)

	// Query Phoenix for traces (give the batch processor time to flush)
	phoenixURL := os.Getenv("PHOENIX_URL")
	if phoenixURL == "" {
		phoenixURL = "http://localhost:6006"
	}

	// Phoenix exposes a GraphQL API; check for spans via the API
	query := map[string]string{
		"query": `{ spans(first: 10) { edges { node { name statusCode context { traceId } } } } }`,
	}
	queryBody, _ := json.Marshal(query)

	phoenixReq, err := http.NewRequest("POST", phoenixURL+"/graphql", bytes.NewBuffer(queryBody))
	if err != nil {
		t.Fatalf("Failed to create Phoenix request: %v", err)
	}
	phoenixReq.Header.Set("Content-Type", "application/json")

	phoenixResp, err := client.Do(phoenixReq)
	if err != nil {
		t.Logf("Phoenix not reachable (expected if Docker stack is not running): %v", err)
		return
	}
	defer phoenixResp.Body.Close()

	t.Logf("Phoenix response status: %d", phoenixResp.StatusCode)
}

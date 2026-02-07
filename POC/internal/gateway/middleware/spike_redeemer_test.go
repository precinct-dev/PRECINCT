package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestSPIKENexusRedeemer_SuccessfulRedemption tests that the redeemer
// correctly calls SPIKE Nexus and parses the response.
func TestSPIKENexusRedeemer_SuccessfulRedemption(t *testing.T) {
	var receivedPath string
	var receivedMethod string
	var receivedContentType string

	nexusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedContentType = r.Header.Get("Content-Type")

		var reqBody spikeSecretRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		receivedPath = reqBody.Path

		resp := spikeSecretResponse{
			Data: map[string]string{
				"value": "test-secret-value-12345",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer nexusServer.Close()

	redeemer := NewSPIKENexusRedeemerWithClient(nexusServer.URL, nexusServer.Client())

	token := &SPIKEToken{
		Ref: "abc123",
		Exp: 3600,
	}

	secret, err := redeemer.RedeemSecret(context.Background(), token)
	if err != nil {
		t.Fatalf("RedeemSecret() returned unexpected error: %v", err)
	}

	if receivedMethod != http.MethodPost {
		t.Errorf("Expected POST method, got %s", receivedMethod)
	}
	if receivedContentType != "application/json" {
		t.Errorf("Expected application/json content type, got %s", receivedContentType)
	}
	if receivedPath != "abc123" {
		t.Errorf("Expected path 'abc123', got '%s'", receivedPath)
	}

	if secret == nil {
		t.Fatal("RedeemSecret() returned nil secret")
	}
	if secret.Value != "test-secret-value-12345" {
		t.Errorf("Expected secret value 'test-secret-value-12345', got '%s'", secret.Value)
	}
	if secret.ExpiresAt == 0 {
		t.Error("Expected non-zero ExpiresAt")
	}
}

// TestSPIKENexusRedeemer_NexusError tests handling of SPIKE Nexus error responses.
func TestSPIKENexusRedeemer_NexusError(t *testing.T) {
	nexusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := spikeSecretResponse{
			Err: "secret not found",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer nexusServer.Close()

	redeemer := NewSPIKENexusRedeemerWithClient(nexusServer.URL, nexusServer.Client())

	token := &SPIKEToken{Ref: "nonexistent"}
	_, err := redeemer.RedeemSecret(context.Background(), token)
	if err == nil {
		t.Fatal("RedeemSecret() expected error for Nexus error response, got nil")
	}
	if got := err.Error(); got != "SPIKE Nexus error: secret not found" {
		t.Errorf("Unexpected error message: %s", got)
	}
}

// TestSPIKENexusRedeemer_HTTPError tests handling of non-200 HTTP responses.
func TestSPIKENexusRedeemer_HTTPError(t *testing.T) {
	nexusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer nexusServer.Close()

	redeemer := NewSPIKENexusRedeemerWithClient(nexusServer.URL, nexusServer.Client())

	token := &SPIKEToken{Ref: "abc123"}
	_, err := redeemer.RedeemSecret(context.Background(), token)
	if err == nil {
		t.Fatal("RedeemSecret() expected error for HTTP 500, got nil")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("Expected error to mention status 500, got: %s", err.Error())
	}
}

// TestSPIKENexusRedeemer_InvalidJSON tests handling of invalid JSON responses.
func TestSPIKENexusRedeemer_InvalidJSON(t *testing.T) {
	nexusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer nexusServer.Close()

	redeemer := NewSPIKENexusRedeemerWithClient(nexusServer.URL, nexusServer.Client())

	token := &SPIKEToken{Ref: "abc123"}
	_, err := redeemer.RedeemSecret(context.Background(), token)
	if err == nil {
		t.Fatal("RedeemSecret() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse response") {
		t.Errorf("Expected parse error, got: %s", err.Error())
	}
}

// TestSPIKENexusRedeemer_MissingValue tests handling of response without 'value' field.
func TestSPIKENexusRedeemer_MissingValue(t *testing.T) {
	nexusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := spikeSecretResponse{
			Data: map[string]string{
				"other_field": "some data",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer nexusServer.Close()

	redeemer := NewSPIKENexusRedeemerWithClient(nexusServer.URL, nexusServer.Client())

	token := &SPIKEToken{Ref: "abc123"}
	_, err := redeemer.RedeemSecret(context.Background(), token)
	if err == nil {
		t.Fatal("RedeemSecret() expected error for missing 'value', got nil")
	}
	if got := err.Error(); got != "SPIKE Nexus response missing 'value' in data" {
		t.Errorf("Unexpected error message: %s", got)
	}
}

// TestSPIKENexusRedeemer_NilToken tests handling of nil token input.
func TestSPIKENexusRedeemer_NilToken(t *testing.T) {
	redeemer := NewSPIKENexusRedeemerWithClient("https://nexus.example.com", http.DefaultClient)

	_, err := redeemer.RedeemSecret(context.Background(), nil)
	if err == nil {
		t.Fatal("RedeemSecret() expected error for nil token, got nil")
	}
}

// TestSPIKENexusRedeemer_ConnectionFailure tests handling of connection failures.
func TestSPIKENexusRedeemer_ConnectionFailure(t *testing.T) {
	redeemer := NewSPIKENexusRedeemerWithClient("http://127.0.0.1:1", http.DefaultClient)

	token := &SPIKEToken{Ref: "abc123"}
	_, err := redeemer.RedeemSecret(context.Background(), token)
	if err == nil {
		t.Fatal("RedeemSecret() expected error for connection failure, got nil")
	}
	if !strings.Contains(err.Error(), "failed to call SPIKE Nexus") {
		t.Errorf("Expected connection error, got: %s", err.Error())
	}
}

// TestSPIKENexusRedeemer_CorrectEndpoint verifies the redeemer calls the
// correct API endpoint: POST /v1/store/secret/get
func TestSPIKENexusRedeemer_CorrectEndpoint(t *testing.T) {
	var requestedURL string

	nexusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedURL = r.URL.Path

		resp := spikeSecretResponse{
			Data: map[string]string{"value": "secret"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer nexusServer.Close()

	redeemer := NewSPIKENexusRedeemerWithClient(nexusServer.URL, nexusServer.Client())

	token := &SPIKEToken{Ref: "abc123"}
	_, err := redeemer.RedeemSecret(context.Background(), token)
	if err != nil {
		t.Fatalf("RedeemSecret() unexpected error: %v", err)
	}

	expectedPath := "/v1/store/secret/get"
	if requestedURL != expectedPath {
		t.Errorf("Expected endpoint %s, got %s", expectedPath, requestedURL)
	}
}

// TestSPIKENexusRedeemer_TrailingSlashHandling verifies the redeemer handles
// trailing slashes in the nexus URL correctly.
func TestSPIKENexusRedeemer_TrailingSlashHandling(t *testing.T) {
	var requestedURL string

	nexusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedURL = r.URL.Path
		resp := spikeSecretResponse{
			Data: map[string]string{"value": "secret"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer nexusServer.Close()

	redeemer := NewSPIKENexusRedeemerWithClient(nexusServer.URL+"/", nexusServer.Client())

	token := &SPIKEToken{Ref: "abc123"}
	_, err := redeemer.RedeemSecret(context.Background(), token)
	if err != nil {
		t.Fatalf("RedeemSecret() unexpected error: %v", err)
	}

	if requestedURL != "/v1/store/secret/get" {
		t.Errorf("Expected /v1/store/secret/get, got %s", requestedURL)
	}
}

// TestSPIKENexusRedeemer_ImplementsSecretRedeemer verifies interface compliance.
func TestSPIKENexusRedeemer_ImplementsSecretRedeemer(t *testing.T) {
	var _ SecretRedeemer = (*SPIKENexusRedeemer)(nil)
	t.Log("SPIKENexusRedeemer correctly implements SecretRedeemer interface")
}

// TestSPIKENexusRedeemer_Close tests the Close method.
func TestSPIKENexusRedeemer_Close(t *testing.T) {
	redeemer := NewSPIKENexusRedeemerWithClient("https://nexus.example.com", http.DefaultClient)
	err := redeemer.Close()
	if err != nil {
		t.Errorf("Close() unexpected error: %v", err)
	}
}

// TestNewSPIKENexusRedeemer_NilX509Source tests creation with nil x509Source
// (dev/test mode with InsecureSkipVerify).
func TestNewSPIKENexusRedeemer_NilX509Source(t *testing.T) {
	redeemer := NewSPIKENexusRedeemer("https://spike-nexus:8443", nil)
	if redeemer == nil {
		t.Fatal("NewSPIKENexusRedeemer() returned nil")
	}
	if redeemer.nexusURL != "https://spike-nexus:8443" {
		t.Errorf("Expected nexusURL 'https://spike-nexus:8443', got '%s'", redeemer.nexusURL)
	}
	if redeemer.httpClient == nil {
		t.Fatal("Expected non-nil httpClient")
	}
}

// TestTokenSubstitutionWithSPIKERedeemer tests the full TokenSubstitution middleware
// with a SPIKENexusRedeemer backed by a mock Nexus server. Proves the redeemer
// is correctly wired into the middleware chain.
func TestTokenSubstitutionWithSPIKERedeemer(t *testing.T) {
	// Create mock SPIKE Nexus that returns owner metadata (RFA-7ct)
	nexusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := spikeSecretResponse{
			Data: map[string]string{
				"value": "real-secret-from-nexus",
				"owner": "spiffe://poc.local/agent/test-agent", // Nexus pre-assigns owner
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer nexusServer.Close()

	redeemer := NewSPIKENexusRedeemerWithClient(nexusServer.URL, nexusServer.Client())

	// Upstream handler that captures the body it receives
	var upstreamBody string
	echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamBody = string(body)
		w.WriteHeader(http.StatusOK)
	})

	// Build middleware chain: BodyCapture -> SPIFFEAuth -> TokenSubstitution -> echo
	chain := BodyCapture(
		SPIFFEAuth(
			TokenSubstitution(echoHandler, redeemer),
			"dev",
		),
	)

	// Send request with SPIKE token
	reqBody := `{"api_key": "$SPIKE{ref:abc123}"}`
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agent/test-agent")

	rr := httptest.NewRecorder()
	chain.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify the upstream received the substituted secret, not the token
	if strings.Contains(upstreamBody, "$SPIKE{") {
		t.Error("Upstream received unsubstituted SPIKE token - substitution failed")
	}
	if !strings.Contains(upstreamBody, "real-secret-from-nexus") {
		t.Errorf("Upstream did not receive expected secret. Got: %s", upstreamBody)
	}
}

// TestTokenSubstitutionFallbackToPOC verifies AC8: when SPIKE_NEXUS_URL is empty,
// the POCSecretRedeemer is used (Phase 1 behavior preserved).
func TestTokenSubstitutionFallbackToPOC(t *testing.T) {
	pocRedeemer := NewPOCSecretRedeemerWithOwner("spiffe://poc.local/agent/test-agent")

	var upstreamBody string
	echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamBody = string(body)
		w.WriteHeader(http.StatusOK)
	})

	chain := BodyCapture(
		SPIFFEAuth(
			TokenSubstitution(echoHandler, pocRedeemer),
			"dev",
		),
	)

	reqBody := `{"api_key": "$SPIKE{ref:abc123}"}`
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agent/test-agent")

	rr := httptest.NewRecorder()
	chain.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	// POC redeemer returns "secret-value-for-<ref>"
	if !strings.Contains(upstreamBody, "secret-value-for-abc123") {
		t.Errorf("POC fallback did not substitute correctly. Got: %s", upstreamBody)
	}
}

// ---------- RFA-m6j.3: Trace context propagation tests ----------

// setupTestPropagator installs a TracerProvider and W3C TraceContext propagator
// for testing trace context injection on SPIKE Nexus requests.
func setupTestPropagator(t *testing.T) (*tracetest.InMemoryExporter, func()) {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return exporter, func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	}
}

// TestSPIKENexusRedeemer_InjectsTraceparent verifies that outbound requests
// to SPIKE Nexus contain the traceparent header from the gateway's span (AC2).
func TestSPIKENexusRedeemer_InjectsTraceparent(t *testing.T) {
	exporter, teardown := setupTestPropagator(t)
	defer teardown()

	var receivedTraceparent string

	nexusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTraceparent = r.Header.Get("Traceparent")
		resp := spikeSecretResponse{
			Data: map[string]string{"value": "test-secret"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer nexusServer.Close()

	redeemer := NewSPIKENexusRedeemerWithClient(nexusServer.URL, nexusServer.Client())

	// Create a span to provide trace context
	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "gateway.token_substitution")

	token := &SPIKEToken{Ref: "test-key"}
	secret, err := redeemer.RedeemSecret(ctx, token)
	span.End()

	if err != nil {
		t.Fatalf("RedeemSecret() unexpected error: %v", err)
	}
	if secret.Value != "test-secret" {
		t.Errorf("Expected secret 'test-secret', got %q", secret.Value)
	}

	// Verify traceparent was injected
	if receivedTraceparent == "" {
		t.Fatal("Expected traceparent header on SPIKE Nexus request, got empty")
	}

	// Verify W3C format: version-traceid-parentid-flags
	parts := strings.Split(receivedTraceparent, "-")
	if len(parts) != 4 {
		t.Fatalf("traceparent format invalid: expected 4 parts, got %d: %q", len(parts), receivedTraceparent)
	}

	// Extract trace_id from traceparent and compare with gateway span
	propagatedTraceID := parts[1]

	spans := exporter.GetSpans()
	var gatewayTraceID string
	for _, s := range spans {
		if s.Name == "gateway.token_substitution" {
			gatewayTraceID = s.SpanContext.TraceID().String()
			break
		}
	}
	if gatewayTraceID == "" {
		t.Fatal("Gateway span 'gateway.token_substitution' not found in exporter")
	}

	// AC4: Same trace_id correlates gateway and SPIKE Nexus spans
	if propagatedTraceID != gatewayTraceID {
		t.Errorf("Trace ID mismatch: propagated=%q, gateway span=%q", propagatedTraceID, gatewayTraceID)
	}

	t.Logf("SPIKE Nexus traceparent: %s (trace_id matches gateway span)", receivedTraceparent)
}

// TestSPIKENexusRedeemer_NoSpanContext_NoTraceparent verifies graceful behavior
// when no span context exists (e.g., OTel not configured).
func TestSPIKENexusRedeemer_NoSpanContext_NoTraceparent(t *testing.T) {
	// Register the propagator but do NOT create a span
	prevProp := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	defer otel.SetTextMapPropagator(prevProp)

	var receivedTraceparent string

	nexusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTraceparent = r.Header.Get("Traceparent")
		resp := spikeSecretResponse{
			Data: map[string]string{"value": "test-secret"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer nexusServer.Close()

	redeemer := NewSPIKENexusRedeemerWithClient(nexusServer.URL, nexusServer.Client())

	// No span in context
	token := &SPIKEToken{Ref: "test-key"}
	_, err := redeemer.RedeemSecret(context.Background(), token)
	if err != nil {
		t.Fatalf("RedeemSecret() unexpected error: %v", err)
	}

	// Without an active span, no traceparent should be injected
	if receivedTraceparent != "" {
		t.Errorf("Expected no traceparent without active span, got: %q", receivedTraceparent)
	}
}

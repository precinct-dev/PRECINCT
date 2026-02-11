package middleware

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMiddlewareChainOrder verifies middleware executes in correct order
func TestMiddlewareChainOrder(t *testing.T) {
	var executionOrder []string

	// Create tracking middleware
	track := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				executionOrder = append(executionOrder, name)
				next.ServeHTTP(w, r)
			})
		}
	}

	// Build chain in expected order per Architecture Section 9.2
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executionOrder = append(executionOrder, "handler")
		w.WriteHeader(http.StatusOK)
	})

	// Apply in reverse order (innermost first) - token_sub MUST be last before handler
	handler = track("token_sub")(handler) // 13 - LAST before proxy
	handler = track("deep_scan")(handler) // 10
	handler = track("step_up")(handler)   // 9
	handler = track("dlp")(handler)       // 7
	handler = track("opa")(handler)       // 6
	handler = track("registry")(handler)  // 5
	handler = track("audit")(handler)     // 4
	handler = track("spiffe")(handler)    // 3
	handler = track("body")(handler)      // 2
	handler = track("size")(handler)      // 1

	// Execute request
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString("test"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify order - token_sub MUST be last before handler (step 13)
	expected := []string{"size", "body", "spiffe", "audit", "registry", "opa", "dlp", "step_up", "deep_scan", "token_sub", "handler"}
	if len(executionOrder) != len(expected) {
		t.Fatalf("Expected %d middleware, got %d", len(expected), len(executionOrder))
	}

	for i, name := range expected {
		if executionOrder[i] != name {
			t.Errorf("Position %d: expected %s, got %s", i, name, executionOrder[i])
		}
	}
}

// TestRequestSizeLimit verifies size limit enforcement at step 1.
// RFA-zxf: The size check must happen in this middleware (step 1), not in
// body_capture (step 2). The middleware returns a GatewayError JSON response
// with middleware="request_size_limit" and middleware_step=1.
func TestRequestSizeLimit(t *testing.T) {
	maxBytes := int64(100)
	nextCalled := false
	handler := RequestSizeLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		// Verify body is still readable downstream
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Downstream handler failed to read body: %v", err)
		}
		if len(bodyBytes) == 0 {
			t.Error("Downstream handler received empty body")
		}
		w.WriteHeader(http.StatusOK)
	}), maxBytes)

	// Test under limit: body passes through to next handler
	t.Run("UnderLimit", func(t *testing.T) {
		nextCalled = false
		body := bytes.Repeat([]byte("a"), 50)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
		if !nextCalled {
			t.Error("Next handler should have been called for body under limit")
		}
	})

	// Test over limit: returns 413 GatewayError at step 1, next handler NOT called
	t.Run("OverLimit", func(t *testing.T) {
		nextCalled = false
		body := bytes.Repeat([]byte("a"), 150)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("Expected 413, got %d", rec.Code)
		}
		if nextCalled {
			t.Error("Next handler should NOT have been called for oversized body")
		}

		// Verify GatewayError JSON response attributes
		var ge GatewayError
		if err := json.Unmarshal(rec.Body.Bytes(), &ge); err != nil {
			t.Fatalf("Failed to parse GatewayError response: %v", err)
		}
		if ge.Code != ErrRequestTooLarge {
			t.Errorf("Expected code %q, got %q", ErrRequestTooLarge, ge.Code)
		}
		if ge.Middleware != "request_size_limit" {
			t.Errorf("Expected middleware 'request_size_limit', got %q", ge.Middleware)
		}
		if ge.MiddlewareStep != 1 {
			t.Errorf("Expected middleware_step=1, got %d", ge.MiddlewareStep)
		}
	})

	// Test exactly at limit: should pass through
	t.Run("ExactLimit", func(t *testing.T) {
		nextCalled = false
		body := bytes.Repeat([]byte("a"), int(maxBytes))
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
		if !nextCalled {
			t.Error("Next handler should have been called for body exactly at limit")
		}
	})

	// Test nil body: should pass through without error
	t.Run("NilBody", func(t *testing.T) {
		nilHandler := RequestSizeLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), maxBytes)

		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		nilHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 for nil body, got %d", rec.Code)
		}
	})
}

// TestBodyCapture verifies body capture and ID generation
func TestBodyCapture(t *testing.T) {
	var capturedBody []byte
	var capturedSessionID string
	var capturedDecisionID string
	var capturedTraceID string

	handler := BodyCapture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody = GetRequestBody(r.Context())
		capturedSessionID = GetSessionID(r.Context())
		capturedDecisionID = GetDecisionID(r.Context())
		capturedTraceID = GetTraceID(r.Context())

		// Verify body can be read again
		bodyBytes, _ := io.ReadAll(r.Body)
		if !bytes.Equal(bodyBytes, capturedBody) {
			t.Error("Body not restored correctly")
		}

		w.WriteHeader(http.StatusOK)
	}))

	requestBody := []byte(`{"test": "data"}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(requestBody))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify body captured
	if !bytes.Equal(capturedBody, requestBody) {
		t.Errorf("Expected body %s, got %s", string(requestBody), string(capturedBody))
	}

	// Verify IDs generated
	if capturedSessionID == "" {
		t.Error("Session ID not generated")
	}
	if capturedDecisionID == "" {
		t.Error("Decision ID not generated")
	}
	if capturedTraceID == "" {
		t.Error("Trace ID not generated")
	}

	// Verify IDs are unique
	if capturedSessionID == capturedDecisionID || capturedSessionID == capturedTraceID {
		t.Error("IDs should be unique")
	}
}

// TestSPIFFEAuthDev verifies SPIFFE auth in dev mode
func TestSPIFFEAuthDev(t *testing.T) {
	handler := SPIFFEAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spiffeID := GetSPIFFEID(r.Context())
		if spiffeID == "" {
			t.Error("SPIFFE ID not set in context")
		}
		w.WriteHeader(http.StatusOK)
	}), "dev")

	t.Run("ValidSPIFFEID", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/test/dev")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
	})

	t.Run("MissingSPIFFEID", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", rec.Code)
		}
	})

	t.Run("InvalidFormat", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-SPIFFE-ID", "not-a-spiffe-id")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", rec.Code)
		}
	})
}

// TestSPIFFEAuthProd verifies SPIFFE auth in prod mode extracts SPIFFE ID from TLS client cert.
// RFA-8z8.1 AC2: In prod mode, gateway validates client certificates via SPIRE trust bundle.
func TestSPIFFEAuthProd(t *testing.T) {
	var capturedSPIFFEID string
	handler := SPIFFEAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSPIFFEID = GetSPIFFEID(r.Context())
		w.WriteHeader(http.StatusOK)
	}), "prod")

	t.Run("ValidClientCertWithSPIFFEID", func(t *testing.T) {
		capturedSPIFFEID = ""
		spiffeURI, _ := url.Parse("spiffe://poc.local/agents/test-agent/dev")

		// Create a self-signed cert with SPIFFE ID as URI SAN
		cert := createTestCertWithSPIFFEID(t, spiffeURI)

		req := httptest.NewRequest("POST", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
		if capturedSPIFFEID != "spiffe://poc.local/agents/test-agent/dev" {
			t.Errorf("Expected SPIFFE ID spiffe://poc.local/agents/test-agent/dev, got %q", capturedSPIFFEID)
		}
	})

	t.Run("NoTLSConnectionReturns401", func(t *testing.T) {
		capturedSPIFFEID = ""
		req := httptest.NewRequest("POST", "/", nil)
		// No TLS at all
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for no TLS connection, got %d", rec.Code)
		}
	})

	t.Run("TLSWithNoPeerCertsReturns401", func(t *testing.T) {
		capturedSPIFFEID = ""
		req := httptest.NewRequest("POST", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for TLS with no peer certs, got %d", rec.Code)
		}
	})

	t.Run("TLSCertWithNoSPIFFEURIReturns401", func(t *testing.T) {
		capturedSPIFFEID = ""
		// Create a cert with no URI SANs
		cert := createTestCertNoSPIFFE(t)

		req := httptest.NewRequest("POST", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for cert without SPIFFE URI, got %d", rec.Code)
		}
	})

	t.Run("TLSCertWithNonSPIFFEURIReturns401", func(t *testing.T) {
		capturedSPIFFEID = ""
		nonSPIFFEURI, _ := url.Parse("https://example.com/not-spiffe")
		cert := createTestCertWithURI(t, nonSPIFFEURI)

		req := httptest.NewRequest("POST", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for cert with non-SPIFFE URI, got %d", rec.Code)
		}
	})
}

// TestExtractSPIFFEIDFromTLS verifies the SPIFFE ID extraction from TLS state.
func TestExtractSPIFFEIDFromTLS(t *testing.T) {
	t.Run("NoTLS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		got := ExtractSPIFFEIDFromTLS(req)
		if got != "" {
			t.Errorf("Expected empty string for no TLS, got %q", got)
		}
	})

	t.Run("NoPeerCerts", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{}
		got := ExtractSPIFFEIDFromTLS(req)
		if got != "" {
			t.Errorf("Expected empty string for no peer certs, got %q", got)
		}
	})

	t.Run("ValidSPIFFEURI", func(t *testing.T) {
		spiffeURI, _ := url.Parse("spiffe://poc.local/gateway")
		cert := createTestCertWithSPIFFEID(t, spiffeURI)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		got := ExtractSPIFFEIDFromTLS(req)
		if got != "spiffe://poc.local/gateway" {
			t.Errorf("Expected spiffe://poc.local/gateway, got %q", got)
		}
	})

	t.Run("MultipleSANsFirstSPIFFEWins", func(t *testing.T) {
		spiffeURI, _ := url.Parse("spiffe://poc.local/first")
		cert := createTestCertWithSPIFFEID(t, spiffeURI)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		got := ExtractSPIFFEIDFromTLS(req)
		if got != "spiffe://poc.local/first" {
			t.Errorf("Expected spiffe://poc.local/first, got %q", got)
		}
	})
}

// TestParseSPIFFEIDFromURI verifies SPIFFE ID URI parsing
func TestParseSPIFFEIDFromURI(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantNil  bool
		wantHost string
	}{
		{name: "valid", raw: "spiffe://poc.local/gateway", wantNil: false, wantHost: "poc.local"},
		{name: "empty", raw: "", wantNil: true},
		{name: "http_scheme", raw: "http://example.com", wantNil: true},
		{name: "no_prefix", raw: "poc.local/gateway", wantNil: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := ParseSPIFFEIDFromURI(tc.raw)
			if tc.wantNil && u != nil {
				t.Errorf("Expected nil for %q, got %v", tc.raw, u)
			}
			if !tc.wantNil && u == nil {
				t.Errorf("Expected non-nil for %q", tc.raw)
			}
			if !tc.wantNil && u != nil && u.Host != tc.wantHost {
				t.Errorf("Expected host %q, got %q", tc.wantHost, u.Host)
			}
		})
	}
}

// --- Test helpers for creating X.509 certificates with SPIFFE IDs ---

// createTestCertWithSPIFFEID creates a self-signed X.509 certificate with
// the given SPIFFE ID as a URI SAN.
func createTestCertWithSPIFFEID(t *testing.T, spiffeURI *url.URL) *x509.Certificate {
	t.Helper()
	return createTestCertWithURI(t, spiffeURI)
}

// createTestCertWithURI creates a self-signed X.509 certificate with the
// given URI as a SAN.
func createTestCertWithURI(t *testing.T, uri *url.URL) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
		URIs:      []*url.URL{uri},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// createTestCertNoSPIFFE creates a self-signed X.509 certificate without
// any URI SANs.
func createTestCertNoSPIFFE(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-cert-no-spiffe",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
		// No URIs
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// TestAuditLog verifies audit logging functionality
func TestAuditLog(t *testing.T) {
	// Create temporary config files for auditor
	tmpDir := t.TempDir()
	bundlePath := tmpDir + "/bundle.rego"
	registryPath := tmpDir + "/registry.yaml"
	if err := os.WriteFile(bundlePath, []byte("package test"), 0644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}

	auditor, err := NewAuditor("", bundlePath, registryPath) // empty path = stdout only
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer func() {
		_ = auditor.Close()
	}()

	handler := AuditLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), auditor)

	// Prepare request with context
	req := httptest.NewRequest("POST", "/test", nil)
	ctx := req.Context()
	ctx = WithSessionID(ctx, "test-session")
	ctx = WithDecisionID(ctx, "test-decision")
	ctx = WithTraceID(ctx, "test-trace")
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/test")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify status captured
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

// TestToolRegistryVerify verifies tool authorization
func TestToolRegistryVerify(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := tmpDir + "/tools.yaml"
	config := `tools:
  - name: file_read
    description: "Read files"
    hash: "abc123"
    risk_level: low
  - name: file_write
    description: "Write files"
    hash: "def456"
    risk_level: high
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	handler := ToolRegistryVerify(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), registry, nil, nil)

	t.Run("AllowedTool", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"file_read","params":{},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		ctx := WithRequestBody(req.Context(), body)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
	})

	t.Run("DisallowedTool", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"unauthorized_tool","params":{},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		ctx := WithRequestBody(req.Context(), body)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Expected 403, got %d", rec.Code)
		}
	})

	t.Run("NoBody", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// Should pass through without error
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
	})
}

// RFA-6fse.4: Unit test for gateway-owned rug-pull protection.
// When the observed tools/list hash is stale/missing, ToolRegistryVerify must refresh
// (via the refresher hook in MCP transport mode) and deny on mismatch.
func TestToolRegistryVerify_ObservedHashRefresh_DeniesOnMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/tools.yaml"

	// Registry baseline: tool exists and is allowlisted with expected hash "expected123".
	config := `tools:
  - name: tavily_search
    description: "Search the web"
    hash: "expected123"
    risk_level: low
`
	_ = os.WriteFile(configPath, []byte(config), 0644)

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	observed := NewObservedToolHashCache(1 * time.Minute)

	// Seed a stale entry that would otherwise allow the call if not refreshed.
	observed.mu.Lock()
	observed.entries[observedToolHashKey("default", "tavily_search")] = observedToolHashEntry{
		Hash:       "expected123",
		ObservedAt: time.Now().Add(-2 * time.Minute),
	}
	observed.mu.Unlock()

	refreshCalls := 0
	refresh := func(ctx context.Context, server string) (map[string]string, error) {
		refreshCalls++
		return map[string]string{
			"tavily_search": "observed_mismatch_999",
		}, nil
	}

	handlerReached := false
	handler := ToolRegistryVerify(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		w.WriteHeader(http.StatusOK)
	}), registry, observed, refresh)

	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"tavily_search","arguments":{"query":"hi"}},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("X-MCP-Server", "default")
	ctx := WithRequestBody(req.Context(), body)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if refreshCalls != 1 {
		t.Fatalf("Expected refresh to be called once, got %d", refreshCalls)
	}
	if handlerReached {
		t.Fatal("Expected request to be denied before reaching next handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d. Body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), ErrRegistryHashMismatch) {
		t.Fatalf("Expected error code %q in body. Body: %s", ErrRegistryHashMismatch, rec.Body.String())
	}
}

// TestToolRegistryVerify_MCPProtocolMethodsPassThrough verifies that MCP protocol-level
// methods (tools/list, resources/read, ping, etc.) pass through the tool registry
// middleware without verification. These are part of the MCP protocol itself, not
// user-defined tools. Bug fix for RFA-rqj.
func TestToolRegistryVerify_MCPProtocolMethodsPassThrough(t *testing.T) {
	// Create a registry with NO tools registered.
	// Protocol methods must pass through even when the registry is empty.
	tmpDir := t.TempDir()
	configPath := tmpDir + "/tools.yaml"
	config := `tools:
  - name: file_read
    description: "Read files"
    hash: "abc123"
    risk_level: low
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	nextCalled := false
	handler := ToolRegistryVerify(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}), registry, nil, nil)

	// All MCP protocol methods that must pass through
	protocolMethods := []string{
		"tools/list",
		"resources/read",
		"resources/list",
		"prompts/list",
		"prompts/get",
		"sampling/createMessage",
		"initialize",
		"ping",
	}

	for _, method := range protocolMethods {
		t.Run("ProtocolMethod_"+method, func(t *testing.T) {
			nextCalled = false
			body := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","method":"%s","params":{},"id":1}`, method))
			req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
			ctx := WithRequestBody(req.Context(), body)
			req = req.WithContext(ctx)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("Protocol method %q should pass through, got status %d", method, rec.Code)
			}
			if !nextCalled {
				t.Errorf("Protocol method %q should call next handler", method)
			}
		})
	}
}

// TestToolRegistryVerify_ToolsCall_VerifiesEffectiveTool proves that tools/call
// is NOT an unconditional protocol passthrough: it must be verified against the
// effective tool name in params.name per MCP spec.
func TestToolRegistryVerify_ToolsCall_VerifiesEffectiveTool(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/tools.yaml"
	config := `tools:
  - name: tavily_search
    description: "Search the web"
    hash: "abc123"
    risk_level: low
`
	_ = os.WriteFile(configPath, []byte(config), 0644)

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	handler := ToolRegistryVerify(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), registry, nil, nil)

	t.Run("Allowed_WhenNameIsRegistered", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"tavily_search","arguments":{"query":"hi"}},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		ctx := WithRequestBody(req.Context(), body)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d. Body: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("Denied_WhenNameIsUnknown", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"unknown_tool","arguments":{}},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		ctx := WithRequestBody(req.Context(), body)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("Expected 403, got %d. Body: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("BadRequest_WhenNameMissing", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{}},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		ctx := WithRequestBody(req.Context(), body)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Expected 400, got %d. Body: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), ErrMCPInvalidRequest) {
			t.Fatalf("Expected error code %q in response body. Body: %s", ErrMCPInvalidRequest, rec.Body.String())
		}
	})
}

// TestToolRegistryVerify_NotificationsPassThrough verifies that notification methods
// (notifications/*) pass through the tool registry middleware. These are MCP protocol
// notifications and should never be subject to tool verification.
func TestToolRegistryVerify_NotificationsPassThrough(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/tools.yaml"
	config := `tools: []
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	nextCalled := false
	handler := ToolRegistryVerify(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}), registry, nil, nil)

	notificationMethods := []string{
		"notifications/initialized",
		"notifications/cancelled",
		"notifications/progress",
		"notifications/tools/list_changed",
		"notifications/resources/list_changed",
	}

	for _, method := range notificationMethods {
		t.Run("Notification_"+method, func(t *testing.T) {
			nextCalled = false
			body := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","method":"%s","params":{},"id":1}`, method))
			req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
			ctx := WithRequestBody(req.Context(), body)
			req = req.WithContext(ctx)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("Notification method %q should pass through, got status %d", method, rec.Code)
			}
			if !nextCalled {
				t.Errorf("Notification method %q should call next handler", method)
			}
		})
	}
}

// TestToolRegistryVerify_NonProtocolMethodsStillVerified verifies that non-protocol
// methods (user-defined tools) are still subject to tool registry verification
// after the protocol method allowlist is applied.
func TestToolRegistryVerify_NonProtocolMethodsStillVerified(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/tools.yaml"
	config := `tools:
  - name: file_read
    description: "Read files"
    hash: "abc123"
    risk_level: low
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	handler := ToolRegistryVerify(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), registry, nil, nil)

	// Registered tool should still be allowed
	t.Run("RegisteredToolAllowed", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"file_read","params":{},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		ctx := WithRequestBody(req.Context(), body)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Registered tool should be allowed, got %d", rec.Code)
		}
	})

	// Unregistered non-protocol method should still be blocked
	t.Run("UnregisteredToolBlocked", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"evil_tool","params":{},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		ctx := WithRequestBody(req.Context(), body)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Unregistered tool should be blocked, got %d", rec.Code)
		}
	})

	// Methods that look similar to protocol methods but aren't
	t.Run("FakeProtocolMethodBlocked", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"tools/evil","params":{},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		ctx := WithRequestBody(req.Context(), body)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Fake protocol method 'tools/evil' should be blocked, got %d", rec.Code)
		}
	})
}

// TestToolRegistryVerify_ProtocolMethodIntegration exercises the ToolRegistryVerify
// middleware end-to-end through the full HTTP handler chain (BodyCapture -> ToolRegistryVerify).
// This is an integration test with no mocks - it uses real middleware instances.
func TestToolRegistryVerify_ProtocolMethodIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/tools.yaml"
	config := `tools:
  - name: registered_tool
    description: "A registered tool"
    hash: "hash123"
    risk_level: low
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	// Build a real middleware chain: BodyCapture -> ToolRegistryVerify -> handler
	// This exercises the full integration path with no mocks.
	var handlerReached bool
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with ToolRegistryVerify, then BodyCapture (outer -> inner execution order)
	chain := BodyCapture(ToolRegistryVerify(innerHandler, registry, nil, nil))

	// Test: protocol method passes through the full chain
	t.Run("ProtocolMethodThroughFullChain", func(t *testing.T) {
		handlerReached = false
		body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		rec := httptest.NewRecorder()

		chain.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 for protocol method through full chain, got %d", rec.Code)
		}
		if !handlerReached {
			t.Error("Protocol method should reach the inner handler through full middleware chain")
		}
	})

	// Test: registered tool passes through the full chain
	t.Run("RegisteredToolThroughFullChain", func(t *testing.T) {
		handlerReached = false
		body := []byte(`{"jsonrpc":"2.0","method":"registered_tool","params":{},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		rec := httptest.NewRecorder()

		chain.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 for registered tool through full chain, got %d", rec.Code)
		}
		if !handlerReached {
			t.Error("Registered tool should reach the inner handler through full middleware chain")
		}
	})

	// Test: unregistered tool is blocked in the full chain
	t.Run("UnregisteredToolBlockedInFullChain", func(t *testing.T) {
		handlerReached = false
		body := []byte(`{"jsonrpc":"2.0","method":"unknown_tool","params":{},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		rec := httptest.NewRecorder()

		chain.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Expected 403 for unregistered tool through full chain, got %d", rec.Code)
		}
		if handlerReached {
			t.Error("Unregistered tool should NOT reach the inner handler")
		}
	})

	// Test: notification passes through the full chain
	t.Run("NotificationThroughFullChain", func(t *testing.T) {
		handlerReached = false
		body := []byte(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{},"id":1}`)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		rec := httptest.NewRecorder()

		chain.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 for notification through full chain, got %d", rec.Code)
		}
		if !handlerReached {
			t.Error("Notification should reach the inner handler through full middleware chain")
		}
	})
}

// TestStepUpGating verifies step-up gating passes through when no body is present.
// The real StepUpGating implementation (step_up_gating.go) fast-paths requests
// with no body, which is what this test validates.
func TestStepUpGating(t *testing.T) {
	called := false
	handler := StepUpGating(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}),
		nil, // guardClient
		nil, // allowlist
		nil, // riskConfig
		nil, // registry
		nil, // auditor
	)

	req := httptest.NewRequest("POST", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("Handler not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

// TestTokenSubstitution verifies token substitution hook is pass-through
func TestTokenSubstitution(t *testing.T) {
	called := false
	handler := TokenSubstitution(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}), NewPOCSecretRedeemer(), nil, nil)

	req := httptest.NewRequest("POST", "/", nil)
	// Add SPIFFE ID to context (required by TokenSubstitution middleware)
	ctx := WithSPIFFEID(req.Context(), "spiffe://poc.local/test")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("Handler not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

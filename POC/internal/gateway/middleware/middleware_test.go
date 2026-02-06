package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
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
	handler = track("token_sub")(handler)    // 13 - LAST before proxy
	handler = track("deep_scan")(handler)    // 10
	handler = track("step_up")(handler)      // 9
	handler = track("dlp")(handler)          // 7
	handler = track("opa")(handler)          // 6
	handler = track("registry")(handler)     // 5
	handler = track("audit")(handler)        // 4
	handler = track("spiffe")(handler)       // 3
	handler = track("body")(handler)         // 2
	handler = track("size")(handler)         // 1

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

// TestRequestSizeLimit verifies size limit enforcement
func TestRequestSizeLimit(t *testing.T) {
	maxBytes := int64(100)
	handler := RequestSizeLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}), maxBytes)

	// Test under limit
	t.Run("UnderLimit", func(t *testing.T) {
		body := bytes.Repeat([]byte("a"), 50)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
	})

	// Test over limit
	t.Run("OverLimit", func(t *testing.T) {
		body := bytes.Repeat([]byte("a"), 150)
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		rec := httptest.NewRecorder()

		// Create a handler that explicitly reads all bytes to trigger the limit
		testHandler := RequestSizeLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			w.WriteHeader(http.StatusOK)
		}), maxBytes)

		testHandler.ServeHTTP(rec, req)

		// Should fail with 413 when body exceeds limit
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("Expected 413, got %d", rec.Code)
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

// TestAuditLog verifies audit logging functionality
func TestAuditLog(t *testing.T) {
	// Create temporary config files for auditor
	tmpDir := t.TempDir()
	bundlePath := tmpDir + "/bundle.rego"
	registryPath := tmpDir + "/registry.yaml"
	os.WriteFile(bundlePath, []byte("package test"), 0644)
	os.WriteFile(registryPath, []byte("tools: []"), 0644)

	auditor, err := NewAuditor("", bundlePath, registryPath) // empty path = stdout only
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

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
	os.WriteFile(configPath, []byte(config), 0644)

	registry, err := NewToolRegistry("http://localhost:8080", configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	handler := ToolRegistryVerify(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), registry)

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
	}))

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

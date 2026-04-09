// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// mockHandleStore is a test implementation of the HandleStore interface
type mockHandleStore struct {
	entries  map[string][]byte
	lastRef  string
	storeErr error
}

func newMockHandleStore() *mockHandleStore {
	return &mockHandleStore{
		entries: make(map[string][]byte),
	}
}

func (m *mockHandleStore) Store(rawData []byte, spiffeID, toolName string) (string, error) {
	if m.storeErr != nil {
		return "", m.storeErr
	}
	ref := "mock_ref_" + toolName
	m.entries[ref] = rawData
	m.lastRef = ref
	return ref, nil
}

// TestClassifyTool verifies the risk_level to classification mapping
func TestClassifyTool(t *testing.T) {
	// Create temporary config file with tools of various risk levels
	tmpDir := t.TempDir()
	configPath := tmpDir + "/tools.yaml"
	config := `tools:
  - name: "public_tool"
    description: "A public tool"
    hash: "abc123"
    risk_level: "low"
  - name: "internal_tool"
    description: "An internal tool"
    hash: "def456"
    risk_level: "medium"
  - name: "sensitive_tool"
    description: "A sensitive tool"
    hash: "ghi789"
    risk_level: "high"
  - name: "critical_tool"
    description: "A critical tool"
    hash: "jkl012"
    risk_level: "critical"
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	tests := []struct {
		toolName    string
		expected    ResponseClassification
		description string
	}{
		{"public_tool", ClassificationPublic, "low risk -> public"},
		{"internal_tool", ClassificationInternal, "medium risk -> internal"},
		{"sensitive_tool", ClassificationSensitive, "high risk -> sensitive"},
		{"critical_tool", ClassificationSensitive, "critical risk -> sensitive"},
		{"unknown_tool", ClassificationInternal, "unknown tool -> internal (conservative)"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			result := ClassifyTool(registry, tt.toolName)
			if result != tt.expected {
				t.Errorf("ClassifyTool(%q) = %q, want %q", tt.toolName, result, tt.expected)
			}
		})
	}
}

// TestResponseFirewallPublicTool verifies that public tool responses pass through unchanged
func TestResponseFirewallPublicTool(t *testing.T) {
	registry := setupTestRegistry(t, "low") // low = public
	store := newMockHandleStore()

	// Upstream handler that returns some data
	upstreamResponse := `{"result": "public data"}`
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})

	handler := ResponseFirewall(upstream, registry, store, 300)

	// Build request with tool name in body context
	body := []byte(`{"jsonrpc":"2.0","method":"test_tool","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	ctx := WithRequestBody(req.Context(), body)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Response should pass through unchanged
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != upstreamResponse {
		t.Errorf("Expected unchanged response %q, got %q", upstreamResponse, rec.Body.String())
	}

	// No handle should have been created
	if len(store.entries) != 0 {
		t.Errorf("Expected no handles for public tool, got %d", len(store.entries))
	}
}

// TestResponseFirewallInternalTool verifies that internal tool responses pass through unchanged
func TestResponseFirewallInternalTool(t *testing.T) {
	registry := setupTestRegistry(t, "medium") // medium = internal
	store := newMockHandleStore()

	upstreamResponse := `{"result": "internal data"}`
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})

	handler := ResponseFirewall(upstream, registry, store, 300)

	body := []byte(`{"jsonrpc":"2.0","method":"test_tool","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	ctx := WithRequestBody(req.Context(), body)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != upstreamResponse {
		t.Errorf("Expected unchanged response %q, got %q", upstreamResponse, rec.Body.String())
	}

	// No handle should have been created for internal tools
	if len(store.entries) != 0 {
		t.Errorf("Expected no handles for internal tool, got %d", len(store.entries))
	}
}

// TestResponseFirewallSensitiveTool verifies that sensitive tool responses are handle-ized
func TestResponseFirewallSensitiveTool(t *testing.T) {
	registry := setupTestRegistry(t, "high") // high = sensitive
	store := newMockHandleStore()

	sensitiveData := `{"transactions": [{"id": 1, "amount": 50000, "ssn": "123-45-6789"}]}`
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sensitiveData))
	})

	handler := ResponseFirewall(upstream, registry, store, 300)

	body := []byte(`{"jsonrpc":"2.0","method":"test_tool","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test/dev")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Response should be 200 with handle-ized content
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}

	// Parse the handle-ized response
	var handleResp HandleizedResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &handleResp); err != nil {
		t.Fatalf("Failed to parse handle-ized response: %v", err)
	}

	// Verify the response is handle-ized, NOT the raw sensitive data
	if handleResp.Classification != "sensitive" {
		t.Errorf("Expected classification 'sensitive', got %q", handleResp.Classification)
	}
	if handleResp.DataHandle == "" {
		t.Error("Expected non-empty data_handle")
	}
	if handleResp.Summary == "" {
		t.Error("Expected non-empty summary")
	}

	// Verify the response does NOT contain raw sensitive data
	respStr := rec.Body.String()
	if bytes.Contains([]byte(respStr), []byte("123-45-6789")) {
		t.Error("Response should NOT contain raw sensitive data (SSN)")
	}
	if bytes.Contains([]byte(respStr), []byte("50000")) {
		t.Error("Response should NOT contain raw sensitive data (amount)")
	}

	// Verify the handle store received the raw data
	if len(store.entries) != 1 {
		t.Errorf("Expected 1 handle stored, got %d", len(store.entries))
	}
	storedData := store.entries[store.lastRef]
	if string(storedData) != sensitiveData {
		t.Errorf("Stored data mismatch: expected %q, got %q", sensitiveData, string(storedData))
	}

	// Verify response headers
	if rec.Header().Get("X-Response-Classification") != "sensitive" {
		t.Errorf("Expected X-Response-Classification header 'sensitive', got %q", rec.Header().Get("X-Response-Classification"))
	}
	if rec.Header().Get("X-Data-Handle") == "" {
		t.Error("Expected X-Data-Handle header to be set")
	}
}

// TestResponseFirewallSensitiveUpstreamError verifies that upstream errors pass through even for sensitive tools
func TestResponseFirewallSensitiveUpstreamError(t *testing.T) {
	registry := setupTestRegistry(t, "high") // high = sensitive
	store := newMockHandleStore()

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	})

	handler := ResponseFirewall(upstream, registry, store, 300)

	body := []byte(`{"jsonrpc":"2.0","method":"test_tool","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	ctx := WithRequestBody(req.Context(), body)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Error responses from upstream should pass through as-is
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", rec.Code)
	}

	// No handle should be created for error responses
	if len(store.entries) != 0 {
		t.Errorf("Expected no handles for error response, got %d", len(store.entries))
	}
}

func TestResponseFirewallSensitiveToolStoreFailureFailsClosed(t *testing.T) {
	registry := setupTestRegistry(t, "high")
	store := &mockHandleStore{
		entries:  make(map[string][]byte),
		storeErr: errors.New("handle store unavailable"),
	}

	sensitiveData := `{"transactions": [{"id": 1, "amount": 50000, "ssn": "123-45-6789"}]}`
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sensitiveData))
	})

	handler := ResponseFirewall(upstream, registry, store, 300)
	body := []byte(`{"jsonrpc":"2.0","method":"test_tool","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test/dev")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Expected 503, got %d", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("123-45-6789")) {
		t.Fatal("Response should not contain raw sensitive data when handle store fails")
	}

	var ge GatewayError
	if err := json.Unmarshal(rec.Body.Bytes(), &ge); err != nil {
		t.Fatalf("failed to decode gateway error: %v body=%q", err, rec.Body.String())
	}
	if ge.Code != ErrResponseHandleStoreUnavailable {
		t.Fatalf("expected code %q, got %q", ErrResponseHandleStoreUnavailable, ge.Code)
	}
	if ge.ReasonCode != "handle_store_unavailable" {
		t.Fatalf("expected reason_code handle_store_unavailable, got %q", ge.ReasonCode)
	}
	if ge.Middleware != "response_firewall" {
		t.Fatalf("expected middleware response_firewall, got %q", ge.Middleware)
	}
	if ge.MiddlewareStep != 14 {
		t.Fatalf("expected middleware_step 14, got %d", ge.MiddlewareStep)
	}
}

func TestResponseFirewallSensitiveToolMarshalFailureFailsClosed(t *testing.T) {
	registry := setupTestRegistry(t, "high")
	store := newMockHandleStore()

	orig := marshalHandleizedResponse
	marshalHandleizedResponse = func(v any) ([]byte, error) {
		return nil, errors.New("marshal exploded")
	}
	t.Cleanup(func() { marshalHandleizedResponse = orig })

	sensitiveData := `{"transactions": [{"id": 1, "amount": 50000, "ssn": "123-45-6789"}]}`
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sensitiveData))
	})

	handler := ResponseFirewall(upstream, registry, store, 300)
	body := []byte(`{"jsonrpc":"2.0","method":"test_tool","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test/dev")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("123-45-6789")) {
		t.Fatal("Response should not contain raw sensitive data when marshal fails")
	}

	var ge GatewayError
	if err := json.Unmarshal(rec.Body.Bytes(), &ge); err != nil {
		t.Fatalf("failed to decode gateway error: %v body=%q", err, rec.Body.String())
	}
	if ge.Code != ErrResponseHandleizationFailed {
		t.Fatalf("expected code %q, got %q", ErrResponseHandleizationFailed, ge.Code)
	}
	if ge.ReasonCode != "handleization_failed" {
		t.Fatalf("expected reason_code handleization_failed, got %q", ge.ReasonCode)
	}
	if ge.Middleware != "response_firewall" {
		t.Fatalf("expected middleware response_firewall, got %q", ge.Middleware)
	}
	if ge.MiddlewareStep != 14 {
		t.Fatalf("expected middleware_step 14, got %d", ge.MiddlewareStep)
	}
}

// TestResponseFirewallNoBody verifies that requests without tool name pass through
func TestResponseFirewallNoBody(t *testing.T) {
	registry := setupTestRegistry(t, "high")
	store := newMockHandleStore()

	upstreamResponse := `{"result": "data"}`
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})

	handler := ResponseFirewall(upstream, registry, store, 300)

	// Request with no body in context
	req := httptest.NewRequest("POST", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should pass through
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != upstreamResponse {
		t.Errorf("Expected unchanged response, got %q", rec.Body.String())
	}
}

// TestResponseFirewallCriticalToolIsSensitive verifies that critical risk tools are also handle-ized
func TestResponseFirewallCriticalToolIsSensitive(t *testing.T) {
	registry := setupTestRegistry(t, "critical") // critical = sensitive
	store := newMockHandleStore()

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"secret": "value"}`))
	})

	handler := ResponseFirewall(upstream, registry, store, 300)

	body := []byte(`{"jsonrpc":"2.0","method":"test_tool","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test/dev")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should be handle-ized
	var handleResp HandleizedResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &handleResp); err != nil {
		t.Fatalf("Failed to parse handle-ized response: %v", err)
	}

	if handleResp.Classification != "sensitive" {
		t.Errorf("Expected classification 'sensitive', got %q", handleResp.Classification)
	}
	if handleResp.DataHandle == "" {
		t.Error("Expected non-empty data_handle for critical tool")
	}
}

// TestExtractToolName verifies tool name extraction from context
func TestExtractToolName(t *testing.T) {
	t.Run("MethodField", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"my_tool","params":{},"id":1}`)
		req := httptest.NewRequest("POST", "/", nil)
		ctx := WithRequestBody(req.Context(), body)

		name := extractToolName(ctx)
		if name != "my_tool" {
			t.Errorf("Expected 'my_tool', got %q", name)
		}
	})

	t.Run("ToolParam", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"","params":{"tool":"param_tool"},"id":1}`)
		req := httptest.NewRequest("POST", "/", nil)
		ctx := WithRequestBody(req.Context(), body)

		name := extractToolName(ctx)
		if name != "param_tool" {
			t.Errorf("Expected 'param_tool', got %q", name)
		}
	})

	t.Run("NoBody", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		name := extractToolName(req.Context())
		if name != "" {
			t.Errorf("Expected empty string, got %q", name)
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		body := []byte(`not json`)
		req := httptest.NewRequest("POST", "/", nil)
		ctx := WithRequestBody(req.Context(), body)

		name := extractToolName(ctx)
		if name != "" {
			t.Errorf("Expected empty string for invalid JSON, got %q", name)
		}
	})
}

// TestFormatDataHandle verifies the handle format string
func TestFormatDataHandle(t *testing.T) {
	result := formatDataHandle("abc123", 300)
	expected := "$DATA{ref:abc123,exp:300}"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// setupTestRegistry creates a ToolRegistry with a single tool at the given risk level
func setupTestRegistry(t *testing.T, riskLevel string) *ToolRegistry {
	t.Helper()
	tmpDir := t.TempDir()
	configPath := tmpDir + "/tools.yaml"
	config := `tools:
  - name: "test_tool"
    description: "A test tool"
    hash: "test_hash_123"
    risk_level: "` + riskLevel + `"
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}
	return registry
}

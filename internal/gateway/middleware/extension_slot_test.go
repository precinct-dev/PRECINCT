package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestExtensionSlot_NoExtensionsPassthrough(t *testing.T) {
	// Empty registry -- the slot middleware should call next directly.
	reg := emptyExtensionRegistry(t)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := ExtensionSlot(next, reg, SlotPostAuthz, nil)

	req := httptest.NewRequest("POST", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("next handler was not called for empty slot")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestExtensionSlot_AllowDecision(t *testing.T) {
	// Extension returns "allow" -- request should pass through.
	server := extensionServer(t, ExtensionResponse{
		Version:  "1",
		Decision: "allow",
		Reason:   "all clear",
	})

	reg := extensionRegistryWithServer(t, SlotPostInspection, "allow_ext", server.URL)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := ExtensionSlot(next, reg, SlotPostInspection, nil)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	ctx := WithRequestBody(req.Context(), []byte(body))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("next handler was not called for allow decision")
	}
}

func TestExtensionSlot_BlockDecision(t *testing.T) {
	server := extensionServer(t, ExtensionResponse{
		Version:  "1",
		Decision: "block",
		Reason:   "unsafe pattern detected",
	})

	reg := extensionRegistryWithServer(t, SlotPostInspection, "block_ext", server.URL)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	handler := ExtensionSlot(next, reg, SlotPostInspection, nil)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	ctx := WithRequestBody(req.Context(), []byte(body))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("next handler should NOT be called for block decision")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}

	var ge GatewayError
	if err := json.Unmarshal(rec.Body.Bytes(), &ge); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	if ge.Code != ErrExtensionBlocked {
		t.Errorf("error code = %q, want %q", ge.Code, ErrExtensionBlocked)
	}
}

func TestExtensionSlot_FlagDecision(t *testing.T) {
	server := extensionServer(t, ExtensionResponse{
		Version:  "1",
		Decision: "flag",
		Flags:    []string{"skulto_safe", "markdown_valid"},
		Reason:   "flagged for audit",
	})

	reg := extensionRegistryWithServer(t, SlotPostInspection, "flag_ext", server.URL)

	collector := &SecurityFlagsCollector{}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := ExtensionSlot(next, reg, SlotPostInspection, nil)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	ctx := WithRequestBody(req.Context(), []byte(body))
	ctx = WithFlagsCollector(ctx, collector)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("next handler should be called for flag decision")
	}

	// Verify flags were propagated to the collector.
	if len(collector.Flags) != 2 {
		t.Fatalf("expected 2 flags, got %d: %v", len(collector.Flags), collector.Flags)
	}
	if collector.Flags[0] != "skulto_safe" || collector.Flags[1] != "markdown_valid" {
		t.Errorf("flags = %v, want [skulto_safe, markdown_valid]", collector.Flags)
	}
}

func TestExtensionSlot_FailOpen(t *testing.T) {
	// Extension server is unreachable (use bad URL).
	reg := extensionRegistryWithServerAndFailMode(t, SlotPostAuthz, "fail_open_ext", "http://127.0.0.1:1", "fail_open")

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := ExtensionSlot(next, reg, SlotPostAuthz, nil)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	ctx := WithRequestBody(req.Context(), []byte(body))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("next handler should be called for fail_open on error")
	}
}

func TestExtensionSlot_FailClosed(t *testing.T) {
	reg := extensionRegistryWithServerAndFailMode(t, SlotPostAuthz, "fail_closed_ext", "http://127.0.0.1:1", "fail_closed")

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	handler := ExtensionSlot(next, reg, SlotPostAuthz, nil)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	ctx := WithRequestBody(req.Context(), []byte(body))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("next handler should NOT be called for fail_closed on error")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestExtensionSlot_PriorityOrdering(t *testing.T) {
	// Two extensions in the same slot; verify they execute in priority order.
	var callOrder []string

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callOrder = append(callOrder, "first")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ExtensionResponse{
			Version: "1", Decision: "allow",
		})
	}))
	t.Cleanup(server1.Close)

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callOrder = append(callOrder, "second")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ExtensionResponse{
			Version: "1", Decision: "allow",
		})
	}))
	t.Cleanup(server2.Close)

	yaml := `
version: "1"
extensions:
  - name: "second_ext"
    slot: "post_authz"
    enabled: true
    endpoint: "` + server2.URL + `"
    timeout_ms: 5000
    fail_mode: "fail_open"
    priority: 200
  - name: "first_ext"
    slot: "post_authz"
    enabled: true
    endpoint: "` + server1.URL + `"
    timeout_ms: 5000
    fail_mode: "fail_open"
    priority: 100
`
	dir := t.TempDir()
	path := filepath.Join(dir, "extensions.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write YAML: %v", err)
	}
	reg, err := NewExtensionRegistry(path)
	if err != nil {
		t.Fatalf("NewExtensionRegistry: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := ExtensionSlot(next, reg, SlotPostAuthz, nil)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	ctx := WithRequestBody(req.Context(), []byte(body))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if len(callOrder) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(callOrder))
	}
	if callOrder[0] != "first" || callOrder[1] != "second" {
		t.Errorf("call order = %v, want [first, second]", callOrder)
	}
}

func TestExtensionSlot_FilterSkipsNonMatching(t *testing.T) {
	// Extension only matches tools/call, but request is tools/list.
	var called int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&called, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ExtensionResponse{
			Version: "1", Decision: "block", Reason: "should not reach",
		})
	}))
	t.Cleanup(server.Close)

	yaml := `
version: "1"
extensions:
  - name: "tools_only"
    slot: "post_authz"
    enabled: true
    endpoint: "` + server.URL + `"
    timeout_ms: 5000
    fail_mode: "fail_closed"
    priority: 100
    filters:
      methods: ["tools/call"]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "extensions.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write YAML: %v", err)
	}
	reg, err := NewExtensionRegistry(path)
	if err != nil {
		t.Fatalf("NewExtensionRegistry: %v", err)
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := ExtensionSlot(next, reg, SlotPostAuthz, nil)
	body := `{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	ctx := WithRequestBody(req.Context(), []byte(body))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("next handler should be called when filter doesn't match")
	}
	if atomic.LoadInt32(&called) != 0 {
		t.Error("extension server should not have been called")
	}
}

func TestExtensionSlot_RequestFieldRedaction(t *testing.T) {
	// Extension with include_body=false should not receive body in payload.
	var receivedReq ExtensionRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedReq)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ExtensionResponse{
			Version: "1", Decision: "allow",
		})
	}))
	t.Cleanup(server.Close)

	yaml := `
version: "1"
extensions:
  - name: "no_body"
    slot: "post_authz"
    enabled: true
    endpoint: "` + server.URL + `"
    timeout_ms: 5000
    fail_mode: "fail_open"
    priority: 100
    request_fields:
      include_body: false
      include_spiffe_id: true
      include_tool_name: true
      include_security_flags: false
`
	dir := t.TempDir()
	path := filepath.Join(dir, "extensions.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write YAML: %v", err)
	}
	reg, err := NewExtensionRegistry(path)
	if err != nil {
		t.Fatalf("NewExtensionRegistry: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := ExtensionSlot(next, reg, SlotPostAuthz, nil)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	ctx := WithRequestBody(req.Context(), []byte(body))
	ctx = context.WithValue(ctx, contextKeySPIFFEID, "spiffe://test/agent")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if receivedReq.Request.Body != "" {
		t.Error("body should be empty when include_body=false")
	}
	if receivedReq.Request.SPIFFEID != "spiffe://test/agent" {
		t.Errorf("spiffe_id = %q, want spiffe://test/agent", receivedReq.Request.SPIFFEID)
	}
	if receivedReq.Request.ToolName != "read_file" {
		t.Errorf("tool_name = %q, want read_file", receivedReq.Request.ToolName)
	}
	if receivedReq.Slot != SlotPostAuthz {
		t.Errorf("slot = %q, want post_authz", receivedReq.Slot)
	}
}

func TestExtensionSlot_BlockWithCustomHTTPStatus(t *testing.T) {
	server := extensionServer(t, ExtensionResponse{
		Version:    "1",
		Decision:   "block",
		Reason:     "custom status",
		HTTPStatus: 429,
		ErrorCode:  "ext_custom_rate_limit",
	})

	reg := extensionRegistryWithServer(t, SlotPostAnalysis, "custom_status_ext", server.URL)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := ExtensionSlot(next, reg, SlotPostAnalysis, nil)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	ctx := WithRequestBody(req.Context(), []byte(body))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 429 {
		t.Errorf("status = %d, want 429", rec.Code)
	}
	var ge GatewayError
	if err := json.Unmarshal(rec.Body.Bytes(), &ge); err != nil {
		t.Fatalf("failed to parse error: %v", err)
	}
	if ge.Code != "ext_custom_rate_limit" {
		t.Errorf("error code = %q, want ext_custom_rate_limit", ge.Code)
	}
}

// --- Test helpers ---

func emptyExtensionRegistry(t *testing.T) *ExtensionRegistry {
	t.Helper()
	yaml := `
version: "1"
extensions: []
`
	dir := t.TempDir()
	path := filepath.Join(dir, "extensions.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write YAML: %v", err)
	}
	reg, err := NewExtensionRegistry(path)
	if err != nil {
		t.Fatalf("NewExtensionRegistry: %v", err)
	}
	return reg
}

func extensionServer(t *testing.T, resp ExtensionResponse) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)
	return server
}

func extensionRegistryWithServer(t *testing.T, slot ExtensionSlotName, name, endpoint string) *ExtensionRegistry {
	t.Helper()
	return extensionRegistryWithServerAndFailMode(t, slot, name, endpoint, "fail_closed")
}

func extensionRegistryWithServerAndFailMode(t *testing.T, slot ExtensionSlotName, name, endpoint, failMode string) *ExtensionRegistry {
	t.Helper()
	yaml := `
version: "1"
extensions:
  - name: "` + name + `"
    slot: "` + string(slot) + `"
    enabled: true
    endpoint: "` + endpoint + `"
    timeout_ms: 5000
    fail_mode: "` + failMode + `"
    priority: 100
    request_fields:
      include_body: true
      include_spiffe_id: true
      include_tool_name: true
      include_security_flags: true
`
	dir := t.TempDir()
	path := filepath.Join(dir, "extensions.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("failed to write YAML: %v", err)
	}
	reg, err := NewExtensionRegistry(path)
	if err != nil {
		t.Fatalf("NewExtensionRegistry: %v", err)
	}
	return reg
}

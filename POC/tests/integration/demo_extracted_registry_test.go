//go:build integration
// +build integration

// Demo-extracted tool registry integration tests.
// Extracts deterministic tool registry assertions from demo/go/main.go into
// httptest-based integration tests using the real tool registry loaded from
// config/tool-registry.yaml.
//
// Covers demo assertions:
// - Unregistered tool (registry rejection)   -- testUnregisteredTool
// - Request size limit (11 MB payload)       -- testRequestSizeLimit
// - Invalid tools/call missing params.name   -- testInvalidToolsCallMissingNameRejected

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
	"github.com/RamXX/agentic_reference_architecture/POC/internal/testutil"
)

// buildRegistryChain constructs a middleware chain with real tool registry,
// SPIFFE auth, body capture, and optional size limit. This exercises the
// actual tool-registry.yaml config without Docker Compose.
func buildRegistryChain(t *testing.T) http.Handler {
	t.Helper()

	configPath := testutil.ToolRegistryConfigPath()
	registry, err := middleware.NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create tool registry: %v", err)
	}

	// Build observed hash cache with entries matching the registry baseline
	// so that registered tools pass the rug-pull check.
	observed := middleware.NewObservedToolHashCache(5 * time.Minute)
	for _, name := range registry.ToolNames() {
		def, _ := registry.GetToolDefinition(name)
		observed.Set("default", name, def.Hash)
	}

	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"reached_terminal"}`))
	})

	// Build chain: BodyCapture -> SPIFFEAuth -> ToolRegistry -> terminal
	handler := middleware.ToolRegistryVerify(terminal, registry, observed, nil)
	handler = middleware.SPIFFEAuth(handler, "dev")
	handler = middleware.BodyCapture(handler)

	return handler
}

// buildSizeLimitChain constructs a minimal chain with RequestSizeLimit at step 1.
func buildSizeLimitChain(maxBytes int64) http.Handler {
	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"reached_terminal"}`))
	})

	// Size limit is step 1 -- wraps everything else.
	handler := middleware.BodyCapture(terminal)
	handler = middleware.RequestSizeLimit(handler, maxBytes)

	return handler
}

// registryMCPRequest builds a tools/call JSON-RPC request for registry testing.
func registryMCPRequest(tool string, params map[string]any) string {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      tool,
			"arguments": params,
		},
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

// ---------------------------------------------------------------------------
// Demo assertion: Unregistered tool (registry rejection)
// ---------------------------------------------------------------------------

// TestDemoExtracted_Registry_UnregisteredToolDenied mirrors demo test
// "Unregistered tool (registry rejection)".
// Sends a request for "not_a_real_tool" which does not exist in tool-registry.yaml.
// The tool registry middleware should reject it with 403.
func TestDemoExtracted_Registry_UnregisteredToolDenied(t *testing.T) {
	handler := buildRegistryChain(t)

	body := registryMCPRequest("not_a_real_tool", map[string]any{})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("Expected HTTP 403 for unregistered tool, got %d: %s", rr.Code, rr.Body.String())
	}

	var ge middleware.GatewayError
	if err := json.Unmarshal(rr.Body.Bytes(), &ge); err != nil {
		t.Fatalf("Failed to parse error: %v", err)
	}
	if ge.Code != middleware.ErrRegistryToolUnknown {
		t.Errorf("Expected code=%s, got %s", middleware.ErrRegistryToolUnknown, ge.Code)
	}
	t.Logf("PASS: Unregistered tool denied, code=%s, step=%d", ge.Code, ge.MiddlewareStep)
}

// ---------------------------------------------------------------------------
// Demo assertion: Registered tool passes (positive path)
// ---------------------------------------------------------------------------

// TestDemoExtracted_Registry_RegisteredToolAllowed verifies that a tool
// registered in tool-registry.yaml passes the registry check. This is the
// positive-path complement to the unregistered tool test.
func TestDemoExtracted_Registry_RegisteredToolAllowed(t *testing.T) {
	handler := buildRegistryChain(t)

	body := registryMCPRequest("tavily_search", map[string]any{"query": "test"})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Fatalf("Registered tool should be allowed, got 403: %s", rr.Body.String())
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 for registered tool, got %d: %s", rr.Code, rr.Body.String())
	}
	t.Logf("PASS: Registered tool tavily_search allowed (HTTP %d)", rr.Code)
}

// ---------------------------------------------------------------------------
// Demo assertion: Invalid tools/call missing params.name (fail-closed)
// ---------------------------------------------------------------------------

// TestDemoExtracted_Registry_InvalidToolsCallMissingName mirrors demo test
// "MCP spec: invalid tools/call is rejected (fail-closed)".
// Sends a tools/call without params.name. The tool registry should reject it
// with HTTP 400 and code=mcp_invalid_request.
func TestDemoExtracted_Registry_InvalidToolsCallMissingName(t *testing.T) {
	handler := buildRegistryChain(t)

	// Intentionally malformed: tools/call without params.name
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      999,
		"method":  "tools/call",
		"params": map[string]any{
			"arguments": map[string]any{"query": "AI security"},
		},
	}
	b, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected HTTP 400 for invalid tools/call, got %d: %s", rr.Code, rr.Body.String())
	}

	var ge middleware.GatewayError
	if err := json.Unmarshal(rr.Body.Bytes(), &ge); err != nil {
		t.Fatalf("Failed to parse error: %v", err)
	}
	if ge.Code != middleware.ErrMCPInvalidRequest {
		t.Errorf("Expected code=%s, got %s", middleware.ErrMCPInvalidRequest, ge.Code)
	}
	t.Logf("PASS: Invalid tools/call rejected with code=%s (fail-closed)", ge.Code)
}

// ---------------------------------------------------------------------------
// Demo assertion: Request size limit (11 MB payload)
// ---------------------------------------------------------------------------

// TestDemoExtracted_Registry_RequestSizeLimit mirrors demo test
// "Request size limit (11 MB payload)".
// Sends an 11 MB payload. The RequestSizeLimit middleware (step 1) should
// reject it with 413.
func TestDemoExtracted_Registry_RequestSizeLimit(t *testing.T) {
	// 10 MB limit, matching the gateway's production config.
	handler := buildSizeLimitChain(10 * 1024 * 1024)

	bigPayload := strings.Repeat("A", 11*1024*1024) // 11 MB
	body := registryMCPRequest("read", map[string]any{"file_path": bigPayload})

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("Expected HTTP 413 for oversized payload, got %d: %s", rr.Code, rr.Body.String())
	}

	var ge middleware.GatewayError
	if err := json.Unmarshal(rr.Body.Bytes(), &ge); err != nil {
		t.Fatalf("Failed to parse error: %v", err)
	}
	if ge.Code != middleware.ErrRequestTooLarge {
		t.Errorf("Expected code=%s, got %s", middleware.ErrRequestTooLarge, ge.Code)
	}
	if ge.MiddlewareStep != 1 {
		t.Errorf("Expected middleware_step=1, got %d", ge.MiddlewareStep)
	}
	t.Logf("PASS: Oversized payload rejected at step %d with code=%s", ge.MiddlewareStep, ge.Code)
}

// ---------------------------------------------------------------------------
// Demo assertion: Hash mismatch rejected
// ---------------------------------------------------------------------------

// TestDemoExtracted_Registry_HashMismatchRejected verifies that providing
// a mismatched tool_hash results in rejection. This is the registry
// equivalent of the demo's rug-pull detection.
func TestDemoExtracted_Registry_HashMismatchRejected(t *testing.T) {
	handler := buildRegistryChain(t)

	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "read",
			"arguments": map[string]any{
				"file_path": testutil.ProjectRoot() + "/README.md",
			},
			"tool_hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		},
	}
	b, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("Expected HTTP 403 for hash mismatch, got %d: %s", rr.Code, rr.Body.String())
	}

	var ge middleware.GatewayError
	if err := json.Unmarshal(rr.Body.Bytes(), &ge); err != nil {
		t.Fatalf("Failed to parse error: %v", err)
	}
	// Accept either registry_hash_mismatch or registry_tool_unknown (poisoning check may trigger)
	if ge.Code != middleware.ErrRegistryHashMismatch && ge.Code != middleware.ErrRegistryToolUnknown {
		t.Errorf("Expected code=%s or %s, got %s", middleware.ErrRegistryHashMismatch, middleware.ErrRegistryToolUnknown, ge.Code)
	}
	t.Logf("PASS: Hash mismatch rejected, code=%s", ge.Code)
}

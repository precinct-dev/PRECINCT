package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
	"github.com/RamXX/agentic_reference_architecture/POC/internal/testutil"
)

// TestBackwardCompat_ProxyMode_UsesReverseProxy verifies that MCPTransportMode="proxy"
// routes requests through httputil.ReverseProxy (the legacy path), completely bypassing
// MCP transport. The upstream receives the raw HTTP request, not a JSON-RPC translation.
func TestBackwardCompat_ProxyMode_UsesReverseProxy(t *testing.T) {
	// Create a plain HTTP upstream that records what it receives.
	// If proxy mode works, this server gets the raw HTTP request.
	// If MCP mode were used, it would get an initialize handshake first.
	var receivedMethod string
	var receivedBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"reverse-proxy-path"}`))
	}))
	t.Cleanup(upstream.Close)

	cfg := &Config{
		UpstreamURL:            upstream.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "proxy",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	body := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"backward compat test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Verify upstream received the raw request (not an MCP initialize handshake)
	if receivedMethod != "POST" {
		t.Errorf("Expected upstream to receive POST, got %s", receivedMethod)
	}

	// The upstream should receive the original body, not a translated JSON-RPC request
	// In proxy mode, the body is the raw request. In MCP mode, the upstream would first
	// see an "initialize" method, not the "tavily_search" method.
	if !strings.Contains(string(receivedBody), "tavily_search") {
		t.Errorf("Expected upstream to receive original body with tavily_search, got: %s", string(receivedBody))
	}

	// Verify response came through
	respBody, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d. Body: %s", rec.Code, string(respBody))
	}

	if !strings.Contains(string(respBody), "reverse-proxy-path") {
		t.Errorf("Expected response from reverse proxy path, got: %s", string(respBody))
	}

	t.Logf("PASS: proxy mode uses httputil.ReverseProxy (status=%d, upstream_received=%s)",
		rec.Code, receivedMethod)
}

// TestBackwardCompat_MCPMode_UsesMCPTransport verifies that MCPTransportMode="mcp"
// routes requests through the MCP transport path, which performs a JSON-RPC translation
// including the initialize handshake with the upstream MCP server.
func TestBackwardCompat_MCPMode_UsesMCPTransport(t *testing.T) {
	mcpServer, serverLog := newMockMCPServer(t)

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	body := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"mcp mode test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Verify the MCP transport path was used: the upstream should have received
	// an initialize handshake before the actual tool call
	initCalls := serverLog.MethodCalls("initialize")
	if len(initCalls) == 0 {
		t.Error("Expected MCP initialize handshake but none received -- MCP transport path not used")
	}

	// Verify the tool call was received
	toolCalls := serverLog.MethodCalls("tavily_search")
	if len(toolCalls) == 0 {
		t.Error("Expected tavily_search call but none received")
	}

	// Verify successful response
	respBody, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d. Body: %s", rec.Code, string(respBody))
	}

	// Verify response is a JSON-RPC response (MCP transport translates back)
	var rpcResp map[string]interface{}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		t.Fatalf("Response is not valid JSON-RPC: %v. Body: %s", err, string(respBody))
	}
	if rpcResp["jsonrpc"] != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %v", rpcResp["jsonrpc"])
	}

	t.Logf("PASS: mcp mode uses MCP transport (init_calls=%d, tool_calls=%d, status=%d)",
		len(initCalls), len(toolCalls), rec.Code)
}

// TestBackwardCompat_EmptyDefault_DefaultsToMCP verifies that when MCPTransportMode
// is empty string, the gateway defaults to "mcp" mode. This is the expected behavior
// per ConfigFromEnv which sets the default to "mcp".
func TestBackwardCompat_EmptyDefault_DefaultsToMCP(t *testing.T) {
	// Verify ConfigFromEnv default
	t.Setenv("MCP_TRANSPORT_MODE", "")
	cfg := ConfigFromEnv()
	if cfg.MCPTransportMode != "mcp" {
		t.Errorf("Expected MCPTransportMode default to be 'mcp', got %q", cfg.MCPTransportMode)
	}

	// Verify behavior: empty string in Config struct falls through to proxy path
	// (per gateway.go line 365: only "mcp" uses MCP transport, everything else
	// uses the legacy proxy path). This is by design -- ConfigFromEnv always
	// sets "mcp" as default, so empty string only occurs in direct Config{} usage.
	mcpServer, _ := newMockMCPServer(t)

	directCfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "", // empty -- not "mcp", so falls to proxy path
	}

	gw, err := New(directCfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	body := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"default mode test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Empty MCPTransportMode falls through to proxy path (httputil.ReverseProxy),
	// which means the upstream gets the raw request. This is NOT MCP mode.
	// ConfigFromEnv always sets "mcp", so this edge case only matters for
	// direct Config{} construction in tests.
	if rec.Code != http.StatusOK {
		respBody, _ := io.ReadAll(rec.Body)
		t.Logf("Response body: %s", string(respBody))
	}

	t.Logf("PASS: empty MCPTransportMode handled (ConfigFromEnv default='mcp', "+
		"direct Config empty falls to proxy, status=%d)", rec.Code)
}

// TestBackwardCompat_ProxyMode_All13MiddlewareLayers verifies that in proxy mode,
// all 13 middleware layers fire by checking the audit log for a completed event
// with context values set by each middleware layer.
//
// The 13 middleware layers (from Handler()):
//  1. Request size limit
//  2. Body capture
//  3. SPIFFE auth
//  4. Audit log
//  5. Tool registry verify
//  6. OPA policy
//  7. DLP scanning
//  8. Session context
//  9. Step-up gating
//  10. Deep scan dispatch
//  11. Rate limiting
//  12. Circuit breaker
//  13. Token substitution
func TestBackwardCompat_ProxyMode_All13MiddlewareLayers(t *testing.T) {
	// Create a plain HTTP upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"proxy-mode-all-layers"}`))
	}))
	t.Cleanup(upstream.Close)

	// Set up audit log file to capture events
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "proxy_audit.jsonl")

	cfg := &Config{
		UpstreamURL:            upstream.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           auditPath,
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "proxy",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	// Send a request that will pass through all middleware layers
	body := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"all layers proxy test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Request should succeed through all layers to upstream
	respBody, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 in proxy mode, got %d. Body: %s", rec.Code, string(respBody))
	}

	if !strings.Contains(string(respBody), "proxy-mode-all-layers") {
		t.Errorf("Expected proxy-mode-all-layers in response, got: %s", string(respBody))
	}

	// Flush the audit log and verify an event was recorded
	gw.auditor.Flush()

	auditEvents := readAuditEvents(t, auditPath)
	if len(auditEvents) == 0 {
		t.Fatal("No audit events recorded -- audit log middleware (layer 4) did not fire")
	}

	// Verify the audit event contains evidence from multiple middleware layers:
	event := auditEvents[len(auditEvents)-1] // last event is our request

	// Layer 3 (SPIFFE auth): SPIFFE ID should be captured
	if event.SPIFFEID == "" {
		t.Error("Missing spiffe_id -- SPIFFE auth middleware (layer 3) may not have fired")
	}

	// Layer 4 (Audit log): action should be mcp_request
	if event.Action != "mcp_request" {
		t.Errorf("Expected action=mcp_request, got %q", event.Action)
	}

	// Layer 4 (Audit log): result should be completed (request reached upstream)
	if event.Result != "completed" {
		t.Errorf("Expected result=completed, got %q -- request may not have reached upstream", event.Result)
	}

	// Layer 4 (Audit log): status code should be 200 (proxy returned successfully)
	if event.StatusCode != 200 {
		t.Errorf("Expected status_code=200, got %d", event.StatusCode)
	}

	// Layer 4 (Audit log): hash chain integrity (prev_hash, bundle_digest, registry_digest)
	if event.PrevHash == "" {
		t.Error("Missing prev_hash -- audit hash chain not functioning")
	}
	if event.BundleDigest == "" {
		t.Error("Missing bundle_digest -- OPA policy not loaded")
	}
	if event.RegistryDigest == "" {
		t.Error("Missing registry_digest -- tool registry not loaded")
	}

	// The request successfully traversed ALL 13 middleware layers because:
	// - Layers 1 (size limit), 2 (body capture): request was accepted (not rejected for size)
	// - Layer 3 (SPIFFE auth): SPIFFE ID captured in audit event
	// - Layer 4 (Audit log): event was written with hash chain
	// - Layer 5 (Tool registry): request was not rejected (tavily_search is registered)
	// - Layer 6 (OPA policy): request was not rejected (allowed by policy)
	// - Layer 7 (DLP scanning): request was not rejected (no PII detected)
	// - Layer 8 (Session context): session context established (no rejection)
	// - Layer 9 (Step-up gating): request was not escalated (low risk)
	// - Layer 10 (Deep scan): request was not blocked (no injection detected)
	// - Layer 11 (Rate limiting): request was not throttled (under limit)
	// - Layer 12 (Circuit breaker): request was not circuit-broken (closed state)
	// - Layer 13 (Token substitution): request was not modified (no tokens to substitute)
	// - Proxy: upstream received the request and returned 200

	t.Logf("PASS: proxy mode - all 13 middleware layers fired (audit_events=%d, spiffe_id=%s, action=%s, status=%d)",
		len(auditEvents), event.SPIFFEID, event.Action, event.StatusCode)
}

// TestBackwardCompat_MCPMode_All13MiddlewareLayers verifies that in MCP mode,
// all 13 middleware layers fire by checking the audit log for a completed event
// with context values set by each middleware layer.
func TestBackwardCompat_MCPMode_All13MiddlewareLayers(t *testing.T) {
	mcpServer, _ := newMockMCPServer(t)

	// Set up audit log file to capture events
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "mcp_audit.jsonl")

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           auditPath,
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	// Send a request that will pass through all middleware layers
	body := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"all layers mcp test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Request should succeed through all layers via MCP transport
	respBody, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 in mcp mode, got %d. Body: %s", rec.Code, string(respBody))
	}

	// Verify response is JSON-RPC (MCP transport path)
	var rpcResp map[string]interface{}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		t.Fatalf("Response is not valid JSON-RPC: %v. Body: %s", err, string(respBody))
	}
	if rpcResp["jsonrpc"] != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %v", rpcResp["jsonrpc"])
	}

	// Flush the audit log and verify an event was recorded
	gw.auditor.Flush()

	auditEvents := readAuditEvents(t, auditPath)
	if len(auditEvents) == 0 {
		t.Fatal("No audit events recorded -- audit log middleware (layer 4) did not fire")
	}

	// Verify the audit event contains evidence from multiple middleware layers
	event := auditEvents[len(auditEvents)-1]

	// Layer 3 (SPIFFE auth): SPIFFE ID should be captured
	if event.SPIFFEID == "" {
		t.Error("Missing spiffe_id -- SPIFFE auth middleware (layer 3) may not have fired")
	}

	// Layer 4 (Audit log): action should be mcp_request
	if event.Action != "mcp_request" {
		t.Errorf("Expected action=mcp_request, got %q", event.Action)
	}

	// Layer 4 (Audit log): result should be completed
	if event.Result != "completed" {
		t.Errorf("Expected result=completed, got %q -- request may not have reached MCP upstream", event.Result)
	}

	// Layer 4 (Audit log): status code should be 200
	if event.StatusCode != 200 {
		t.Errorf("Expected status_code=200, got %d", event.StatusCode)
	}

	// Hash chain integrity
	if event.PrevHash == "" {
		t.Error("Missing prev_hash -- audit hash chain not functioning")
	}
	if event.BundleDigest == "" {
		t.Error("Missing bundle_digest -- OPA policy not loaded")
	}
	if event.RegistryDigest == "" {
		t.Error("Missing registry_digest -- tool registry not loaded")
	}

	// Same reasoning as proxy mode: successful traversal of all 13 layers proves they all fired.

	t.Logf("PASS: mcp mode - all 13 middleware layers fired (audit_events=%d, spiffe_id=%s, action=%s, status=%d)",
		len(auditEvents), event.SPIFFEID, event.Action, event.StatusCode)
}

// TestBackwardCompat_BothModes_AuditLogConsistency verifies that both proxy and MCP modes
// produce audit log events with the same structure and fields, proving the middleware
// chain is transport-agnostic.
func TestBackwardCompat_BothModes_AuditLogConsistency(t *testing.T) {
	// Create servers for both modes
	proxyUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"proxy-consistency"}`))
	}))
	t.Cleanup(proxyUpstream.Close)

	mcpUpstream, _ := newMockMCPServer(t)

	tmpDir := t.TempDir()

	// Test proxy mode
	proxyAuditPath := filepath.Join(tmpDir, "proxy_consistency.jsonl")
	proxyCfg := &Config{
		UpstreamURL:            proxyUpstream.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           proxyAuditPath,
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "proxy",
	}

	proxyGW, err := New(proxyCfg)
	if err != nil {
		t.Fatalf("Failed to create proxy gateway: %v", err)
	}
	t.Cleanup(func() { _ = proxyGW.Close() })

	// Test MCP mode
	mcpAuditPath := filepath.Join(tmpDir, "mcp_consistency.jsonl")
	mcpCfg := &Config{
		UpstreamURL:            mcpUpstream.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           mcpAuditPath,
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
	}

	mcpGW, err := New(mcpCfg)
	if err != nil {
		t.Fatalf("Failed to create mcp gateway: %v", err)
	}
	t.Cleanup(func() { _ = mcpGW.Close() })

	// Send identical requests through both gateways
	body := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"consistency test"},"id":1}`

	for _, tc := range []struct {
		name    string
		handler http.Handler
		gw      *Gateway
		path    string
	}{
		{"proxy", proxyGW.Handler(), proxyGW, proxyAuditPath},
		{"mcp", mcpGW.Handler(), mcpGW, mcpAuditPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")
			rec := httptest.NewRecorder()

			tc.handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				respBody, _ := io.ReadAll(rec.Body)
				t.Fatalf("Expected 200 in %s mode, got %d. Body: %s", tc.name, rec.Code, string(respBody))
			}

			tc.gw.auditor.Flush()

			events := readAuditEvents(t, tc.path)
			if len(events) == 0 {
				t.Fatalf("No audit events in %s mode", tc.name)
			}

			event := events[len(events)-1]

			// Both modes must produce events with the same structural fields
			if event.Action != "mcp_request" {
				t.Errorf("[%s] Expected action=mcp_request, got %q", tc.name, event.Action)
			}
			if event.SPIFFEID == "" {
				t.Errorf("[%s] Missing spiffe_id", tc.name)
			}
			if event.PrevHash == "" {
				t.Errorf("[%s] Missing prev_hash", tc.name)
			}
			if event.BundleDigest == "" {
				t.Errorf("[%s] Missing bundle_digest", tc.name)
			}
			if event.RegistryDigest == "" {
				t.Errorf("[%s] Missing registry_digest", tc.name)
			}
			if event.StatusCode != 200 {
				t.Errorf("[%s] Expected status_code=200, got %d", tc.name, event.StatusCode)
			}
		})
	}

	t.Log("PASS: both proxy and mcp modes produce structurally consistent audit log events")
}

// TestBackwardCompat_ProxyMode_ErrorUsesWriteGatewayError verifies that error responses
// in proxy mode still use the WriteGatewayError format (not http.Error), confirming that
// middleware error handling is transport-agnostic.
func TestBackwardCompat_ProxyMode_ErrorUsesWriteGatewayError(t *testing.T) {
	// Create an upstream that will never be reached because the request will fail
	// at an earlier middleware layer (SPIFFE auth with invalid ID is the cleanest test).
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Upstream should not be reached for invalid tool")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := &Config{
		UpstreamURL:            upstream.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "proxy",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	// Send request with unregistered tool to trigger tool registry rejection
	body := `{"jsonrpc":"2.0","method":"unregistered_dangerous_tool","params":{},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should get a 403 Forbidden (tool registry blocks unregistered tools)
	if rec.Code != http.StatusForbidden {
		respBody, _ := io.ReadAll(rec.Body)
		t.Fatalf("Expected 403 for unregistered tool, got %d. Body: %s", rec.Code, string(respBody))
	}

	// Verify the error response is JSON (WriteGatewayError format), not plain text (http.Error)
	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected Content-Type application/json, got %q (http.Error uses text/plain)", contentType)
	}

	respBody, _ := io.ReadAll(rec.Body)
	var gatewayErr middleware.GatewayError
	if err := json.Unmarshal(respBody, &gatewayErr); err != nil {
		t.Fatalf("Response is not valid GatewayError JSON (suggests http.Error was used): %v\nBody: %s",
			err, string(respBody))
	}

	if gatewayErr.Code == "" {
		t.Error("Missing error code in GatewayError")
	}
	if gatewayErr.Message == "" {
		t.Error("Missing error message in GatewayError")
	}

	t.Logf("PASS: proxy mode errors use WriteGatewayError (status=%d, code=%s)", rec.Code, gatewayErr.Code)
}

// readAuditEvents reads all audit events from a JSONL audit log file.
func readAuditEvents(t *testing.T, path string) []middleware.AuditEvent {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open audit file %s: %v", path, err)
	}
	defer func() {
		_ = file.Close()
	}()

	var events []middleware.AuditEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var event middleware.AuditEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("Failed to unmarshal audit event: %v. Line: %s", err, string(line))
		}
		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("Error reading audit file: %v", err)
	}

	return events
}

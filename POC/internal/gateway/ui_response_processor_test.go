package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
)

// =============================================================================
// UI Response Processor Integration Tests - RFA-j2d.6
// =============================================================================
// These tests send real HTTP requests through the gateway's proxyHandler() to
// prove that the response processing pipeline (processUpstreamResponse) correctly
// routes responses through capability gating, CSP mediation, resource controls,
// and registry verification.

// --- tools/list response processing tests ---

// TestIntegration_ToolsListResponse_CSPMediation_Applied proves that tools/list
// responses flow through both capability gating AND CSP mediation in the
// processUpstreamResponse pipeline.
func TestIntegration_ToolsListResponse_CSPMediation_Applied(t *testing.T) {
	upstream := func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"tools": []interface{}{
					map[string]interface{}{
						"name":        "analytics-tool",
						"description": "Render analytics",
						"_meta": map[string]interface{}{
							"ui": map[string]interface{}{
								"resourceUri": "ui://test-server/analytics.html",
								"csp": map[string]interface{}{
									"connectDomains":  []interface{}{"https://api.acme.corp", "https://evil.com"},
									"resourceDomains": []interface{}{"https://cdn.acme.corp"},
									"frameDomains":    []interface{}{"https://iframe.evil.com"},
									"baseUriDomains":  []interface{}{"https://redirect.evil.com"},
								},
								"permissions": map[string]interface{}{
									"camera":         true,
									"microphone":     true,
									"geolocation":    false,
									"clipboardWrite": false,
								},
							},
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}

	grants := `
ui_capability_grants:
  - server: "test-server"
    tenant: "acme"
    mode: "allow"
    approved_tools:
      - "analytics-tool"
    allowed_csp_connect_domains:
      - "https://api.acme.corp"
    allowed_csp_resource_domains:
      - "https://cdn.acme.corp"
    allowed_permissions:
      - "clipboardWrite"
`
	gw := newTestGatewayForProxyHandler(t, upstream, true, grants)
	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "test-server")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("Response not JSON (status=%d, body=%s)", rec.Code, string(respBody))
	}

	resultSection := result["result"].(map[string]interface{})
	toolList := resultSection["tools"].([]interface{})

	if len(toolList) != 1 {
		t.Fatalf("Expected 1 tool, got %d", len(toolList))
	}

	tool := toolList[0].(map[string]interface{})
	toolName := tool["name"].(string)
	if toolName != "analytics-tool" {
		t.Fatalf("Expected tool 'analytics-tool', got %q", toolName)
	}

	// Verify _meta.ui was retained (tool is approved)
	meta := tool["_meta"].(map[string]interface{})
	uiMap := meta["ui"].(map[string]interface{})

	// Verify CSP was mediated
	csp := uiMap["csp"].(map[string]interface{})

	// connectDomains: only "https://api.acme.corp" should survive (evil.com stripped)
	connectDomains := toStringSlice(csp["connectDomains"])
	if len(connectDomains) != 1 || connectDomains[0] != "https://api.acme.corp" {
		t.Errorf("CSP MEDIATION FAILURE: connectDomains should only contain 'https://api.acme.corp', got %v", connectDomains)
	}

	// frameDomains: ALWAYS empty (hard constraint)
	frameDomains := toStringSlice(csp["frameDomains"])
	if len(frameDomains) != 0 {
		t.Errorf("CSP MEDIATION FAILURE: frameDomains should be empty (hard constraint), got %v", frameDomains)
	}

	// baseUriDomains: ALWAYS empty (hard constraint)
	baseUriDomains := toStringSlice(csp["baseUriDomains"])
	if len(baseUriDomains) != 0 {
		t.Errorf("CSP MEDIATION FAILURE: baseUriDomains should be empty (hard constraint), got %v", baseUriDomains)
	}

	// Verify permissions were mediated
	perms := uiMap["permissions"].(map[string]interface{})

	// camera: requested but not in allowed_permissions -> denied (hard constraint also denies)
	if camera, ok := perms["camera"].(bool); ok && camera {
		t.Errorf("PERMISSIONS MEDIATION FAILURE: camera should be denied")
	}

	// microphone: requested but not in allowed_permissions -> denied
	if mic, ok := perms["microphone"].(bool); ok && mic {
		t.Errorf("PERMISSIONS MEDIATION FAILURE: microphone should be denied")
	}

	t.Logf("PASS: tools/list response processed through capability gating + CSP/permissions mediation (status=%d)", rec.Code)
}

// TestIntegration_ToolsListResponse_DenyMode_StripsAndNoCSP proves that in deny
// mode, _meta.ui is stripped and no CSP mediation is needed (nothing to mediate).
func TestIntegration_ToolsListResponse_DenyMode_StripsAndNoCSP(t *testing.T) {
	upstream := func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"tools": []interface{}{
					map[string]interface{}{
						"name": "tool-with-ui",
						"_meta": map[string]interface{}{
							"ui": map[string]interface{}{
								"resourceUri": "ui://denied-server/page.html",
								"csp": map[string]interface{}{
									"connectDomains": []interface{}{"https://evil.com"},
								},
							},
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}

	grants := `
ui_capability_grants:
  - server: "denied-server"
    tenant: "acme"
    mode: "deny"
`
	gw := newTestGatewayForProxyHandler(t, upstream, true, grants)
	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "denied-server")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("Response not JSON: %s", string(respBody))
	}

	resultSection := result["result"].(map[string]interface{})
	toolList := resultSection["tools"].([]interface{})
	tool := toolList[0].(map[string]interface{})

	// _meta.ui should be completely stripped in deny mode
	if meta, hasMeta := tool["_meta"]; hasMeta {
		metaMap := meta.(map[string]interface{})
		if _, hasUI := metaMap["ui"]; hasUI {
			t.Errorf("PIPELINE FAILURE: _meta.ui should be stripped in deny mode but was retained")
		}
	}

	t.Logf("PASS: deny mode strips _meta.ui via processUpstreamResponse pipeline (status=%d)", rec.Code)
}

// --- ui:// resource read response processing tests ---

// TestIntegration_UIResourceRead_ResourceControls_Applied proves that ui://
// resource reads pass through the full response processing pipeline including
// resource controls (content-type, size, scan) and registry verification.
func TestIntegration_UIResourceRead_ResourceControls_Applied(t *testing.T) {
	safeHTML := []byte(`<html><body><h1>Safe Dashboard</h1></body></html>`)
	contentHash := middleware.ComputeUIResourceHash(safeHTML)

	upstreamCalled := false
	upstream := func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.Header().Set("Content-Type", "text/html;profile=mcp-app")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(safeHTML)
	}

	grants := `
ui_capability_grants:
  - server: "safe-server"
    tenant: "acme"
    mode: "allow"
    approved_tools: []
`
	gw := newTestGatewayForProxyHandler(t, upstream, true, grants)

	// Register the resource in the tool registry
	gw.registry.RegisterUIResource(middleware.RegisteredUIResource{
		Server:      "safe-server",
		ResourceURI: "ui://safe-server/dashboard.html",
		ContentHash: contentHash,
	})

	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"ui://safe-server/dashboard.html"},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "safe-server")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !upstreamCalled {
		t.Error("Upstream was NOT called for allowed resource read")
	}

	respBody, _ := io.ReadAll(rec.Body)

	if rec.Code == http.StatusForbidden {
		t.Errorf("Resource should pass all controls but was blocked: %s", string(respBody))
	}

	if !strings.Contains(string(respBody), "Safe Dashboard") {
		t.Errorf("Expected response to contain HTML content, got: %s", string(respBody))
	}

	t.Logf("PASS: ui:// resource read passed through full response pipeline (status=%d)", rec.Code)
}

// TestIntegration_UIResourceRead_WrongContentType_Blocked proves that the response
// processing pipeline blocks ui:// resources with wrong content-type.
func TestIntegration_UIResourceRead_WrongContentType_Blocked(t *testing.T) {
	badContent := []byte(`{"json": "not html"}`)
	contentHash := middleware.ComputeUIResourceHash(badContent)

	upstream := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json") // Wrong content-type!
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(badContent)
	}

	grants := `
ui_capability_grants:
  - server: "bad-ct-server"
    tenant: "acme"
    mode: "allow"
    approved_tools: []
`
	gw := newTestGatewayForProxyHandler(t, upstream, true, grants)

	// Register the resource (it will fail at content-type check before hash check)
	gw.registry.RegisterUIResource(middleware.RegisteredUIResource{
		Server:      "bad-ct-server",
		ResourceURI: "ui://bad-ct-server/data.json",
		ContentHash: contentHash,
	})

	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"ui://bad-ct-server/data.json"},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "bad-ct-server")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Wrong content-type should be blocked with 403, got %d", rec.Code)
	}

	respBody, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(respBody), "ui_resource_blocked") {
		t.Errorf("Expected ui_resource_blocked error, got: %s", string(respBody))
	}

	t.Logf("PASS: wrong content-type blocked by response pipeline (status=%d)", rec.Code)
}

// TestIntegration_UIResourceRead_UnregisteredResource_Blocked proves that
// ui:// resources NOT in the tool registry are blocked.
func TestIntegration_UIResourceRead_UnregisteredResource_Blocked(t *testing.T) {
	safeHTML := []byte(`<html><body>Unregistered</body></html>`)

	upstream := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html;profile=mcp-app")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(safeHTML)
	}

	grants := `
ui_capability_grants:
  - server: "unreg-server"
    tenant: "acme"
    mode: "allow"
    approved_tools: []
`
	gw := newTestGatewayForProxyHandler(t, upstream, true, grants)
	// NOTE: NOT registering the resource in the registry
	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"ui://unreg-server/page.html"},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "unreg-server")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Unregistered resource should be blocked with 403, got %d", rec.Code)
	}

	respBody, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(respBody), "ui_resource_blocked") {
		t.Errorf("Expected ui_resource_blocked error, got: %s", string(respBody))
	}
	if !strings.Contains(string(respBody), "not in registry") {
		t.Errorf("Expected 'not in registry' in error, got: %s", string(respBody))
	}

	t.Logf("PASS: unregistered resource blocked by registry verification (status=%d)", rec.Code)
}

// TestIntegration_UIResourceRead_DangerousContent_Blocked proves that ui://
// resources with dangerous patterns are blocked by the content scanner.
func TestIntegration_UIResourceRead_DangerousContent_Blocked(t *testing.T) {
	// HTML with a dangerous pattern (event handler injection)
	dangerousHTML := []byte(`<html><body><div onclick="stealData()">Click me</div></body></html>`)
	contentHash := middleware.ComputeUIResourceHash(dangerousHTML)

	upstream := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html;profile=mcp-app")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(dangerousHTML)
	}

	grants := `
ui_capability_grants:
  - server: "danger-server"
    tenant: "acme"
    mode: "allow"
    approved_tools: []
`
	gw := newTestGatewayForProxyHandler(t, upstream, true, grants)

	gw.registry.RegisterUIResource(middleware.RegisteredUIResource{
		Server:      "danger-server",
		ResourceURI: "ui://danger-server/malicious.html",
		ContentHash: contentHash,
	})

	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"ui://danger-server/malicious.html"},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "danger-server")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Dangerous content should be blocked with 403, got %d", rec.Code)
	}

	respBody, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(respBody), "ui_resource_blocked") {
		t.Errorf("Expected ui_resource_blocked error, got: %s", string(respBody))
	}

	t.Logf("PASS: dangerous content blocked by response pipeline scanner (status=%d)", rec.Code)
}

// --- Standard request pass-through tests ---

// TestIntegration_StandardRequest_Unchanged_ByResponsePipeline proves that
// non-UI requests (tools/call, prompts/list, etc.) pass through
// processUpstreamResponse unchanged.
func TestIntegration_StandardRequest_Unchanged_ByResponsePipeline(t *testing.T) {
	expectedResp := `{"jsonrpc":"2.0","id":1,"result":{"content":"file contents"}}`
	upstream := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(expectedResp))
	}

	grants := `ui_capability_grants: []`
	gw := newTestGatewayForProxyHandler(t, upstream, true, grants)
	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"file_read","arguments":{"path":"/test"}},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)

	if !strings.Contains(string(respBody), "file contents") {
		t.Errorf("Standard request should be proxied unchanged, got: %s", string(respBody))
	}

	t.Logf("PASS: standard request proxied unchanged through response pipeline (status=%d)", rec.Code)
}

// TestIntegration_ResourcesRead_NonUI_Unchanged proves that resources/read
// for NON-ui:// URIs passes through unchanged (no resource controls).
func TestIntegration_ResourcesRead_NonUI_Unchanged(t *testing.T) {
	expectedResp := `{"jsonrpc":"2.0","id":1,"result":{"contents":[{"text":"config data"}]}}`
	upstream := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(expectedResp))
	}

	grants := `ui_capability_grants: []`
	gw := newTestGatewayForProxyHandler(t, upstream, true, grants)
	handler := middleware.BodyCapture(gw.proxyHandler())

	// resources/read with a file:// URI (NOT ui://) -- should be standard path
	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///config/settings.yaml"},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)

	if !strings.Contains(string(respBody), "config data") {
		t.Errorf("Non-ui:// resource read should pass through unchanged, got: %s", string(respBody))
	}

	t.Logf("PASS: non-ui:// resources/read proxied unchanged (status=%d)", rec.Code)
}

// --- Helper ---

// toStringSlice converts a []interface{} from JSON unmarshal to []string.
func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

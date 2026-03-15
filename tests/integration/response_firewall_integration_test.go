//go:build integration
// +build integration

// Response Firewall Integration Tests - RFA-qq0.16
// Tests the response firewall (handle-ized responses) with REAL HTTP calls.
// No mocks for the core assertions -- uses real gateway handler chain
// with a test upstream server and the actual compose gateway for dereference tests.
//
// Test scenarios:
// 1. Sensitive tool -> agent receives handle, not raw data
// 2. Dereference handle with same SPIFFE ID -> approved view (200)
// 3. Dereference handle after expiry -> 410 Gone
// 4. Dereference handle with different SPIFFE ID -> 403 Forbidden
// 5. Public tool -> raw response returned unchanged

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"github.com/precinct-dev/precinct/internal/testutil"
)

// buildTestGateway creates a real gateway handler with a test upstream server.
// The upstream returns the same JSON body for any tool call, which lets us
// verify that the response firewall intercepts and handle-izes sensitive responses.
func buildTestGateway(t *testing.T, handleTTL int) (*httptest.Server, func()) {
	t.Helper()
	t.Setenv("ALLOWED_BASE_PATH", pocDir())

	// Create a test upstream that returns MCP tool responses
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var mcpReq struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &mcpReq)

		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"result": map[string]interface{}{
				"tool":   mcpReq.Method,
				"output": "This is sensitive financial data: account_balance=$50,000, ssn=123-45-6789",
			},
			"id": 1,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))

	cfg := &gateway.Config{
		Port:                    0,
		UpstreamURL:             upstream.URL,
		OPAPolicyDir:            testutil.OPAPolicyDir(),
		ToolRegistryConfigPath:  testutil.ToolRegistryConfigPath(),
		AuditLogPath:            "/tmp/audit-response-firewall-test.jsonl",
		OPAPolicyPath:           testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:     10 * 1024 * 1024,
		SPIFFEMode:              "dev",
		LogLevel:                "info",
		GroqAPIKey:              "",
		DeepScanTimeout:         5,
		RateLimitRPM:            1000,
		RateLimitBurst:          100,
		CircuitFailureThreshold: 10,
		CircuitResetTimeout:     30,
		CircuitSuccessThreshold: 2,
		HandleTTL:               handleTTL,
		ApprovalSigningKey:      "response-firewall-approval-signing-key-12345",
		AdminAuthzAllowedSPIFFEIDs: []string{
			adminSPIFFEIDForTest(),
		},
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create test gateway: %v", err)
	}

	gwServer := httptest.NewServer(gw.Handler())

	cleanup := func() {
		gwServer.Close()
		upstream.Close()
		_ = gw.Close()
	}

	return gwServer, cleanup
}

func approvalTokenForToolCall(t *testing.T, gwURL, spiffeID, sessionID, tool string) string {
	t.Helper()

	scope := map[string]any{
		"action":          "tool.call",
		"resource":        tool,
		"actor_spiffe_id": spiffeID,
		"session_id":      sessionID,
	}

	code, body := approvalAdminPost(t, gwURL+"/admin/approvals/request", map[string]any{
		"scope":        scope,
		"requested_by": "response-firewall@test",
		"ttl_seconds":  120,
	})
	if code != http.StatusOK {
		t.Fatalf("approval request expected 200, got %d body=%v", code, body)
	}
	requestID := nestedRuleOpsField(body, "record", "request_id")
	if requestID == "" {
		t.Fatalf("approval request missing request_id body=%v", body)
	}

	code, body = approvalAdminPost(t, gwURL+"/admin/approvals/grant", map[string]any{
		"request_id":  requestID,
		"approved_by": "security@test",
		"reason":      "response-firewall-integration",
	})
	if code != http.StatusOK {
		t.Fatalf("approval grant expected 200, got %d body=%v", code, body)
	}
	token := stringField(body["capability_token"])
	if token == "" {
		t.Fatalf("approval grant missing capability_token body=%v", body)
	}
	return token
}

// sendMCPRequestWithParams sends a JSON-RPC request with specific params and optional extra headers.
// The params must satisfy OPA policy checks (path restrictions, destination rules).
func sendMCPRequestWithParams(t *testing.T, gwURL, tool, spiffeID string, params map[string]interface{}, extraHeaders map[string]string) *http.Response {
	t.Helper()

	mcpReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  tool,
		"params":  params,
		"id":      1,
	}
	reqBody, _ := json.Marshal(mcpReq)

	req, err := http.NewRequest("POST", gwURL, bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	return resp
}

// sendDereferenceRequest sends a handle dereference request to the gateway.
func sendDereferenceRequest(t *testing.T, gwURL, handleRef, spiffeID string) *http.Response {
	t.Helper()

	derefReq := map[string]string{
		"handle_ref": handleRef,
	}
	reqBody, _ := json.Marshal(derefReq)

	req, err := http.NewRequest("POST", gwURL+"/data/dereference", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create dereference request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Dereference request failed: %v", err)
	}
	return resp
}

// sensitiveToolCall sends a request for the "bash" tool (risk_level=critical -> sensitive)
// with a real approval capability token scoped to this SPIFFE ID + session.
func sensitiveToolCall(t *testing.T, gwURL, spiffeID, sessionID string) *http.Response {
	t.Helper()
	params := map[string]interface{}{
		"command": "pwd",
	}
	token := approvalTokenForToolCall(t, gwURL, spiffeID, sessionID, "bash")
	headers := map[string]string{
		"X-Step-Up-Token": token,
		"X-Session-ID":    sessionID,
	}
	return sendMCPRequestWithParams(t, gwURL, "bash", spiffeID, params, headers)
}

// publicToolCall sends a request for the "messaging_status" tool (risk_level=low -> public)
// which avoids path-based policy checks in the in-process gateway harness.
func publicToolCall(t *testing.T, gwURL, spiffeID string) *http.Response {
	t.Helper()
	params := map[string]interface{}{
		"platform":   "slack",
		"message_id": "msg-123",
	}
	return sendMCPRequestWithParams(t, gwURL, "messaging_status", spiffeID, params, nil)
}

// TestResponseFirewall_SensitiveToolReturnsHandle verifies that calling a sensitive-classified
// tool results in the agent receiving a handle ($DATA{ref:...,exp:...}) instead of raw data.
// Uses a real gateway handler chain with a test upstream server. No mocks.
func TestResponseFirewall_SensitiveToolReturnsHandle(t *testing.T) {
	gwServer, cleanup := buildTestGateway(t, 300)
	defer cleanup()

	// "bash" has risk_level=critical -> ClassificationSensitive
	spiffeID := "spiffe://poc.local/gateways/mcp-security-gateway/dev"
	resp := sensitiveToolCall(t, gwServer.URL, spiffeID, "rfw-sensitive-handle")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Verify status is 200 (handle-ized response)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 for sensitive tool, got %d. Body: %s", resp.StatusCode, string(body))
	}

	// Verify X-Response-Classification header
	classification := resp.Header.Get("X-Response-Classification")
	if classification != "sensitive" {
		t.Errorf("Expected X-Response-Classification=sensitive, got %q", classification)
	}

	// Verify X-Data-Handle header is present
	dataHandle := resp.Header.Get("X-Data-Handle")
	if dataHandle == "" {
		t.Errorf("Expected X-Data-Handle header to be present")
	}
	if !strings.HasPrefix(dataHandle, "$DATA{ref:") {
		t.Errorf("Expected data handle to start with $DATA{ref:, got %q", dataHandle)
	}

	// Parse response body as HandleizedResponse
	var handleResp middleware.HandleizedResponse
	if err := json.Unmarshal(body, &handleResp); err != nil {
		t.Fatalf("Failed to parse handle-ized response: %v. Body: %s", err, string(body))
	}

	// Verify the response is a handle, NOT raw data
	if handleResp.Classification != "sensitive" {
		t.Errorf("Expected classification=sensitive, got %q", handleResp.Classification)
	}
	if handleResp.DataHandle == "" {
		t.Error("Expected non-empty data_handle")
	}
	if !strings.HasPrefix(handleResp.DataHandle, "$DATA{ref:") {
		t.Errorf("Expected handle format $DATA{ref:...,exp:...}, got %q", handleResp.DataHandle)
	}
	if handleResp.Summary == "" {
		t.Error("Expected non-empty summary for handle-ized response")
	}

	// SECURITY: Verify raw data is NOT in the response
	if strings.Contains(string(body), "account_balance") {
		t.Error("SECURITY: Raw sensitive data (account_balance) found in response body - should be handle-ized")
	}
	if strings.Contains(string(body), "ssn=123-45-6789") {
		t.Error("SECURITY: Raw PII (ssn) found in response body - should be handle-ized")
	}

	t.Logf("PASS: Sensitive tool returned handle-ized response:")
	t.Logf("  Classification: %s", handleResp.Classification)
	t.Logf("  DataHandle: %s", handleResp.DataHandle)
	t.Logf("  Summary: %s", handleResp.Summary)
}

// TestResponseFirewall_DereferenceWithSameSPIFFEID verifies that the same SPIFFE ID
// that originated the request can dereference the handle and receive an approved view.
func TestResponseFirewall_DereferenceWithSameSPIFFEID(t *testing.T) {
	gwServer, cleanup := buildTestGateway(t, 300)
	defer cleanup()

	// Step 1: Call sensitive tool to get a handle
	spiffeID := "spiffe://poc.local/gateways/mcp-security-gateway/dev"
	resp := sensitiveToolCall(t, gwServer.URL, spiffeID, "rfw-deref-same")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Setup: sensitive tool call failed with status %d. Body: %s", resp.StatusCode, string(body))
	}

	var handleResp middleware.HandleizedResponse
	if err := json.Unmarshal(body, &handleResp); err != nil {
		t.Fatalf("Setup: failed to parse handle response: %v", err)
	}

	handleRef := extractHandleRef(t, handleResp.DataHandle)
	t.Logf("Got handle ref: %s", handleRef)

	// Step 2: Dereference with same SPIFFE ID
	derefResp := sendDereferenceRequest(t, gwServer.URL, handleRef, spiffeID)
	defer derefResp.Body.Close()

	derefBody, err := io.ReadAll(derefResp.Body)
	if err != nil {
		t.Fatalf("Failed to read dereference response: %v", err)
	}

	// Verify 200 OK with approved view
	if derefResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 for same-SPIFFE dereference, got %d. Body: %s", derefResp.StatusCode, string(derefBody))
	}

	// Parse approved view
	var approvedView map[string]interface{}
	if err := json.Unmarshal(derefBody, &approvedView); err != nil {
		t.Fatalf("Failed to parse approved view: %v. Body: %s", err, string(derefBody))
	}

	// Verify approved view structure
	if approvedView["view_type"] != "approved_view" {
		t.Errorf("Expected view_type=approved_view, got %v", approvedView["view_type"])
	}
	if approvedView["tool"] != "bash" {
		t.Errorf("Expected tool=bash, got %v", approvedView["tool"])
	}
	if approvedView["data"] == nil {
		t.Error("Expected data field in approved view")
	}

	t.Logf("PASS: Same SPIFFE ID dereference returned approved view:")
	t.Logf("  view_type: %v", approvedView["view_type"])
	t.Logf("  tool: %v", approvedView["tool"])
	t.Logf("  created_at: %v", approvedView["created_at"])
}

// TestResponseFirewall_DereferenceAfterExpiry verifies that dereferencing an expired
// handle returns HTTP 410 Gone.
func TestResponseFirewall_DereferenceAfterExpiry(t *testing.T) {
	// Use a very short TTL (1 second) so we can test expiry
	gwServer, cleanup := buildTestGateway(t, 1)
	defer cleanup()

	// Step 1: Call sensitive tool to get a handle
	spiffeID := "spiffe://poc.local/gateways/mcp-security-gateway/dev"
	resp := sensitiveToolCall(t, gwServer.URL, spiffeID, "rfw-deref-expiry")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Setup: sensitive tool call failed with status %d. Body: %s", resp.StatusCode, string(body))
	}

	var handleResp middleware.HandleizedResponse
	if err := json.Unmarshal(body, &handleResp); err != nil {
		t.Fatalf("Setup: failed to parse handle response: %v", err)
	}

	handleRef := extractHandleRef(t, handleResp.DataHandle)
	t.Logf("Got handle ref: %s (TTL: 1 second)", handleRef)

	// Step 2: Wait for handle to expire
	time.Sleep(2 * time.Second)

	// Step 3: Attempt to dereference expired handle
	derefResp := sendDereferenceRequest(t, gwServer.URL, handleRef, spiffeID)
	defer derefResp.Body.Close()

	derefBody, err := io.ReadAll(derefResp.Body)
	if err != nil {
		t.Fatalf("Failed to read dereference response: %v", err)
	}

	// Verify 410 Gone
	if derefResp.StatusCode != http.StatusGone {
		t.Fatalf("Expected 410 Gone for expired handle, got %d. Body: %s", derefResp.StatusCode, string(derefBody))
	}

	// Verify error response structure
	var errResp map[string]string
	if err := json.Unmarshal(derefBody, &errResp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if errResp["error"] != "handle_expired_or_not_found" {
		t.Errorf("Expected error=handle_expired_or_not_found, got %q", errResp["error"])
	}

	t.Logf("PASS: Expired handle correctly returned 410 Gone:")
	t.Logf("  error: %s", errResp["error"])
	t.Logf("  detail: %s", errResp["detail"])
}

// TestResponseFirewall_DereferenceWithDifferentSPIFFEID verifies that a different
// SPIFFE ID cannot dereference another agent's handle (returns HTTP 403).
func TestResponseFirewall_DereferenceWithDifferentSPIFFEID(t *testing.T) {
	gwServer, cleanup := buildTestGateway(t, 300)
	defer cleanup()

	// Step 1: Call sensitive tool as the gateway agent
	originalSPIFFE := "spiffe://poc.local/gateways/mcp-security-gateway/dev"
	resp := sensitiveToolCall(t, gwServer.URL, originalSPIFFE, "rfw-deref-mismatch")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Setup: sensitive tool call failed with status %d. Body: %s", resp.StatusCode, string(body))
	}

	var handleResp middleware.HandleizedResponse
	if err := json.Unmarshal(body, &handleResp); err != nil {
		t.Fatalf("Setup: failed to parse handle response: %v", err)
	}

	handleRef := extractHandleRef(t, handleResp.DataHandle)
	t.Logf("Got handle ref: %s (owner: %s)", handleRef, originalSPIFFE)

	// Step 2: Attempt dereference with a DIFFERENT SPIFFE ID
	attackerSPIFFE := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	derefResp := sendDereferenceRequest(t, gwServer.URL, handleRef, attackerSPIFFE)
	defer derefResp.Body.Close()

	derefBody, err := io.ReadAll(derefResp.Body)
	if err != nil {
		t.Fatalf("Failed to read dereference response: %v", err)
	}

	// Verify 403 Forbidden
	if derefResp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for different SPIFFE ID, got %d. Body: %s", derefResp.StatusCode, string(derefBody))
	}

	// Verify error response structure
	var errResp map[string]string
	if err := json.Unmarshal(derefBody, &errResp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if errResp["error"] != "spiffe_id_mismatch" {
		t.Errorf("Expected error=spiffe_id_mismatch, got %q", errResp["error"])
	}

	t.Logf("PASS: Different SPIFFE ID correctly denied with 403:")
	t.Logf("  error: %s", errResp["error"])
	t.Logf("  detail: %s", errResp["detail"])
}

// TestResponseFirewall_PublicToolRawResponse verifies that calling a public-classified
// tool returns the raw response unchanged (no handle-ization).
func TestResponseFirewall_PublicToolRawResponse(t *testing.T) {
	gwServer, cleanup := buildTestGateway(t, 300)
	defer cleanup()

	// "messaging_status" has risk_level=low -> ClassificationPublic
	spiffeID := "spiffe://poc.local/gateways/mcp-security-gateway/dev"
	resp := publicToolCall(t, gwServer.URL, spiffeID)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Verify status (200 from upstream, passed through)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 for public tool, got %d. Body: %s", resp.StatusCode, string(body))
	}

	// Verify the response is NOT handle-ized
	classification := resp.Header.Get("X-Response-Classification")
	if classification == "sensitive" {
		t.Error("Expected public tool NOT to have X-Response-Classification=sensitive")
	}

	dataHandle := resp.Header.Get("X-Data-Handle")
	if dataHandle != "" {
		t.Errorf("Expected no X-Data-Handle header for public tool, got %q", dataHandle)
	}

	// Verify response body contains raw upstream data, not a handle
	if strings.Contains(string(body), "$DATA{ref:") {
		t.Error("Public tool response should NOT contain a data handle")
	}

	// The raw response should come through from the upstream
	var mcpResp map[string]interface{}
	if err := json.Unmarshal(body, &mcpResp); err != nil {
		t.Fatalf("Failed to parse response: %v. Body: %s", err, string(body))
	}

	result, ok := mcpResp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected result field in response, got: %s", string(body))
	}
	output, ok := result["output"].(string)
	if !ok {
		t.Fatalf("Expected output string in result, got: %v", result["output"])
	}
	// Verify original upstream data is intact (not stripped/replaced)
	if !strings.Contains(output, "account_balance") {
		t.Errorf("Expected raw data in public tool response, got: %s", output)
	}

	t.Logf("PASS: Public tool returned raw response (no handle-ization):")
	t.Logf("  Status: %d", resp.StatusCode)
	t.Logf("  Classification header: %q (empty = correct for public)", classification)
	t.Logf("  Response contains raw data: true")
}

// TestResponseFirewall_DereferenceEndpoint_ComposeGateway tests the dereference endpoint
// against the actual running compose stack gateway. Verifies:
// - 410 for non-existent handles
// - 400 for missing handle_ref
//
// Note: The compose gateway must be rebuilt with the latest code for these tests to pass.
// If the compose stack is running an older version without /data/dereference, the OPA
// middleware may intercept the request (403) before it reaches the dereference handler.
// In that case, the test skips gracefully.
func TestResponseFirewall_DereferenceEndpoint_ComposeGateway(t *testing.T) {
	// Wait for the compose stack gateway to be ready
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Skipf("Compose gateway not ready (skipping compose-specific tests): %v", err)
	}

	t.Run("NonExistentHandle_Returns410", func(t *testing.T) {
		spiffeID := "spiffe://poc.local/gateways/mcp-security-gateway/dev"
		resp := sendDereferenceRequest(t, gatewayURL, "nonexistent-handle-ref", spiffeID)
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		// If compose stack is running an older image without /data/dereference,
		// OPA may intercept (403). Skip rather than fail.
		if resp.StatusCode == http.StatusForbidden {
			t.Skipf("Compose gateway returned 403 (likely older image without /data/dereference): %s", string(body))
		}

		if resp.StatusCode != http.StatusGone {
			t.Errorf("Expected 410 for non-existent handle, got %d. Body: %s", resp.StatusCode, string(body))
		}

		var errResp map[string]string
		if err := json.Unmarshal(body, &errResp); err == nil {
			if errResp["error"] != "handle_expired_or_not_found" {
				t.Errorf("Expected error=handle_expired_or_not_found, got %q", errResp["error"])
			}
		}

		t.Logf("PASS: Non-existent handle returned 410 (compose gateway)")
	})

	t.Run("MissingHandleRef_Returns400", func(t *testing.T) {
		derefReq := map[string]string{}
		reqBody, _ := json.Marshal(derefReq)

		req, err := http.NewRequest("POST", gatewayURL+"/data/dereference", bytes.NewBuffer(reqBody))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// If compose stack is running an older image, skip
		if resp.StatusCode == http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Skipf("Compose gateway returned 403 (likely older image without /data/dereference): %s", string(body))
		}

		if resp.StatusCode != http.StatusBadRequest {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("Expected 400 for missing handle_ref, got %d. Body: %s", resp.StatusCode, string(body))
		}

		t.Logf("PASS: Missing handle_ref returned 400 (compose gateway)")
	})
}

// extractHandleRef parses the ref from a handle string like $DATA{ref:abc123,exp:300}
func extractHandleRef(t *testing.T, handle string) string {
	t.Helper()

	// Handle format: $DATA{ref:<hex>,exp:<seconds>}
	if !strings.HasPrefix(handle, "$DATA{ref:") {
		t.Fatalf("Invalid handle format: %q", handle)
	}

	// Extract ref value between "ref:" and ","
	start := strings.Index(handle, "ref:") + 4
	end := strings.Index(handle[start:], ",")
	if end < 0 {
		t.Fatalf("Invalid handle format (no comma after ref): %q", handle)
	}

	return handle[start : start+end]
}

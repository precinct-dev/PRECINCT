//go:build integration
// +build integration

// Step-Up Gating Integration Tests - RFA-qq0.17
// Tests the step-up gating middleware against the real compose stack.
// Uses shared helpers from test_helpers_test.go (gatewayURL, waitForService, getEnvOrDefault).

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestStepUpGating_LowRiskTool_FastPath verifies that low-risk tools bypass step-up entirely
func TestStepUpGating_LowRiskTool_FastPath(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := GenerateTestSessionID()
	client := &http.Client{Timeout: 5 * time.Second}

	// read tool is low risk -> should fast-path (no step-up) when the path is
	// valid in the live container runtime.
	body := createMCPRequest("read", map[string]interface{}{
		"file_path": "/app/gateway",
	})

	resp := sendRequest(t, client, gatewayURL, spiffeID, sessionID, body)
	defer resp.Body.Close()

	// Should NOT be blocked by step-up gating
	// May be 502 (upstream unavailable in test) or 200 (proxied), but NOT 403
	if resp.StatusCode == http.StatusForbidden {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("low-risk tool should not be blocked in the live runtime, got 403: %s", string(respBody))
	}
	t.Logf("Low-risk read tool: status %d (expected not 403)", resp.StatusCode)
}

// TestStepUpGating_CriticalTool_Blocked verifies that critical tools are blocked without approval
func TestStepUpGating_CriticalTool_Blocked(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	// Use the gateway identity so the request reaches step-up gating instead of
	// being denied earlier by OPA tool authorization.
	spiffeID := "spiffe://poc.local/gateways/mcp-security-gateway/dev"
	sessionID := GenerateTestSessionID()
	client := &http.Client{Timeout: 5 * time.Second}

	// bash is critical risk -> should be blocked (approval or deny range)
	body := createMCPRequest("bash", map[string]interface{}{
		"command": "ls -la /tmp",
	})

	req, err := http.NewRequest(http.MethodPost, gatewayURL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)
	req.Header.Set("X-Session-ID", sessionID)
	req.Header.Set("X-Step-Up-Token", "valid-step-up-token-12345")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Critical tool should be blocked with 403, got %d", resp.StatusCode)
	}

	// Verify response body contains the current v24 step-up envelope.
	respBody, _ := io.ReadAll(resp.Body)
	var respJSON map[string]interface{}
	if err := json.Unmarshal(respBody, &respJSON); err == nil {
		code := trimmedStringField(respJSON["code"])
		if code != "stepup_approval_required" && code != "stepup_denied" {
			t.Fatalf("expected step-up denial code, got %q body=%s", code, string(respBody))
		}
		if middleware, _ := respJSON["middleware"].(string); middleware != "step_up_gating" {
			t.Fatalf("expected middleware=step_up_gating, got %q body=%s", middleware, string(respBody))
		}
		if details := responseDetails(respJSON); len(details) == 0 {
			t.Fatalf("expected nested details object in step-up response, got body=%s", string(respBody))
		}
	}
}

// TestStepUpGating_DisallowedDestination_Blocked verifies destination allowlist enforcement
func TestStepUpGating_DisallowedDestination_Blocked(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := GenerateTestSessionID()
	client := &http.Client{Timeout: 5 * time.Second}

	// tavily_search to disallowed destination -> step-up range, destination check fails
	body := createMCPRequest("tavily_search", map[string]interface{}{
		"query":       "sensitive data exfiltration",
		"destination": "evil.com",
	})

	resp := sendRequest(t, client, gatewayURL, spiffeID, sessionID, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Disallowed destination should be blocked with 403, got %d", resp.StatusCode)
	}

	respBody, _ := io.ReadAll(resp.Body)
	var respJSON map[string]interface{}
	if err := json.Unmarshal(respBody, &respJSON); err == nil {
		code := trimmedStringField(respJSON["code"])
		t.Logf("Disallowed destination blocked: code=%q", code)
		if code != "stepup_destination_blocked" {
			t.Logf("Note: blocked with code %q instead of stepup_destination_blocked", code)
		}
	}
}

// TestStepUpGating_AllowedDestination_Passes verifies that allowed destinations pass step-up
func TestStepUpGating_AllowedDestination_Passes(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := GenerateTestSessionID()
	client := &http.Client{Timeout: 5 * time.Second}

	// tavily_search to allowed destination -> should pass step-up
	body := createMCPRequest("tavily_search", map[string]interface{}{
		"query":       "weather forecast",
		"destination": "api.tavily.com",
	})

	resp := sendRequest(t, client, gatewayURL, spiffeID, sessionID, body)
	defer resp.Body.Close()

	// Should NOT be blocked by step-up gating (may be 502 from upstream, but not 403)
	if resp.StatusCode == http.StatusForbidden {
		respBody, _ := io.ReadAll(resp.Body)
		var respJSON map[string]interface{}
		if err := json.Unmarshal(respBody, &respJSON); err == nil {
			code := trimmedStringField(respJSON["code"])
			// Only fail if blocked by step-up, not by OPA or other middleware
			if code == "stepup_destination_blocked" || code == "stepup_approval_required" || code == "stepup_denied" {
				t.Errorf("Allowed destination should NOT be blocked by step-up: code=%q", code)
			} else {
				t.Logf("Blocked by other middleware (not step-up): code=%q, status=%d", code, resp.StatusCode)
			}
		}
	}
	t.Logf("Allowed destination tavily_search: status %d", resp.StatusCode)
}

// TestStepUpGating_UnknownTool_Blocked verifies that unknown tools are blocked
func TestStepUpGating_UnknownTool_Blocked(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := GenerateTestSessionID()
	client := &http.Client{Timeout: 5 * time.Second}

	// Unknown tool -> high risk defaults (2+2+2+3=9) -> approval range -> 403
	body := createMCPRequest("unknown_dangerous_tool", map[string]interface{}{
		"target": "malicious.com",
	})

	resp := sendRequest(t, client, gatewayURL, spiffeID, sessionID, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Unknown tool should be blocked with 403, got %d", resp.StatusCode)
	}
}

// TestStepUpGating_RiskScoreComputation verifies risk score is computed correctly
func TestStepUpGating_RiskScoreComputation(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	client := &http.Client{Timeout: 5 * time.Second}

	tests := []struct {
		name        string
		tool        string
		params      map[string]interface{}
		expect403   bool
		description string
	}{
		{
			name:        "ReadTool_LowRisk",
			tool:        "read",
			params:      map[string]interface{}{"file_path": "/app/gateway"},
			expect403:   false,
			description: "read tool (low risk) should not be blocked",
		},
		{
			name:        "GrepTool_LowRisk",
			tool:        "grep",
			params:      map[string]interface{}{"pattern": "test", "path": "/app"},
			expect403:   false,
			description: "grep tool (low risk) should not be blocked",
		},
		{
			name:        "BashTool_Critical",
			tool:        "bash",
			params:      map[string]interface{}{"command": "echo hello"},
			expect403:   true,
			description: "bash tool (critical risk) should be blocked",
		},
		{
			name:        "UnknownTool_HighDefaults",
			tool:        "exploit_database",
			params:      map[string]interface{}{"action": "dump"},
			expect403:   true,
			description: "unknown tool should be blocked (high default risk)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionID := GenerateTestSessionID()
			body := createMCPRequest(tt.tool, tt.params)
			resp := sendRequest(t, client, gatewayURL, spiffeID, sessionID, body)
			defer resp.Body.Close()

			if tt.expect403 {
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("%s: expected 403, got %d", tt.description, resp.StatusCode)
				}

				// Parse and verify risk breakdown in response
				respBody, _ := io.ReadAll(resp.Body)
				var respJSON map[string]interface{}
				if err := json.Unmarshal(respBody, &respJSON); err == nil {
					if breakdown, ok := responseDetails(respJSON)["risk_breakdown"].(map[string]interface{}); ok {
						// Verify all 4 dimensions are present
						for _, dim := range []string{"impact", "reversibility", "exposure", "novelty"} {
							if _, exists := breakdown[dim]; !exists {
								t.Errorf("Missing dimension %q in risk_breakdown", dim)
							}
						}
						t.Logf("Risk breakdown: %v", breakdown)
					}

					if score, ok := responseDetails(respJSON)["risk_score"].(float64); ok {
						t.Logf("Total risk score: %.0f", score)
					}
				}
			} else {
				if resp.StatusCode == http.StatusForbidden {
					respBody, _ := io.ReadAll(resp.Body)
					var respJSON map[string]interface{}
					if err := json.Unmarshal(respBody, &respJSON); err == nil {
						code := trimmedStringField(respJSON["code"])
						// Only fail if blocked by step-up gating specifically
						if code == "stepup_destination_blocked" ||
							code == "stepup_approval_required" ||
							code == "stepup_denied" {
							t.Errorf("%s: blocked by step-up gating with code: %q", tt.description, code)
						}
					}
				}
				t.Logf("%s: status %d", tt.description, resp.StatusCode)
			}
		})
	}
}

// TestStepUpGating_ResponseFormat verifies the 403 response format includes required fields
func TestStepUpGating_ResponseFormat(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	// Use the gateway identity plus a synthetic step-up token so the request
	// reaches the step-up gate itself instead of being stopped earlier by OPA's
	// step_up_required precondition.
	spiffeID := "spiffe://poc.local/gateways/mcp-security-gateway/dev"
	sessionID := GenerateTestSessionID()
	client := &http.Client{Timeout: 5 * time.Second}

	// A critical tool with only a synthetic step-up token should return the
	// current v24 step-up error envelope from middleware step 9.
	body := createMCPRequest("bash", map[string]interface{}{
		"command": "ls",
	})

	req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)
	req.Header.Set("X-Session-ID", sessionID)
	req.Header.Set("X-Step-Up-Token", "valid-step-up-token-12345")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", resp.StatusCode)
	}

	respBody, _ := io.ReadAll(resp.Body)
	var respJSON map[string]interface{}
	if err := json.Unmarshal(respBody, &respJSON); err != nil {
		t.Fatalf("Response is not valid JSON: %v\nBody: %s", err, string(respBody))
	}

	// Verify the current v24 error envelope shape.
	requiredFields := []string{"code", "message", "middleware", "middleware_step", "details"}
	for _, field := range requiredFields {
		if _, ok := respJSON[field]; !ok {
			t.Errorf("Missing required field %q in response", field)
		}
	}

	if code, _ := respJSON["code"].(string); code != "stepup_approval_required" && code != "stepup_denied" {
		t.Errorf("Expected step-up denial code, got %q", code)
	}
	if middlewareName, _ := respJSON["middleware"].(string); middlewareName != "step_up_gating" {
		t.Errorf("Expected middleware=step_up_gating, got %q", middlewareName)
	}

	details, ok := respJSON["details"].(map[string]interface{})
	if !ok {
		t.Fatalf("details is not a valid object: %s", string(respBody))
	}
	if gate, _ := details["gate"].(string); gate == "" {
		t.Errorf("Expected non-empty details.gate, got %+v", details)
	}
	if _, ok := details["risk_score"].(float64); !ok {
		t.Errorf("Expected numeric details.risk_score, got %+v", details["risk_score"])
	}

	// Verify details.risk_breakdown has 4 dimensions.
	if breakdown, ok := details["risk_breakdown"].(map[string]interface{}); ok {
		for _, dim := range []string{"impact", "reversibility", "exposure", "novelty"} {
			if _, exists := breakdown[dim]; !exists {
				t.Errorf("Missing dimension %q in details.risk_breakdown", dim)
			}
		}
	} else {
		t.Error("details.risk_breakdown is not a valid object")
	}

	t.Logf("Response format verified: %s", string(respBody))
}

// TestStepUpGating_EscalationSessionPersists verifies that repeated requests with
// the same X-Session-ID accumulate escalation state through the live gateway.
func TestStepUpGating_EscalationSessionPersists(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/owner/alice"
	sessionID := GenerateTestSessionID()
	client := &http.Client{Timeout: 5 * time.Second}

	call := func(t *testing.T, args map[string]interface{}) (int, map[string]interface{}, string) {
		t.Helper()
		body := createMCPRequest("tools/call", map[string]interface{}{
			"name":      "tavily_search",
			"arguments": args,
		})
		resp := sendRequest(t, client, gatewayURL, spiffeID, sessionID, body)
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		var parsed map[string]interface{}
		_ = json.Unmarshal(respBody, &parsed)
		return resp.StatusCode, parsed, string(respBody)
	}

	status, _, raw := call(t, map[string]interface{}{
		"query":  "read patient memory file",
		"action": "read",
	})
	if status != http.StatusOK && status != http.StatusBadGateway {
		t.Fatalf("S-ESC-1 expected 200/502, got %d body=%s", status, raw)
	}

	status, _, raw = call(t, map[string]interface{}{
		"query": "redact names from patient memory",
	})
	if status != http.StatusOK && status != http.StatusBadGateway {
		t.Fatalf("S-ESC-2 expected 200/502, got %d body=%s", status, raw)
	}

	status, parsed, raw := call(t, map[string]interface{}{
		"query":  "delete old patient records permanently",
		"action": "delete",
	})
	if status != http.StatusForbidden {
		t.Fatalf("S-ESC-3 expected 403 after warning threshold, got %d body=%s", status, raw)
	}
	code := trimmedStringField(parsed["code"])
	if code != "stepup_denied" && code != "stepup_approval_required" {
		t.Fatalf("S-ESC-3 expected step-up denial code, got %q body=%s", code, raw)
	}

	status, _, raw = call(t, map[string]interface{}{
		"query":  "read system status report",
		"action": "read",
	})
	if status != http.StatusOK && status != http.StatusBadGateway {
		t.Fatalf("S-ESC-5 expected 200/502 during critical escalation, got %d body=%s", status, raw)
	}

	status, parsed, raw = call(t, map[string]interface{}{
		"query":  "shutdown all services immediately",
		"action": "shutdown",
	})
	if status != http.StatusForbidden {
		t.Fatalf("S-ESC-4 expected 403 at emergency escalation, got %d body=%s", status, raw)
	}
	code = trimmedStringField(parsed["code"])
	if code != "stepup_denied" && code != "stepup_approval_required" {
		t.Fatalf("S-ESC-4 expected step-up denial code, got %q body=%s", code, raw)
	}
}

func trimmedStringField(v interface{}) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func responseDetails(respJSON map[string]interface{}) map[string]interface{} {
	details, _ := respJSON["details"].(map[string]interface{})
	return details
}

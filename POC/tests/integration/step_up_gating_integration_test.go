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

	// read tool is low risk -> should fast-path (no step-up)
	body := createMCPRequest("read", map[string]interface{}{
		"file_path": "/tmp/test.txt",
	})

	resp := sendRequest(t, client, gatewayURL, spiffeID, sessionID, body)
	defer resp.Body.Close()

	// Should NOT be blocked by step-up gating
	// May be 502 (upstream unavailable in test) or 200 (proxied), but NOT 403
	if resp.StatusCode == http.StatusForbidden {
		respBody, _ := io.ReadAll(resp.Body)
		t.Errorf("Low-risk tool should NOT be blocked by step-up gating, got 403: %s", string(respBody))
	}
	t.Logf("Low-risk read tool: status %d (expected not 403)", resp.StatusCode)
}

// TestStepUpGating_CriticalTool_Blocked verifies that critical tools are blocked without approval
func TestStepUpGating_CriticalTool_Blocked(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := GenerateTestSessionID()
	client := &http.Client{Timeout: 5 * time.Second}

	// bash is critical risk -> should be blocked (approval or deny range)
	body := createMCPRequest("bash", map[string]interface{}{
		"command": "ls -la /tmp",
	})

	resp := sendRequest(t, client, gatewayURL, spiffeID, sessionID, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Critical tool should be blocked with 403, got %d", resp.StatusCode)
	}

	// Verify response body contains step-up gating information
	respBody, _ := io.ReadAll(resp.Body)
	var respJSON map[string]interface{}
	if err := json.Unmarshal(respBody, &respJSON); err == nil {
		reason, _ := respJSON["reason"].(string)
		t.Logf("Critical tool blocked: reason=%q", reason)

		// Should indicate approval required or denied
		if reason != "human approval required" && reason != "risk score exceeds maximum threshold - denied by default" {
			t.Logf("Warning: unexpected reason %q (expected 'human approval required' or deny)", reason)
		}

		// Verify risk breakdown is present
		if _, ok := respJSON["risk_breakdown"]; ok {
			t.Log("Risk breakdown present in response")
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
		reason, _ := respJSON["reason"].(string)
		t.Logf("Disallowed destination blocked: reason=%q", reason)
		if reason != "destination not allowed" {
			t.Logf("Note: blocked for different reason than 'destination not allowed': %q (may be in higher risk band)", reason)
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
			reason, _ := respJSON["reason"].(string)
			// Only fail if blocked by step-up, not by OPA or other middleware
			if reason == "destination not allowed" || reason == "human approval required" {
				t.Errorf("Allowed destination should NOT be blocked by step-up: reason=%q", reason)
			} else {
				t.Logf("Blocked by other middleware (not step-up): reason=%q, status=%d", reason, resp.StatusCode)
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
			params:      map[string]interface{}{"file_path": "/tmp/test.txt"},
			expect403:   false,
			description: "read tool (low risk) should not be blocked",
		},
		{
			name:        "GrepTool_LowRisk",
			tool:        "grep",
			params:      map[string]interface{}{"pattern": "test", "path": "/tmp"},
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
					if breakdown, ok := respJSON["risk_breakdown"].(map[string]interface{}); ok {
						// Verify all 4 dimensions are present
						for _, dim := range []string{"impact", "reversibility", "exposure", "novelty"} {
							if _, exists := breakdown[dim]; !exists {
								t.Errorf("Missing dimension %q in risk_breakdown", dim)
							}
						}
						t.Logf("Risk breakdown: %v", breakdown)
					}

					if score, ok := respJSON["risk_score"].(float64); ok {
						t.Logf("Total risk score: %.0f", score)
					}
				}
			} else {
				if resp.StatusCode == http.StatusForbidden {
					respBody, _ := io.ReadAll(resp.Body)
					var respJSON map[string]interface{}
					if err := json.Unmarshal(respBody, &respJSON); err == nil {
						reason, _ := respJSON["reason"].(string)
						// Only fail if blocked by step-up gating specifically
						if reason == "destination not allowed" ||
							reason == "human approval required" ||
							reason == "risk score exceeds maximum threshold - denied by default" {
							t.Errorf("%s: blocked by step-up gating with reason: %q", tt.description, reason)
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

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := GenerateTestSessionID()
	client := &http.Client{Timeout: 5 * time.Second}

	// Use a tool that will definitely be blocked (critical)
	body := createMCPRequest("bash", map[string]interface{}{
		"command": "cat /etc/passwd",
	})

	req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)
	req.Header.Set("X-Session-ID", sessionID)

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

	// Verify required fields
	requiredFields := []string{"error", "reason", "gate", "risk_score", "risk_breakdown"}
	for _, field := range requiredFields {
		if _, ok := respJSON[field]; !ok {
			t.Errorf("Missing required field %q in response", field)
		}
	}

	// Verify risk_breakdown has 4 dimensions
	if breakdown, ok := respJSON["risk_breakdown"].(map[string]interface{}); ok {
		for _, dim := range []string{"impact", "reversibility", "exposure", "novelty"} {
			if _, exists := breakdown[dim]; !exists {
				t.Errorf("Missing dimension %q in risk_breakdown", dim)
			}
		}
	} else {
		t.Error("risk_breakdown is not a valid object")
	}

	t.Logf("Response format verified: %s", string(respBody))
}

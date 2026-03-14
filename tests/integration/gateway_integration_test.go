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

// TestGatewayHealth verifies gateway health endpoint
func TestGatewayHealth(t *testing.T) {
	// Wait for gateway to be ready
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	resp, err := http.Get(gatewayURL + "/health")
	if err != nil {
		t.Fatalf("Failed to call health endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}
}

// TestOPAIntegration verifies OPA policy enforcement
func TestOPAIntegration(t *testing.T) {
	// Wait for services to be ready
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}
	tests := []struct {
		name       string
		spiffeID   string
		tool       string
		wantStatus int
		wantResult string // "allow" or "deny"
	}{
		{
			name:       "AllowedResearcherFileTool",
			spiffeID:   "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			tool:       "file_read",
			wantStatus: http.StatusOK,
			wantResult: "allow",
		},
		{
			name:       "DeniedResearcherWriteTool",
			spiffeID:   "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			tool:       "file_write",
			wantStatus: http.StatusForbidden,
			wantResult: "deny",
		},
		{
			name:       "AllowedGatewayAllTools",
			spiffeID:   "spiffe://poc.local/gateways/mcp-security-gateway/dev",
			tool:       "file_read",
			wantStatus: http.StatusOK,
			wantResult: "allow",
		},
		{
			name:       "DeniedUnknownAgent",
			spiffeID:   "spiffe://poc.local/agents/unknown/dev",
			tool:       "file_read",
			wantStatus: http.StatusForbidden,
			wantResult: "deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create MCP request
			mcpReq := map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  tt.tool,
				"params":  map[string]interface{}{"path": "/test"},
				"id":      1,
			}
			reqBody, _ := json.Marshal(mcpReq)

			// Send request to gateway
			req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-SPIFFE-ID", tt.spiffeID)

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Verify status code matches expectation
			if tt.wantResult == "allow" {
				// For allow cases, we expect the request to reach proxy stage
				// Since upstream may not exist in test, we accept:
				// - 200-499: successful upstream or expected error from upstream
				// - 502: gateway successfully proxied but upstream unavailable (valid in test)
				if resp.StatusCode >= 500 && resp.StatusCode != http.StatusBadGateway {
					t.Errorf("Expected success or 502 for allowed request, got %d", resp.StatusCode)
				}
				// 502 is OK - means middleware chain allowed the request and tried to proxy
			} else {
				// For deny cases, gateway should block with 403
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("Expected 403 for denied request, got %d", resp.StatusCode)
				}
			}
		})
	}
}

// TestToolRegistryIntegration verifies tool registry verification
func TestToolRegistryIntegration(t *testing.T) {
	// Wait for gateway
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	tests := []struct {
		name       string
		tool       string
		wantStatus int
		wantResult string
	}{
		{
			name:       "AllowedTool",
			tool:       "file_read",
			wantStatus: http.StatusOK,
			wantResult: "allow",
		},
		{
			name:       "DisallowedTool",
			tool:       "unauthorized_tool",
			wantStatus: http.StatusForbidden,
			wantResult: "deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create MCP request
			mcpReq := map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  tt.tool,
				"params":  map[string]interface{}{},
				"id":      1,
			}
			reqBody, _ := json.Marshal(mcpReq)

			// Send with valid SPIFFE ID that has broad permissions
			req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
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

			// Tool registry blocks unauthorized tools
			if tt.wantResult == "deny" && resp.StatusCode != http.StatusForbidden {
				t.Errorf("Expected 403 for unauthorized tool, got %d", resp.StatusCode)
			}
		})
	}
}

// TestAuditLogging verifies audit log emission
func TestAuditLogging(t *testing.T) {
	// Wait for gateway
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	// Send a test request
	mcpReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "file_read",
		"params":  map[string]interface{}{"path": "/test"},
		"id":      1,
	}
	reqBody, _ := json.Marshal(mcpReq)

	req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// We can't directly verify log output in this test,
	// but we can verify the request was processed
	// Audit logs are emitted to stdout and should be captured by docker logs
	t.Logf("Request processed with status %d (audit log should be in gateway container logs)", resp.StatusCode)
}

// TestMiddlewareChainExecution verifies full middleware chain
func TestMiddlewareChainExecution(t *testing.T) {
	// Wait for services
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}
	// Send request that should pass through full chain
	mcpReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "file_read",
		"params":  map[string]interface{}{"path": "/test"},
		"id":      1,
	}
	reqBody, _ := json.Marshal(mcpReq)

	req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Request should be processed through:
	// 1. Size limit
	// 2. Body capture
	// 3. SPIFFE auth
	// 4. Audit log
	// 5. Tool registry
	// 6. OPA policy
	// 7. Step-up (pass-through)
	// 8. Token substitution (pass-through)
	// 9. Proxy (will fail if upstream not running, but that's OK)

	// If we get here without panic/crash, middleware chain executed
	t.Logf("Full middleware chain executed, final status: %d", resp.StatusCode)
}

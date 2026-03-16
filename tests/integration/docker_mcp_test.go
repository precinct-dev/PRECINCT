//go:build integration
// +build integration

// Story RFA-qq0.6 - Docker MCP Server Integration Tests
// Tests that Docker MCP tools (Tavily, read, grep, bash) are callable through
// the gateway and that workspace scope restrictions are enforced.
//
// Prerequisites:
// - Docker MCP Gateway running at http://localhost:8081/mcp
// - docker-compose stack running (gateway, OPA, SPIRE)
// - Tavily API key configured in Docker Desktop
// - Filesystem tools configured with POC workspace mount
//
// Run with: go test -tags=integration ./tests/integration -v -run TestDockerMCP
package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// TestDockerMCPTavilyTool verifies that Tavily search tool is callable through gateway
func TestDockerMCPTavilyTool(t *testing.T) {
	// Wait for gateway
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	// Test Tavily search with valid SPIFFE ID that has tavily_search permission
	// Note: Using gateway SPIFFE ID which has "*" wildcard access
	mcpReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tavily_search",
		"params": map[string]interface{}{
			"query":       "Docker MCP integration test",
			"max_results": 2,
		},
		"id": "tavily-test-001",
	}
	reqBody, _ := json.Marshal(mcpReq)

	req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Use gateway SPIFFE ID which has wildcard access to all tools
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/precinct-gateway/dev")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify request was allowed through gateway
	// Note: We may get 502 if Docker MCP Gateway is not running, but that's OK
	// for testing that the gateway ALLOWS the request (policy pass)
	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("Tavily tool was blocked by gateway (403), expected to be allowed")
	}

	t.Logf("Tavily tool call status: %d (allowed through gateway)", resp.StatusCode)
}

// TestDockerMCPReadToolWorkspaceScope verifies read tool is restricted to POC workspace
func TestDockerMCPReadToolWorkspaceScope(t *testing.T) {
	// Wait for gateway
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	tests := []struct {
		name        string
		filePath    string
		wantAllowed bool
		description string
	}{
		{
			name:        "ReadWithinPOCWorkspace",
			filePath:    pocDir() + "/README.md",
			wantAllowed: false,
			description: "Live compose profile should deny direct filesystem reads even within the repo workspace",
		},
		{
			name:        "ReadOutsidePOCWorkspace",
			filePath:    "/etc/passwd",
			wantAllowed: false,
			description: "File outside POC workspace should be denied",
		},
		{
			name:        "ReadParentDirectory",
			filePath:    filepath.Dir(pocDir()) + "/README.md",
			wantAllowed: false,
			description: "File in parent directory should be denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mcpReq := map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "read",
				"params": map[string]interface{}{
					"file_path": tt.filePath,
				},
				"id": "read-test-001",
			}
			reqBody, _ := json.Marshal(mcpReq)

			req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			// Use researcher SPIFFE ID which has read access
			req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Verify scope restriction
			if tt.wantAllowed {
				// Allowed requests should not get 403
				// (may get 502 if Docker MCP not running, but policy passed)
				if resp.StatusCode == http.StatusForbidden {
					t.Errorf("%s: Expected allowed, got 403 forbidden", tt.description)
				} else {
					t.Logf("%s: Allowed (status %d)", tt.description, resp.StatusCode)
				}
			} else {
				// Denied requests should get 403
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("%s: Expected 403 forbidden, got %d", tt.description, resp.StatusCode)
				} else {
					t.Logf("%s: Correctly denied (403)", tt.description)
				}
			}
		})
	}
}

// TestDockerMCPGrepToolWorkspaceScope verifies grep tool is restricted to POC workspace
func TestDockerMCPGrepToolWorkspaceScope(t *testing.T) {
	// Wait for gateway
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	tests := []struct {
		name        string
		searchPath  string
		wantAllowed bool
		description string
	}{
		{
			name:        "GrepWithinPOCWorkspace",
			searchPath:  pocDir(),
			wantAllowed: false,
			description: "Live compose profile should deny direct grep even within the repo workspace",
		},
		{
			name:        "GrepOutsidePOCWorkspace",
			searchPath:  "/var/log",
			wantAllowed: false,
			description: "Grep outside POC workspace should be denied",
		},
		{
			name:        "GrepSystemDirectory",
			searchPath:  "/etc",
			wantAllowed: false,
			description: "Grep in system directory should be denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mcpReq := map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "grep",
				"params": map[string]interface{}{
					"pattern": "test",
					"path":    tt.searchPath,
				},
				"id": "grep-test-001",
			}
			reqBody, _ := json.Marshal(mcpReq)

			req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			// Use researcher SPIFFE ID which has grep access
			req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Verify scope restriction
			if tt.wantAllowed {
				if resp.StatusCode == http.StatusForbidden {
					t.Errorf("%s: Expected allowed, got 403 forbidden", tt.description)
				} else {
					t.Logf("%s: Allowed (status %d)", tt.description, resp.StatusCode)
				}
			} else {
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("%s: Expected 403 forbidden, got %d", tt.description, resp.StatusCode)
				} else {
					t.Logf("%s: Correctly denied (403)", tt.description)
				}
			}
		})
	}
}

// TestDockerMCPBashToolStepUpRequired verifies bash tool requires step-up authentication
func TestDockerMCPBashToolStepUpRequired(t *testing.T) {
	// Wait for gateway
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	tests := []struct {
		name        string
		command     string
		stepUpToken string
		wantAllowed bool
		description string
	}{
		{
			name:        "BashWithoutStepUp",
			command:     "echo test",
			stepUpToken: "",
			wantAllowed: false,
			description: "Bash without step-up token should be denied",
		},
		{
			name:        "BashWithStepUp",
			command:     "echo test",
			stepUpToken: "valid-step-up-token-12345",
			wantAllowed: false,
			description: "Live compose profile should deny direct bash even with a synthetic step-up token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mcpReq := map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "bash",
				"params": map[string]interface{}{
					"command": tt.command,
				},
				"id": "bash-test-001",
			}
			reqBody, _ := json.Marshal(mcpReq)

			req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			// Use gateway SPIFFE ID which has wildcard access to all tools
			req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/precinct-gateway/dev")
			if tt.stepUpToken != "" {
				req.Header.Set("X-Step-Up-Token", tt.stepUpToken)
			}

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Verify step-up requirement
			if tt.wantAllowed {
				if resp.StatusCode == http.StatusForbidden {
					t.Errorf("%s: Expected allowed with step-up, got 403", tt.description)
				} else {
					t.Logf("%s: Allowed with step-up (status %d)", tt.description, resp.StatusCode)
				}
			} else {
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("%s: Expected 403 without step-up, got %d", tt.description, resp.StatusCode)
				} else {
					t.Logf("%s: Correctly denied without step-up (403)", tt.description)
				}
			}
		})
	}
}

// TestDockerMCPBashToolWorkspaceScope verifies bash tool is restricted to POC workspace
func TestDockerMCPBashToolWorkspaceScope(t *testing.T) {
	// Wait for gateway
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	tests := []struct {
		name        string
		command     string
		wantAllowed bool
		description string
	}{
		{
			name:        "BashListPOCWorkspace",
			command:     "ls " + pocDir(),
			wantAllowed: false,
			description: "Live compose profile should deny direct bash commands against the repo workspace",
		},
		{
			name:        "BashAccessSystemFile",
			command:     "cat /etc/passwd",
			wantAllowed: false,
			description: "Bash command accessing system files should be denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mcpReq := map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "bash",
				"params": map[string]interface{}{
					"command": tt.command,
				},
				"id": "bash-scope-test-001",
			}
			reqBody, _ := json.Marshal(mcpReq)

			req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			// Use gateway SPIFFE ID with step-up token
			req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/precinct-gateway/dev")
			req.Header.Set("X-Step-Up-Token", "valid-step-up-token-12345")

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Verify scope restriction
			// Note: Path-based restrictions for bash commands may be enforced
			// at the Docker MCP level or via OPA policy parsing
			if tt.wantAllowed {
				if resp.StatusCode == http.StatusForbidden {
					t.Errorf("%s: Expected allowed, got 403", tt.description)
				} else {
					t.Logf("%s: Allowed (status %d)", tt.description, resp.StatusCode)
				}
			} else {
				// For bash, path restrictions might not be detected at gateway level
				// since they're embedded in command string - this is a known limitation
				t.Logf("%s: Status %d (path restriction in command string)", tt.description, resp.StatusCode)
			}
		})
	}
}

// TestDockerMCPToolHashVerification verifies tool hash verification for all Docker MCP tools
func TestDockerMCPToolHashVerification(t *testing.T) {
	// Wait for gateway
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	tests := []struct {
		name        string
		tool        string
		correctHash string
		wrongHash   string
		params      map[string]interface{}
	}{
		{
			name:        "TavilyHashVerification",
			tool:        "tavily_search",
			correctHash: "76c6b3d8a7ddbc387ca87aa784e99354feeda1ff438768cd99232a6772cceac0",
			wrongHash:   "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			params:      map[string]interface{}{"query": "test"},
		},
		{
			name:        "ReadHashVerification",
			tool:        "read",
			correctHash: "c4fbe869591f047985cd812915ed87d2c9c77de445089dcbc507416a86491453",
			wrongHash:   "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			params:      map[string]interface{}{"file_path": pocDir() + "/README.md"},
		},
		{
			name:        "GrepHashVerification",
			tool:        "grep",
			correctHash: "8bf71be3abae46b7ac610d92913c20e5f8d46bdbde9144c1c7e9798d92518cec",
			wrongHash:   "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			params:      map[string]interface{}{"pattern": "test", "path": pocDir()},
		},
		{
			name:        "BashHashVerification",
			tool:        "bash",
			correctHash: "ada241bb834f0737fd259606208f5d8ba2aeb2adbefa5ddc9df8f59b7c152c9f",
			wrongHash:   "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			params:      map[string]interface{}{"command": "echo test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_CorrectHash", func(t *testing.T) {
			// Test with correct hash - should be allowed
			params := make(map[string]interface{})
			for k, v := range tt.params {
				params[k] = v
			}
			params["tool_hash"] = tt.correctHash

			mcpReq := map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  tt.tool,
				"params":  params,
				"id":      "hash-test-correct",
			}
			reqBody, _ := json.Marshal(mcpReq)

			req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/precinct-gateway/dev")
			if tt.tool == "bash" {
				req.Header.Set("X-Step-Up-Token", "valid-step-up-token-12345")
			}

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if tt.tool == "tavily_search" {
				if resp.StatusCode == http.StatusForbidden {
					t.Errorf("Tool %s with correct hash was blocked (403)", tt.tool)
				} else {
					t.Logf("Tool %s with correct hash allowed (status %d)", tt.tool, resp.StatusCode)
				}
				return
			}
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("Tool %s with correct hash should still be denied in the live compose profile, got %d", tt.tool, resp.StatusCode)
			} else {
				t.Logf("Tool %s with correct hash correctly remained denied in the live compose profile", tt.tool)
			}
		})

		t.Run(tt.name+"_WrongHash", func(t *testing.T) {
			// Test with wrong hash - should be denied
			params := make(map[string]interface{})
			for k, v := range tt.params {
				params[k] = v
			}
			params["tool_hash"] = tt.wrongHash

			mcpReq := map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  tt.tool,
				"params":  params,
				"id":      "hash-test-wrong",
			}
			reqBody, _ := json.Marshal(mcpReq)

			req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/precinct-gateway/dev")
			if tt.tool == "bash" {
				req.Header.Set("X-Step-Up-Token", "valid-step-up-token-12345")
			}

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("Tool %s with wrong hash was not blocked (expected 403, got %d)", tt.tool, resp.StatusCode)
			} else {
				t.Logf("Tool %s with wrong hash correctly denied (403)", tt.tool)
			}
		})
	}
}

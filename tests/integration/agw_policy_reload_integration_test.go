//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAgwPolicyReloadIntegration_ModifyGrantsAndVerifyEffect(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	grantPath := filepath.Join(pocDir(), "config", "opa", "tool_grants.yaml")
	original, err := os.ReadFile(grantPath)
	if err != nil {
		t.Fatalf("read tool_grants.yaml: %v", err)
	}

	t.Cleanup(func() {
		_ = os.WriteFile(grantPath, original, 0644)
		restore := exec.Command("go", "run", "./cmd/agw", "policy", "reload", "--confirm", "--format", "json")
		restore.Dir = pocDir()
		_, _ = restore.CombinedOutput()
	})

	spiffeID := "spiffe://poc.local/agents/mcp-client/policy-reload-integration/dev"
	tool := "tavily_search"

	// Baseline: request should be denied by OPA before adding the grant.
	if code := postGatewayRPCForPolicyReload(t, spiffeID, tool, map[string]any{"query": "policy-reload-before"}); code != http.StatusForbidden {
		t.Fatalf("expected pre-reload OPA deny (403), got %d", code)
	}

	injection := `
  - spiffe_pattern: "spiffe://poc.local/agents/mcp-client/policy-reload-integration/dev"
    description: "Policy reload integration test grant"
    allowed_tools:
      - tavily_search
    max_data_classification: internal
    requires_approval_for: []
`

	originalText := string(original)
	updatedText := strings.Replace(originalText, "\n# Data classification levels", injection+"\n# Data classification levels", 1)
	if updatedText == originalText {
		t.Fatalf("failed to inject integration grant into tool_grants.yaml")
	}
	if err := os.WriteFile(grantPath, []byte(updatedText), 0644); err != nil {
		t.Fatalf("write modified tool_grants.yaml: %v", err)
	}

	// Reload through the CLI command under test.
	cmd := exec.Command("go", "run", "./cmd/agw", "policy", "reload", "--confirm", "--format", "json")
	cmd.Dir = pocDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("agw policy reload failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var reloadResp struct {
		Status        string `json:"status"`
		RegistryTools int    `json:"registry_tools"`
		OPAPolicies   int    `json:"opa_policies"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &reloadResp); err != nil {
		t.Fatalf("invalid policy reload json: %v raw=%q", err, stdout.String())
	}
	if reloadResp.Status != "reloaded" {
		t.Fatalf("expected status=reloaded, got %+v", reloadResp)
	}
	if reloadResp.OPAPolicies <= 0 {
		t.Fatalf("expected opa_policies > 0, got %+v", reloadResp)
	}

	// Post-reload: the same request should now pass OPA.
	if code := postGatewayRPCForPolicyReload(t, spiffeID, tool, map[string]any{"query": "policy-reload-after"}); code != http.StatusOK {
		t.Fatalf("expected post-reload request allowed (200), got %d", code)
	}
}

func postGatewayRPCForPolicyReload(t *testing.T, spiffeID, method string, params map[string]any) int {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, gatewayURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("gateway request failed: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

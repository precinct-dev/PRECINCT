//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestAgwInspectRateLimitIntegration_JSON(t *testing.T) {
	// Requires running gateway + KeyDB (compose stack). Skip quickly if not up.
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Skipf("Gateway not ready (requires running stack: make up): %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/inspect-ratelimit-researcher/dev"

	// Send a few MCP requests to create/update rate limit keys for this identity.
	for i := 0; i < 3; i++ {
		// Use a tool that is known to exist in the mock upstream + registry so the
		// request passes tool_registry_verify + OPA and reaches rate limiting.
		mcpReq := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "tavily_search",
			"params":  map[string]interface{}{"query": "rate-limit-test", "max_results": 1},
			"id":      1,
		}
		reqBody, _ := json.Marshal(mcpReq)
		req, err := http.NewRequest("POST", gatewayURL, bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SPIFFE-ID", spiffeID)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Inspect rate limit for the specific SPIFFE ID.
	cmd := exec.Command("go", "run", "./cmd/agw", "inspect", "rate-limit", spiffeID, "--format", "json")
	cmd.Dir = pocDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// If KeyDB is unreachable, the command should exit 1 and this integration test should fail.
		t.Fatalf("agw inspect rate-limit failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var parsed struct {
		RateLimits []struct {
			SPIFFEID   string `json:"spiffe_id"`
			Remaining  int    `json:"remaining"`
			Limit      int    `json:"limit"`
			Burst      int    `json:"burst"`
			TTLSeconds int    `json:"ttl_seconds"`
		} `json:"rate_limits"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("expected valid JSON, got err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if len(parsed.RateLimits) != 1 || parsed.RateLimits[0].SPIFFEID != spiffeID {
		t.Fatalf("unexpected parsed output: %+v", parsed)
	}
	if parsed.RateLimits[0].Limit <= 0 || parsed.RateLimits[0].Burst <= 0 {
		t.Fatalf("expected positive limit/burst, got %+v", parsed.RateLimits[0])
	}
	if parsed.RateLimits[0].TTLSeconds <= 0 {
		t.Fatalf("expected ttl_seconds > 0, got %+v", parsed.RateLimits[0])
	}
	if parsed.RateLimits[0].Remaining < 0 {
		t.Fatalf("expected remaining >= 0, got %+v", parsed.RateLimits[0])
	}

	if keydbUsesCompose(integrationKeyDBURL()) {
		t.Skip("compose://keydb mode validates targeted rate-limit inspection; all-active enumeration is too expensive for live compose exec")
	}

	// Inspect all active rate limits (should include the same identity).
	cmdAll := exec.Command("go", "run", "./cmd/agw", "inspect", "rate-limit", "--format", "json")
	cmdAll.Dir = pocDir()
	stdout.Reset()
	stderr.Reset()
	cmdAll.Stdout = &stdout
	cmdAll.Stderr = &stderr
	if err := cmdAll.Run(); err != nil {
		t.Fatalf("agw inspect rate-limit (all) failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), spiffeID) {
		t.Fatalf("expected all-rate-limits output to include %q; stdout=%q", spiffeID, stdout.String())
	}
}

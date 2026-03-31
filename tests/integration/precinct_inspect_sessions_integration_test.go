//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

func TestPrecinctInspectSessionsIntegration_JSON(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Skipf("Gateway not ready (requires running stack: make up): %v", err)
	}
	if keydbUsesCompose(integrationKeyDBURL()) {
		t.Skip("compose://keydb mode validates targeted session reset flows; live session enumeration is too expensive for compose exec")
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/inspect-sessions-researcher/dev"
	resetCircuitBreakerForTool(t, "tavily_search")
	// Generate real session activity through the gateway.
	for i := 0; i < 2; i++ {
		reqBody := []byte(`{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"session-inspect-test"},"id":1}`)
		req, err := http.NewRequest("POST", gatewayURL, bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SPIFFE-ID", spiffeID)

		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err == nil && resp != nil {
			resp.Body.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}

	cmd := exec.Command("go", "run", "./cli/precinct", "inspect", "sessions", spiffeID, "--format", "json")
	cmd.Dir = pocDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("precinct inspect sessions failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var parsed struct {
		Sessions []struct {
			SessionID     string  `json:"session_id"`
			SPIFFEID      string  `json:"spiffe_id"`
			RiskScore     float64 `json:"risk_score"`
			ToolsAccessed int     `json:"tools_accessed"`
			TTLSeconds    int     `json:"ttl_seconds"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("expected valid JSON, got err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if len(parsed.Sessions) == 0 {
		t.Fatalf("expected non-empty sessions output")
	}

	for _, s := range parsed.Sessions {
		if s.SPIFFEID != spiffeID {
			t.Fatalf("expected filtered spiffe=%s, got %+v", spiffeID, s)
		}
		if s.ToolsAccessed <= 0 {
			t.Fatalf("expected tools_accessed > 0, got %+v", s)
		}
		if s.TTLSeconds <= 0 {
			t.Fatalf("expected ttl_seconds > 0, got %+v", s)
		}
	}
}

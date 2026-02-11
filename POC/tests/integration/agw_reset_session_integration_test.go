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

func TestAgwResetSessionIntegration_ClearSPIFFEIdentitySessions(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"

	// Prime tool metadata hash observation to avoid early registry denials.
	if code := postGatewayRPCMethod(t, spiffeID, "tools/list", map[string]any{}); code != http.StatusOK {
		t.Fatalf("tools/list bootstrap failed, expected 200 got %d", code)
	}

	// Generate session activity through the live gateway.
	for i := 0; i < 2; i++ {
		_ = postGatewayRPCMethod(t, spiffeID, "tavily_search", map[string]any{"query": "reset-session-integration"})
	}
	time.Sleep(300 * time.Millisecond)

	inspectBefore := exec.Command("go", "run", "./cmd/agw", "inspect", "sessions", spiffeID, "--format", "json")
	inspectBefore.Dir = pocDir()
	var beforeOut, beforeErr bytes.Buffer
	inspectBefore.Stdout = &beforeOut
	inspectBefore.Stderr = &beforeErr
	if err := inspectBefore.Run(); err != nil {
		t.Fatalf("agw inspect sessions (before) failed: %v stdout=%q stderr=%q", err, beforeOut.String(), beforeErr.String())
	}

	var beforeParsed struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(beforeOut.Bytes(), &beforeParsed); err != nil {
		t.Fatalf("invalid inspect-before json: %v raw=%q", err, beforeOut.String())
	}
	if len(beforeParsed.Sessions) == 0 {
		t.Fatalf("expected at least one session before reset, got %+v", beforeParsed)
	}

	resetCmd := exec.Command("go", "run", "./cmd/agw", "reset", "session", spiffeID, "--confirm", "--format", "json")
	resetCmd.Dir = pocDir()
	var resetOut, resetErr bytes.Buffer
	resetCmd.Stdout = &resetOut
	resetCmd.Stderr = &resetErr
	if err := resetCmd.Run(); err != nil {
		t.Fatalf("agw reset session failed: %v stdout=%q stderr=%q", err, resetOut.String(), resetErr.String())
	}

	var resetParsed struct {
		Mode     string   `json:"mode"`
		SPIFFEID string   `json:"spiffe_id"`
		Deleted  int64    `json:"deleted"`
		Keys     []string `json:"keys"`
	}
	if err := json.Unmarshal(resetOut.Bytes(), &resetParsed); err != nil {
		t.Fatalf("invalid reset json: %v raw=%q", err, resetOut.String())
	}
	if resetParsed.Mode != "spiffe" || resetParsed.SPIFFEID != spiffeID {
		t.Fatalf("unexpected reset output metadata: %+v", resetParsed)
	}
	if resetParsed.Deleted == 0 || len(resetParsed.Keys) == 0 {
		t.Fatalf("expected deleted keys in reset output, got %+v", resetParsed)
	}

	inspectAfter := exec.Command("go", "run", "./cmd/agw", "inspect", "sessions", spiffeID, "--format", "json")
	inspectAfter.Dir = pocDir()
	var afterOut, afterErr bytes.Buffer
	inspectAfter.Stdout = &afterOut
	inspectAfter.Stderr = &afterErr
	if err := inspectAfter.Run(); err != nil {
		t.Fatalf("agw inspect sessions (after) failed: %v stdout=%q stderr=%q", err, afterOut.String(), afterErr.String())
	}

	var afterParsed struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(afterOut.Bytes(), &afterParsed); err != nil {
		t.Fatalf("invalid inspect-after json: %v raw=%q", err, afterOut.String())
	}
	if len(afterParsed.Sessions) != 0 {
		t.Fatalf("expected zero sessions after reset for %s, got %+v", spiffeID, afterParsed.Sessions)
	}
}

func postGatewayRPCMethod(t *testing.T, spiffeID, method string, params map[string]any) int {
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

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

func TestPrecinctAuditSearchIntegration_JSON(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Skipf("Gateway not ready (requires running stack: make up): %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"

	// Generate real audit entries through the running gateway:
	// one expected-allowed request and one expected-denied request.
	sendGatewayMCPRequest(t, spiffeID, `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"audit-search-integration"},"id":1}`)
	sendGatewayMCPRequest(t, spiffeID, `{"jsonrpc":"2.0","method":"tool_does_not_exist","params":{},"id":2}`)
	time.Sleep(300 * time.Millisecond)

	// Default source is docker compose logs (AC7).
	cmd := exec.Command("go", "run", "./cli/precinct", "audit", "search", "--spiffe-id", spiffeID, "--last", "1h", "--format", "json")
	cmd.Dir = pocDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("precinct audit search failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var parsed []struct {
		Timestamp  string `json:"timestamp"`
		DecisionID string `json:"decision_id"`
		SPIFFEID   string `json:"spiffe_id"`
		Result     string `json:"result"`
		StatusCode int    `json:"status_code"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("expected valid json array, got err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if len(parsed) == 0 {
		t.Fatalf("expected non-empty search results for spiffe=%q", spiffeID)
	}

	decisionID := ""
	for _, e := range parsed {
		if e.SPIFFEID == spiffeID && e.DecisionID != "" {
			decisionID = e.DecisionID
			break
		}
	}
	if decisionID == "" {
		t.Fatalf("expected at least one result with non-empty decision_id, got %+v", parsed)
	}

	// AC1: decision-id filter should return that specific entry.
	cmdByDecision := exec.Command("go", "run", "./cli/precinct", "audit", "search", "--decision-id", decisionID, "--format", "json")
	cmdByDecision.Dir = pocDir()
	stdout.Reset()
	stderr.Reset()
	cmdByDecision.Stdout = &stdout
	cmdByDecision.Stderr = &stderr
	if err := cmdByDecision.Run(); err != nil {
		t.Fatalf("precinct audit search --decision-id failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var decisionParsed []struct {
		DecisionID string `json:"decision_id"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decisionParsed); err != nil {
		t.Fatalf("expected valid json, got err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if len(decisionParsed) == 0 {
		t.Fatalf("expected decision-id query to return entries for %q", decisionID)
	}
	for _, e := range decisionParsed {
		if e.DecisionID != decisionID {
			t.Fatalf("expected only decision_id=%q, got %+v", decisionID, decisionParsed)
		}
	}

	// AC3: denied filter should include denied/error entries in the time window.
	cmdDenied := exec.Command("go", "run", "./cli/precinct", "audit", "search", "--denied", "--last", "1h", "--format", "json")
	cmdDenied.Dir = pocDir()
	stdout.Reset()
	stderr.Reset()
	cmdDenied.Stdout = &stdout
	cmdDenied.Stderr = &stderr
	if err := cmdDenied.Run(); err != nil {
		t.Fatalf("precinct audit search --denied failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var deniedParsed []struct {
		Result     string `json:"result"`
		StatusCode int    `json:"status_code"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &deniedParsed); err != nil {
		t.Fatalf("expected valid json for denied query, got err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if len(deniedParsed) == 0 {
		t.Fatalf("expected non-empty denied search results")
	}
	for _, e := range deniedParsed {
		if e.Result != "denied" && e.StatusCode < 400 {
			t.Fatalf("expected denied/error entries, got %+v", e)
		}
	}
}

func sendGatewayMCPRequest(t *testing.T, spiffeID string, body string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, gatewayURL, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("gateway request failed: %v", err)
	}
	resp.Body.Close()
}

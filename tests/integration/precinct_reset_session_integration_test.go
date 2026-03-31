//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func TestPrecinctResetSessionIntegration_ClearSPIFFEIdentitySessions(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/reset-session-researcher/dev"
	sessionID := "reset-session-int-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	sessionKey := "session:" + spiffeID + ":" + sessionID
	actionsKey := sessionKey + ":actions"

	keydbSetValue(t, sessionKey, `{"RiskScore":0.22}`, 2*time.Minute)
	keydbRPushValues(t, actionsKey, `{"tool":"tavily_search"}`)

	if exists := keydbExists(t, sessionKey, actionsKey); exists == 0 {
		t.Fatalf("expected seeded session keys before reset")
	}

	resetCmd := exec.Command("go", "run", "./cli/precinct", "reset", "session", spiffeID, "--confirm", "--keydb-url", integrationKeyDBURL(), "--format", "json")
	resetCmd.Dir = pocDir()
	var resetOut, resetErr bytes.Buffer
	resetCmd.Stdout = &resetOut
	resetCmd.Stderr = &resetErr
	if err := resetCmd.Run(); err != nil {
		t.Fatalf("precinct reset session failed: %v stdout=%q stderr=%q", err, resetOut.String(), resetErr.String())
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

	if exists := keydbExists(t, sessionKey, actionsKey); exists != 0 {
		t.Fatalf("expected zero session keys after reset for %s, got exists=%d", spiffeID, exists)
	}
}

//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"testing"
)

func TestPrecinctPolicyTestOfflineIntegration_AllowedAndDeniedPairs(t *testing.T) {
	allowed := exec.Command(
		"go", "run", "./cli/precinct", "policy", "test",
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"tavily_search",
		"--params", `{"query":"offline-policy-allowed"}`,
		"--format", "json",
	)
	allowed.Dir = pocDir()
	var allowedOut, allowedErr bytes.Buffer
	allowed.Stdout = &allowedOut
	allowed.Stderr = &allowedErr
	if err := allowed.Run(); err != nil {
		t.Fatalf("allowed pair command failed: %v stdout=%q stderr=%q", err, allowedOut.String(), allowedErr.String())
	}

	var allowedParsed struct {
		Verdict string `json:"verdict"`
		Layers  []struct {
			Result string `json:"result"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(allowedOut.Bytes(), &allowedParsed); err != nil {
		t.Fatalf("invalid allowed JSON: %v raw=%q", err, allowedOut.String())
	}
	if allowedParsed.Verdict != "ALLOWED" {
		t.Fatalf("expected ALLOWED verdict, got %+v", allowedParsed)
	}

	denied := exec.Command(
		"go", "run", "./cli/precinct", "policy", "test",
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"tool_does_not_exist",
		"--format", "json",
	)
	denied.Dir = pocDir()
	var deniedOut, deniedErr bytes.Buffer
	denied.Stdout = &deniedOut
	denied.Stderr = &deniedErr
	if err := denied.Run(); err != nil {
		t.Fatalf("denied pair command failed: %v stdout=%q stderr=%q", err, deniedOut.String(), deniedErr.String())
	}

	var deniedParsed struct {
		Verdict       string `json:"verdict"`
		BlockingLayer int    `json:"blocking_layer"`
	}
	if err := json.Unmarshal(deniedOut.Bytes(), &deniedParsed); err != nil {
		t.Fatalf("invalid denied JSON: %v raw=%q", err, deniedOut.String())
	}
	if deniedParsed.Verdict != "DENIED" {
		t.Fatalf("expected DENIED verdict, got %+v", deniedParsed)
	}
	if deniedParsed.BlockingLayer != 4 {
		t.Fatalf("expected blocking_layer=4 (registry), got %+v", deniedParsed)
	}
}

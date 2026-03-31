//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestPrecinctPolicyListIntegration_JSONAndFilteredTable(t *testing.T) {
	cmdJSON := exec.Command("go", "run", "./cli/precinct", "policy", "list", "--format", "json")
	cmdJSON.Dir = pocDir()
	var stdout, stderr bytes.Buffer
	cmdJSON.Stdout = &stdout
	cmdJSON.Stderr = &stderr
	if err := cmdJSON.Run(); err != nil {
		t.Fatalf("precinct policy list json failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var parsed struct {
		Grants []struct {
			Description    string   `json:"description"`
			SPIFFEPattern  string   `json:"spiffe_pattern"`
			AllowedTools   []string `json:"allowed_tools"`
			Classification string   `json:"classification"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("expected valid JSON output, got err=%v raw=%q", err, stdout.String())
	}
	if len(parsed.Grants) == 0 {
		t.Fatalf("expected non-empty policy grants output")
	}

	cmdFiltered := exec.Command(
		"go", "run", "./cli/precinct", "policy", "list",
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"--format", "table",
	)
	cmdFiltered.Dir = pocDir()
	stdout.Reset()
	stderr.Reset()
	cmdFiltered.Stdout = &stdout
	cmdFiltered.Stderr = &stderr
	if err := cmdFiltered.Run(); err != nil {
		t.Fatalf("precinct policy list filtered table failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "GRANT") || !strings.Contains(out, "SPIFFE_PATTERN") {
		t.Fatalf("expected table headers, got %q", out)
	}
	if !strings.Contains(out, "dspy-researcher") && !strings.Contains(out, "*-researcher") {
		t.Fatalf("expected filtered grants for dspy identity, got %q", out)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePolicyFixtures(t *testing.T) (string, string) {
	t.Helper()

	tmp := t.TempDir()
	opaDir := filepath.Join(tmp, "opa")
	if err := os.MkdirAll(opaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	grants := `tool_grants:
  - spiffe_pattern: "spiffe://poc.local/agents/mcp-client/*-researcher/dev"
    description: "Research agents"
    allowed_tools: ["read", "grep", "tavily_search"]
    max_data_classification: internal
    requires_approval_for: ["bash"]
  - spiffe_pattern: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
    description: "DSPy Research Agent"
    allowed_tools: ["read", "llm_query"]
    max_data_classification: internal
    requires_approval_for: []
`
	registry := `tools:
  - name: "read"
    risk_level: "low"
    requires_step_up: false
  - name: "grep"
    risk_level: "low"
    requires_step_up: false
  - name: "tavily_search"
    risk_level: "medium"
    requires_step_up: false
  - name: "llm_query"
    risk_level: "medium"
    requires_step_up: false
`

	if err := os.WriteFile(filepath.Join(opaDir, "tool_grants.yaml"), []byte(grants), 0o644); err != nil {
		t.Fatalf("write grants: %v", err)
	}
	registryPath := filepath.Join(tmp, "tool-registry.yaml")
	if err := os.WriteFile(registryPath, []byte(registry), 0o644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	return opaDir, registryPath
}

func TestAgwPolicyList_JSON_All(t *testing.T) {
	opaDir, registryPath := writePolicyFixtures(t)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"policy", "list",
			"--opa-policy-dir", opaDir,
			"--tool-registry", registryPath,
			"--format", "json",
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
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
		t.Fatalf("expected valid json, got err=%v raw=%q", err, stdout.String())
	}
	if len(parsed.Grants) != 2 {
		t.Fatalf("expected 2 grants, got %+v", parsed.Grants)
	}
}

func TestAgwPolicyList_FilteredTableDefault(t *testing.T) {
	opaDir, registryPath := writePolicyFixtures(t)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"policy", "list", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"--opa-policy-dir", opaDir,
			"--tool-registry", registryPath,
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	s := stdout.String()
	if !strings.Contains(s, "GRANT") || !strings.Contains(s, "SPIFFE_PATTERN") {
		t.Fatalf("unexpected table output: %q", s)
	}
	if !strings.Contains(s, "DSPy Research Agent") || !strings.Contains(s, "Research agents") {
		t.Fatalf("expected both exact+wildcard grants for dspy, got: %q", s)
	}
}

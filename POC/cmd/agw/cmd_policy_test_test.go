package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePolicyTestCLIConfig(t *testing.T) (opaDir string, registryPath string) {
	t.Helper()

	tmp := t.TempDir()
	opaDir = filepath.Join(tmp, "opa")
	if err := os.MkdirAll(opaDir, 0o755); err != nil {
		t.Fatalf("mkdir opa dir: %v", err)
	}

	grants := `tool_grants:
  - spiffe_pattern: "spiffe://poc.local/agents/mcp-client/*-researcher/dev"
    description: "Research agents"
    allowed_tools: ["tavily_search"]
    max_data_classification: internal
    requires_approval_for: []
`
	if err := os.WriteFile(filepath.Join(opaDir, "tool_grants.yaml"), []byte(grants), 0o644); err != nil {
		t.Fatalf("write grants: %v", err)
	}

	registryPath = filepath.Join(tmp, "tool-registry.yaml")
	registry := `tools:
  - name: "tavily_search"
    hash: "76c6b3d8a7ddbc387ca87aa784e99354feeda1ff438768cd99232a6772cceac0"
`
	if err := os.WriteFile(registryPath, []byte(registry), 0o644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	return opaDir, registryPath
}

func TestAgwPolicyTest_JSONAllowed(t *testing.T) {
	opaDir, registryPath := writePolicyTestCLIConfig(t)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"policy", "test",
			"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"tavily_search",
			"--opa-policy-dir", opaDir,
			"--tool-registry", registryPath,
			"--params", `{"query":"hello"}`,
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
		Verdict string `json:"verdict"`
		Layers  []struct {
			Step   int    `json:"step"`
			Result string `json:"result"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v raw=%q", err, stdout.String())
	}
	if parsed.Verdict != "ALLOWED" {
		t.Fatalf("expected ALLOWED verdict, got %+v", parsed)
	}
	if len(parsed.Layers) != 6 {
		t.Fatalf("expected 6 layers, got %+v", parsed.Layers)
	}
}

func TestAgwPolicyTest_TableDenied(t *testing.T) {
	opaDir, registryPath := writePolicyTestCLIConfig(t)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"policy", "test",
			"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"unknown_tool",
			"--opa-policy-dir", opaDir,
			"--tool-registry", registryPath,
			"--format", "table",
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "DRY RUN (offline)") {
		t.Fatalf("expected dry-run heading, got %q", out)
	}
	if !strings.Contains(out, "VERDICT: DENIED (blocked at layer 4)") {
		t.Fatalf("expected denied verdict, got %q", out)
	}
	if !strings.Contains(out, "NOTE: Runtime layers 7-13 require --runtime flag with running stack") {
		t.Fatalf("expected runtime note, got %q", out)
	}
}

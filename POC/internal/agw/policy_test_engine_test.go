package agw

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePolicyTestFixtures(t *testing.T) (opaDir string, registryPath string) {
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
    risk_level: "medium"
    requires_step_up: false
`
	if err := os.WriteFile(registryPath, []byte(registry), 0o644); err != nil {
		t.Fatalf("write registry: %v", err)
	}

	return opaDir, registryPath
}

func TestRunPolicyTestOffline_Allowed(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)

	out, err := RunPolicyTestOffline(
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"tavily_search",
		`{"query":"hello"}`,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "ALLOWED" {
		t.Fatalf("expected ALLOWED verdict, got %+v", out)
	}
	if len(out.Layers) != 6 {
		t.Fatalf("expected 6 layers, got %+v", out.Layers)
	}
	for i, layer := range out.Layers {
		if layer.Result != "PASS" {
			t.Fatalf("expected layer %d PASS, got %+v", i+1, layer)
		}
	}
}

func TestRunPolicyTestOffline_Layer1SizeFail(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)
	huge := `{"blob":"` + strings.Repeat("a", policyTestMaxRequestSizeBytes) + `"}`

	out, err := RunPolicyTestOffline(
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"tavily_search",
		huge,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 1 {
		t.Fatalf("expected layer-1 denial, got %+v", out)
	}
}

func TestRunPolicyTestOffline_Layer2BodyFail(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)

	out, err := RunPolicyTestOffline(
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"tavily_search",
		`{"query":`,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 2 {
		t.Fatalf("expected layer-2 denial, got %+v", out)
	}
}

func TestRunPolicyTestOffline_Layer3SpiffeFail(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)

	out, err := RunPolicyTestOffline(
		"spiffe://other.local/agents/mcp-client/dspy-researcher/dev",
		"tavily_search",
		`{"query":"hello"}`,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 3 {
		t.Fatalf("expected layer-3 denial, got %+v", out)
	}
}

func TestRunPolicyTestOffline_Layer4RegistryFail(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)

	out, err := RunPolicyTestOffline(
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"unknown_tool",
		`{"query":"hello"}`,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 4 {
		t.Fatalf("expected layer-4 denial, got %+v", out)
	}
}

func TestRunPolicyTestOffline_Layer5OPAFail(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)

	out, err := RunPolicyTestOffline(
		"spiffe://poc.local/agents/mcp-client/other/dev",
		"tavily_search",
		`{"query":"hello"}`,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 5 {
		t.Fatalf("expected layer-5 denial, got %+v", out)
	}
}

func TestRunPolicyTestOffline_Layer6DLPFail(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)

	out, err := RunPolicyTestOffline(
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"tavily_search",
		`{"token":"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}`,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 6 {
		t.Fatalf("expected layer-6 denial, got %+v", out)
	}
}

func TestRenderPolicyTestOfflineTableAndJSON(t *testing.T) {
	out := PolicyTestOfflineOutput{
		Mode:          "offline",
		SPIFFEID:      "spiffe://poc.local/agents/x/dev",
		Tool:          "tavily_search",
		Verdict:       "DENIED",
		BlockingLayer: 5,
		Note:          "Runtime layers 7-13 require --runtime flag with running stack",
		Layers: []PolicyTestLayer{
			{Step: 1, Layer: "Request Size Limit", Result: "PASS", Detail: "ok"},
			{Step: 5, Layer: "OPA Policy", Result: "FAIL", Detail: "denied"},
		},
	}

	table, err := RenderPolicyTestOfflineTable(out)
	if err != nil {
		t.Fatalf("RenderPolicyTestOfflineTable failed: %v", err)
	}
	for _, want := range []string{
		"DRY RUN (offline)",
		"STEP",
		"OPA Policy",
		"VERDICT: DENIED (blocked at layer 5)",
	} {
		if !strings.Contains(table, want) {
			t.Fatalf("expected table output to contain %q, got %q", want, table)
		}
	}

	b, err := RenderPolicyTestOfflineJSON(out)
	if err != nil {
		t.Fatalf("RenderPolicyTestOfflineJSON failed: %v", err)
	}
	if !strings.Contains(string(b), `"blocking_layer":5`) {
		t.Fatalf("expected blocking layer in json, got %s", string(b))
	}
	if !strings.Contains(string(b), fmt.Sprintf(`"tool":"%s"`, out.Tool)) {
		t.Fatalf("expected tool field in json, got %s", string(b))
	}
}

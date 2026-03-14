package agw

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListPolicyGrants_AllAndFiltered(t *testing.T) {
	tmp := t.TempDir()
	opaDir := filepath.Join(tmp, "opa")
	if err := os.MkdirAll(opaDir, 0o755); err != nil {
		t.Fatalf("mkdir opa dir: %v", err)
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
`

	if err := os.WriteFile(filepath.Join(opaDir, "tool_grants.yaml"), []byte(grants), 0o644); err != nil {
		t.Fatalf("write grants: %v", err)
	}
	registryPath := filepath.Join(tmp, "tool-registry.yaml")
	if err := os.WriteFile(registryPath, []byte(registry), 0o644); err != nil {
		t.Fatalf("write registry: %v", err)
	}

	all, err := ListPolicyGrants(opaDir, registryPath, "")
	if err != nil {
		t.Fatalf("ListPolicyGrants(all): %v", err)
	}
	if len(all.Grants) != 2 {
		t.Fatalf("expected 2 grants, got %+v", all.Grants)
	}
	if all.Grants[0].RegisteredToolRefs == 0 {
		t.Fatalf("expected registered tool refs > 0, got %+v", all.Grants[0])
	}

	filtered, err := ListPolicyGrants(opaDir, registryPath, "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	if err != nil {
		t.Fatalf("ListPolicyGrants(filtered): %v", err)
	}
	if len(filtered.Grants) != 2 {
		t.Fatalf("expected wildcard + exact grants for dspy, got %+v", filtered.Grants)
	}

	none, err := ListPolicyGrants(opaDir, registryPath, "spiffe://other.domain/agent/dev")
	if err != nil {
		t.Fatalf("ListPolicyGrants(none): %v", err)
	}
	if len(none.Grants) != 0 {
		t.Fatalf("expected no grants for unmatched SPIFFE ID, got %+v", none.Grants)
	}
}

func TestRenderPolicyListOutputs(t *testing.T) {
	out := PolicyListOutput{
		Grants: []PolicyGrant{
			{
				Description:      "Research agents",
				SPIFFEPattern:    "spiffe://poc.local/agents/mcp-client/*-researcher/dev",
				AllowedTools:     []string{"read", "grep"},
				Classification:   "internal",
				ApprovalRequired: []string{"bash"},
			},
		},
	}

	table, err := RenderPolicyListTable(out)
	if err != nil {
		t.Fatalf("RenderPolicyListTable: %v", err)
	}
	if !strings.Contains(table, "GRANT") || !strings.Contains(table, "Research agents") || !strings.Contains(table, "spiffe://poc.local/agents/mcp-client/*-researcher/dev") {
		t.Fatalf("unexpected table output:\n%s", table)
	}

	b, err := RenderPolicyListJSON(out)
	if err != nil {
		t.Fatalf("RenderPolicyListJSON: %v", err)
	}
	var parsed PolicyListOutput
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("expected valid JSON, got err=%v raw=%q", err, string(b))
	}
	if len(parsed.Grants) != 1 || parsed.Grants[0].Description != "Research agents" {
		t.Fatalf("unexpected parsed json: %+v", parsed)
	}
}

package precinctcli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectIdentity_MatchesWildcardAndExactGrants(t *testing.T) {
	tmp := t.TempDir()
	opaDir := filepath.Join(tmp, "opa")
	if err := os.MkdirAll(opaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	grants := `tool_grants:
  - spiffe_pattern: "spiffe://poc.local/agents/mcp-client/*-researcher/dev"
    description: "Research agents"
    allowed_tools: ["read", "grep"]
    max_data_classification: internal
    requires_approval_for: ["bash"]
  - spiffe_pattern: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
    description: "DSPy agent"
    allowed_tools: ["llm_query"]
    max_data_classification: internal
    requires_approval_for: []
`
	registry := `tools:
  - name: "read"
    risk_level: "low"
    requires_step_up: false
  - name: "bash"
    risk_level: "critical"
    requires_step_up: true
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

	out, err := InspectIdentity("spiffe://poc.local/agents/mcp-client/dspy-researcher/dev", opaDir, registryPath)
	if err != nil {
		t.Fatalf("InspectIdentity: %v", err)
	}
	if len(out.MatchedGrants) != 2 {
		t.Fatalf("expected 2 matched grants, got %d", len(out.MatchedGrants))
	}

	byTool := map[string]IdentityToolPermission{}
	for _, p := range out.Tools {
		byTool[p.Tool] = p
	}
	if !byTool["read"].Authorized {
		t.Fatalf("expected read to be authorized")
	}
	if byTool["bash"].Authorized {
		t.Fatalf("expected bash to be unauthorized")
	}
	if !byTool["bash"].ApprovalRequired {
		t.Fatalf("expected bash approval requirement from matched grant")
	}
	if !byTool["llm_query"].Authorized {
		t.Fatalf("expected llm_query to be authorized by exact grant")
	}
}

func TestInspectIdentity_NoMatchingGrant(t *testing.T) {
	tmp := t.TempDir()
	opaDir := filepath.Join(tmp, "opa")
	if err := os.MkdirAll(opaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(opaDir, "tool_grants.yaml"), []byte(`tool_grants:
  - spiffe_pattern: "spiffe://poc.local/agents/*"
    description: "agents"
    allowed_tools: ["read"]
    max_data_classification: internal
    requires_approval_for: []
`), 0o644); err != nil {
		t.Fatalf("write grants: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "tool-registry.yaml"), []byte(`tools:
  - name: "read"
    risk_level: "low"
    requires_step_up: false
`), 0o644); err != nil {
		t.Fatalf("write registry: %v", err)
	}

	_, err := InspectIdentity("spiffe://different.domain/agent/dev", opaDir, filepath.Join(tmp, "tool-registry.yaml"))
	if !errors.Is(err, ErrNoMatchingGrants) {
		t.Fatalf("expected ErrNoMatchingGrants, got %v", err)
	}
}

func TestRenderIdentityOutputs(t *testing.T) {
	out := IdentityInspection{
		SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		MatchedGrants: []MatchedGrant{
			{
				SPIFFEPattern: "spiffe://poc.local/agents/mcp-client/*-researcher/dev",
				Description:   "Research agents",
			},
		},
		Tools: []IdentityToolPermission{
			{Tool: "read", Authorized: true, RiskLevel: "low", RequiresStepUp: false, ApprovalRequired: false},
			{Tool: "bash", Authorized: false, RiskLevel: "critical", RequiresStepUp: true, ApprovalRequired: true},
		},
	}

	js, err := RenderIdentityJSON(out)
	if err != nil {
		t.Fatalf("RenderIdentityJSON: %v", err)
	}
	var parsed IdentityInspection
	if err := json.Unmarshal(js, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.SPIFFEID != out.SPIFFEID {
		t.Fatalf("unexpected parsed spiffe id: %q", parsed.SPIFFEID)
	}

	table, err := RenderIdentityTable(out)
	if err != nil {
		t.Fatalf("RenderIdentityTable: %v", err)
	}
	for _, needle := range []string{"SPIFFE ID:", "MATCHED GRANTS:", "TOOL", "AUTHORIZED", "read", "bash"} {
		if !strings.Contains(table, needle) {
			t.Fatalf("expected %q in table output:\n%s", needle, table)
		}
	}
}

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseToolExecutionInputValidation(t *testing.T) {
	envelope := RunEnvelope{
		RunID:         "run-1",
		SessionID:     "sess-1",
		Tenant:        "tenant-a",
		ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Plane:         PlaneTool,
	}

	_, err := parseToolExecutionInput(envelope, map[string]any{
		"protocol":      "mcp",
		"capability_id": "tool.default.mcp",
		"tool_name":     "read",
	})
	if err != nil {
		t.Fatalf("expected valid mcp input, got error: %v", err)
	}

	_, err = parseToolExecutionInput(envelope, map[string]any{
		"protocol":      "cli",
		"capability_id": "tool.default.cli",
		"command":       "ls",
		"args":          []any{"-la"},
	})
	if err != nil {
		t.Fatalf("expected valid cli input, got error: %v", err)
	}

	_, err = parseToolExecutionInput(envelope, map[string]any{
		"protocol":      "cli",
		"capability_id": "tool.default.cli",
		"command":       "ls -la",
	})
	if err == nil {
		t.Fatal("expected command with whitespace to be rejected")
	}
}

func TestToolPlanePolicyEngineCapabilityScope(t *testing.T) {
	engine := newToolPlanePolicyEngine("")
	req := PlaneRequestV2{
		Envelope: RunEnvelope{
			RunID:         "run-tool-1",
			SessionID:     "sess-tool-1",
			Tenant:        "tenant-a",
			ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			Plane:         PlaneTool,
		},
		Policy: PolicyInputV2{
			Envelope: RunEnvelope{
				RunID:         "run-tool-1",
				SessionID:     "sess-tool-1",
				Tenant:        "tenant-a",
				ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Plane:         PlaneTool,
			},
			Action:   "tool.execute",
			Resource: "tool/read",
			Attributes: map[string]any{
				"protocol":      "mcp",
				"capability_id": "tool.default.mcp",
				"tool_name":     "read",
			},
		},
	}

	decision, reason, status, metadata := engine.evaluate(req)
	if decision != DecisionAllow || reason != ReasonToolAllow || status != 200 {
		t.Fatalf("expected allow, got decision=%s reason=%s status=%d metadata=%v", decision, reason, status, metadata)
	}
	if metadata["policy_path"] != "shared_tool_plane_policy_v2" {
		t.Fatalf("expected shared policy path metadata, got %v", metadata["policy_path"])
	}

	req.Envelope.Tenant = "tenant-other"
	req.Policy.Envelope.Tenant = "tenant-other"
	decision, reason, status, _ = engine.evaluate(req)
	if decision != DecisionDeny || reason != ReasonToolCapabilityDenied || status != 403 {
		t.Fatalf("expected capability deny for wrong tenant, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

func TestToolPlanePolicyEngineCLIConstraints(t *testing.T) {
	engine := newToolPlanePolicyEngine("")
	req := PlaneRequestV2{
		Envelope: RunEnvelope{
			RunID:         "run-tool-2",
			SessionID:     "sess-tool-2",
			Tenant:        "tenant-a",
			ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			Plane:         PlaneTool,
		},
		Policy: PolicyInputV2{
			Envelope: RunEnvelope{
				RunID:         "run-tool-2",
				SessionID:     "sess-tool-2",
				Tenant:        "tenant-a",
				ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Plane:         PlaneTool,
			},
			Action:   "tool.execute",
			Resource: "tool/cli/system",
			Attributes: map[string]any{
				"protocol":      "cli",
				"capability_id": "tool.default.cli",
				"command":       "ls",
				"args":          []any{"-la"},
			},
		},
	}

	decision, reason, status, _ := engine.evaluate(req)
	if decision != DecisionAllow || reason != ReasonToolAllow || status != 200 {
		t.Fatalf("expected allow, got decision=%s reason=%s status=%d", decision, reason, status)
	}

	req.Policy.Attributes["command"] = "rm"
	decision, reason, status, _ = engine.evaluate(req)
	if decision != DecisionDeny || reason != ReasonToolCLICommandDenied || status != 403 {
		t.Fatalf("expected denied command, got decision=%s reason=%s status=%d", decision, reason, status)
	}

	req.Policy.Attributes["command"] = "ls"
	req.Policy.Attributes["args"] = []any{"-la", ";", "/tmp"}
	decision, reason, status, _ = engine.evaluate(req)
	if decision != DecisionDeny || reason != ReasonToolCLIArgsDenied || status != 403 {
		t.Fatalf("expected denied args token, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

func TestToolPlanePolicyEngineLoadsRegistryFromFile(t *testing.T) {
	dir := t.TempDir()
	registryPath := filepath.Join(dir, "capability-registry-v2.yaml")
	content := `
capability_grants:
  - id: custom-cli
    tenant: tenant-a
    workload: dspy-researcher
    protocol: cli
    capability_type: tool
    capability_id: tool.custom.cli
    effect_type: read
    risk_level: low
    allowed_actions: ["tool.execute"]
    allowed_resources: ["tool/cli/custom*"]
    allowed_commands: ["whoami"]
    max_args: 1
`
	if err := os.WriteFile(registryPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write registry file: %v", err)
	}

	engine := newToolPlanePolicyEngine(registryPath)
	req := PlaneRequestV2{
		Envelope: RunEnvelope{
			RunID:         "run-tool-3",
			SessionID:     "sess-tool-3",
			Tenant:        "tenant-a",
			ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			Plane:         PlaneTool,
		},
		Policy: PolicyInputV2{
			Envelope: RunEnvelope{
				RunID:         "run-tool-3",
				SessionID:     "sess-tool-3",
				Tenant:        "tenant-a",
				ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Plane:         PlaneTool,
			},
			Action:   "tool.execute",
			Resource: "tool/cli/custom-shell",
			Attributes: map[string]any{
				"protocol":      "cli",
				"capability_id": "tool.custom.cli",
				"command":       "whoami",
				"args":          []string{},
			},
		},
	}

	decision, reason, status, metadata := engine.evaluate(req)
	if decision != DecisionAllow || reason != ReasonToolAllow || status != 200 {
		t.Fatalf("expected allow from custom registry, got decision=%s reason=%s status=%d metadata=%v", decision, reason, status, metadata)
	}
	if metadata["capability_grant"] != "custom-cli" {
		t.Fatalf("expected custom capability grant metadata, got %v", metadata["capability_grant"])
	}
}

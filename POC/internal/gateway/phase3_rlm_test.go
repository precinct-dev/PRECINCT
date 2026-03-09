package gateway

import "testing"

func TestRLMGovernanceLineageAndBudgetAccounting(t *testing.T) {
	engine := newRLMGovernanceEngine()

	rootReq := PlaneRequestV2{
		Envelope: RunEnvelope{
			RunID:         "run-rlm-root",
			SessionID:     "sess-rlm",
			Tenant:        "tenant-a",
			ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			Plane:         PlaneModel,
			ExecutionMode: "rlm",
			LineageID:     "lineage-1",
		},
		Policy: PolicyInputV2{
			Envelope: RunEnvelope{
				RunID:         "run-rlm-root",
				SessionID:     "sess-rlm",
				Tenant:        "tenant-a",
				ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Plane:         PlaneModel,
				ExecutionMode: "rlm",
				LineageID:     "lineage-1",
			},
			Action:   "model.call",
			Resource: "model/inference",
			Attributes: map[string]any{
				"rlm_depth": 0,
				"rlm_limits": map[string]any{
					"max_depth":        2,
					"max_subcalls":     3,
					"max_budget_units": 2.5,
				},
				"rlm_subcall_budget_units": 1.0,
			},
		},
	}

	handled, decision, reason, status, metadata := engine.evaluate(rootReq)
	if !handled || decision != DecisionAllow || reason != ReasonRLMAllow || status != 200 {
		t.Fatalf("expected root allow, got handled=%v decision=%s reason=%s status=%d metadata=%v", handled, decision, reason, status, metadata)
	}

	childReq := rootReq
	childReq.Envelope.RunID = "run-rlm-child-1"
	childReq.Envelope.ParentRunID = "run-rlm-root"
	childReq.Policy.Envelope = childReq.Envelope
	childReq.Policy.Attributes = map[string]any{
		"rlm_depth":                1,
		"rlm_subcall":              true,
		"uasgs_mediated":           true,
		"rlm_subcall_budget_units": 1.0,
	}
	handled, decision, reason, status, metadata = engine.evaluate(childReq)
	if !handled || decision != DecisionAllow || reason != ReasonRLMAllow || status != 200 {
		t.Fatalf("expected child allow, got handled=%v decision=%s reason=%s status=%d metadata=%v", handled, decision, reason, status, metadata)
	}
	if metadata["rlm_parent_run_id"] != "run-rlm-root" {
		t.Fatalf("expected lineage parent_run_id in metadata, got %v", metadata["rlm_parent_run_id"])
	}
	if metadata["rlm_subcalls_used"] != 2 {
		t.Fatalf("expected rlm_subcalls_used=2, got %v", metadata["rlm_subcalls_used"])
	}

	overflowReq := childReq
	overflowReq.Envelope.RunID = "run-rlm-child-2"
	overflowReq.Policy.Envelope.RunID = "run-rlm-child-2"
	overflowReq.Policy.Attributes = map[string]any{
		"rlm_depth":                2,
		"rlm_subcall":              true,
		"uasgs_mediated":           true,
		"rlm_subcall_budget_units": 1.0,
	}
	handled, decision, reason, status, _ = engine.evaluate(overflowReq)
	if !handled || decision != DecisionDeny || reason != ReasonRLMHaltMaxBudget || status != 429 {
		t.Fatalf("expected budget halt, got handled=%v decision=%s reason=%s status=%d", handled, decision, reason, status)
	}
}

func TestRLMGovernanceBypassDenied(t *testing.T) {
	engine := newRLMGovernanceEngine()
	req := PlaneRequestV2{
		Envelope: RunEnvelope{
			RunID:         "run-rlm-bypass",
			SessionID:     "sess-rlm",
			Tenant:        "tenant-a",
			ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			Plane:         PlaneTool,
			ExecutionMode: "rlm",
			LineageID:     "lineage-bypass",
			ParentRunID:   "run-rlm-root",
		},
		Policy: PolicyInputV2{
			Envelope: RunEnvelope{
				RunID:         "run-rlm-bypass",
				SessionID:     "sess-rlm",
				Tenant:        "tenant-a",
				ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Plane:         PlaneTool,
				ExecutionMode: "rlm",
				LineageID:     "lineage-bypass",
				ParentRunID:   "run-rlm-root",
			},
			Action:   "tool.execute",
			Resource: "tool/read",
			Attributes: map[string]any{
				"rlm_depth":      1,
				"rlm_subcall":    true,
				"uasgs_mediated": false,
			},
		},
	}

	handled, decision, reason, status, _ := engine.evaluate(req)
	if !handled || decision != DecisionDeny || reason != ReasonRLMBypassDenied || status != 403 {
		t.Fatalf("expected bypass deny, got handled=%v decision=%s reason=%s status=%d", handled, decision, reason, status)
	}
}

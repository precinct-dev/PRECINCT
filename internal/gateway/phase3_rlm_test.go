// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"testing"
)

// ---------------------------------------------------------------------------
// Helper: build a PlaneRequestV2 with RLM-relevant fields populated.
// ---------------------------------------------------------------------------

func makeRLMRequest(runID, lineageID, executionMode string, depth int, attrs map[string]any) PlaneRequestV2 {
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs["rlm_depth"] = depth

	envelope := RunEnvelope{
		RunID:         runID,
		SessionID:     "sess-rlm-test",
		Tenant:        "test-tenant",
		ActorSPIFFEID: "spiffe://test/actor",
		Plane:         PlaneModel,
		ExecutionMode: executionMode,
		LineageID:     lineageID,
	}

	return PlaneRequestV2{
		Envelope: envelope,
		Policy: PolicyInputV2{
			Envelope:   envelope,
			Action:     "model.call",
			Resource:   "model/inference",
			Attributes: attrs,
		},
	}
}

func makeRLMSubcallRequest(runID, lineageID, parentRunID, parentDecisionID string, depth int, attrs map[string]any) PlaneRequestV2 {
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs["rlm_subcall"] = true
	attrs["rlm_depth"] = depth

	envelope := RunEnvelope{
		RunID:            runID,
		SessionID:        "sess-rlm-test",
		Tenant:           "test-tenant",
		ActorSPIFFEID:    "spiffe://test/actor",
		Plane:            PlaneModel,
		ExecutionMode:    "rlm",
		LineageID:        lineageID,
		ParentRunID:      parentRunID,
		ParentDecisionID: parentDecisionID,
	}

	return PlaneRequestV2{
		Envelope: envelope,
		Policy: PolicyInputV2{
			Envelope:   envelope,
			Action:     "model.call",
			Resource:   "model/inference",
			Attributes: attrs,
		},
	}
}

// ===========================================================================
// UNIT TESTS -- exercise rlmGovernanceEngine.evaluate() directly
// ===========================================================================

func TestRLMEngine_BypassWhenNotRLM(t *testing.T) {
	engine := newRLMGovernanceEngine()

	// Standard execution mode: engine should not handle the request.
	req := makeRLMRequest("run-1", "", "standard", 0, nil)
	handled, _, _, _, _ := engine.evaluate(req)

	if handled {
		t.Fatal("expected handled=false for execution_mode=standard, got true")
	}
}

func TestRLMEngine_BypassWhenNoModeSet(t *testing.T) {
	engine := newRLMGovernanceEngine()

	// Empty execution mode, no rlm_subcall: should not engage.
	req := makeRLMRequest("run-1", "", "", 0, nil)
	handled, _, _, _, _ := engine.evaluate(req)

	if handled {
		t.Fatal("expected handled=false for empty execution_mode, got true")
	}
}

func TestRLMEngine_ValidRootRequest(t *testing.T) {
	engine := newRLMGovernanceEngine()

	req := makeRLMRequest("run-root", "lineage-1", "rlm", 0, nil)
	handled, decision, reason, status, meta := engine.evaluate(req)

	if !handled {
		t.Fatal("expected handled=true for valid RLM request")
	}
	if decision != DecisionAllow {
		t.Fatalf("expected DecisionAllow, got %q", decision)
	}
	if reason != ReasonRLMAllow {
		t.Fatalf("expected ReasonRLMAllow, got %q", reason)
	}
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	// Validate metadata keys expected on every allow response.
	requiredKeys := []string{
		"rlm_mode", "rlm_lineage_id", "rlm_root_run_id",
		"rlm_current_run_id", "rlm_parent_run_id", "rlm_parent_decision_id",
		"rlm_depth", "rlm_subcall_budget_units", "rlm_subcalls_used",
		"rlm_subcalls_remaining", "rlm_budget_units_used",
		"rlm_budget_units_remaining", "rlm_limits",
	}
	for _, key := range requiredKeys {
		if _, ok := meta[key]; !ok {
			t.Errorf("missing metadata key %q", key)
		}
	}

	// Root request should record its own run_id as root.
	if rootID, ok := meta["rlm_root_run_id"].(string); !ok || rootID != "run-root" {
		t.Errorf("expected rlm_root_run_id=run-root, got %v", meta["rlm_root_run_id"])
	}
	if currentID, ok := meta["rlm_current_run_id"].(string); !ok || currentID != "run-root" {
		t.Errorf("expected rlm_current_run_id=run-root, got %v", meta["rlm_current_run_id"])
	}
	if meta["rlm_mode"] != true {
		t.Errorf("expected rlm_mode=true, got %v", meta["rlm_mode"])
	}
}

func TestRLMEngine_SubcallWithoutUASGSMediation(t *testing.T) {
	engine := newRLMGovernanceEngine()

	// Subcall at depth 1 WITHOUT uasgs_mediated=true must be denied.
	req := makeRLMSubcallRequest("run-child", "lineage-1", "run-root", "dec-root", 1, nil)
	handled, decision, reason, status, meta := engine.evaluate(req)

	if !handled {
		t.Fatal("expected handled=true")
	}
	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %q", decision)
	}
	if reason != ReasonRLMBypassDenied {
		t.Fatalf("expected ReasonRLMBypassDenied, got %q", reason)
	}
	if status != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", status)
	}
	if meta["uasgs_mediated"] != false {
		t.Errorf("expected uasgs_mediated=false in metadata, got %v", meta["uasgs_mediated"])
	}
}

func TestRLMEngine_DepthExceedsMax(t *testing.T) {
	engine := newRLMGovernanceEngine()

	// Custom limits with max_depth=2, then request at depth 3.
	attrs := map[string]any{
		"uasgs_mediated": true,
		"rlm_limits": map[string]any{
			"max_depth":        2,
			"max_subcalls":     64,
			"max_budget_units": 128.0,
		},
	}
	req := makeRLMSubcallRequest("run-deep", "lineage-1", "run-parent", "dec-parent", 3, attrs)
	handled, decision, reason, status, _ := engine.evaluate(req)

	if !handled {
		t.Fatal("expected handled=true")
	}
	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %q", decision)
	}
	if reason != ReasonRLMHaltMaxDepth {
		t.Fatalf("expected ReasonRLMHaltMaxDepth, got %q", reason)
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("expected status 429, got %d", status)
	}
}

func TestRLMEngine_SubcallsExceedMax(t *testing.T) {
	engine := newRLMGovernanceEngine()

	lineage := "lineage-subcall-limit"
	attrs := func() map[string]any {
		return map[string]any{
			"uasgs_mediated": true,
			"rlm_limits": map[string]any{
				"max_depth":        10,
				"max_subcalls":     3,
				"max_budget_units": 1000.0,
			},
		}
	}

	// First call at depth 0 (root): uses 1 subcall slot.
	req0 := makeRLMRequest("run-0", lineage, "rlm", 0, attrs())
	if handled, decision, _, _, _ := engine.evaluate(req0); !handled || decision != DecisionAllow {
		t.Fatal("root request should be allowed")
	}

	// Second call: subcall at depth 1.
	req1 := makeRLMSubcallRequest("run-1", lineage, "run-0", "dec-0", 1, attrs())
	if handled, decision, _, _, _ := engine.evaluate(req1); !handled || decision != DecisionAllow {
		t.Fatal("2nd call should be allowed (2/3 subcalls)")
	}

	// Third call: subcall at depth 1.
	req2 := makeRLMSubcallRequest("run-2", lineage, "run-0", "dec-0", 1, attrs())
	if handled, decision, _, _, _ := engine.evaluate(req2); !handled || decision != DecisionAllow {
		t.Fatal("3rd call should be allowed (3/3 subcalls)")
	}

	// Fourth call: exceeds max_subcalls=3 (used 3, need 3+1 > 3).
	req3 := makeRLMSubcallRequest("run-3", lineage, "run-0", "dec-0", 1, attrs())
	handled, decision, reason, status, _ := engine.evaluate(req3)

	if !handled {
		t.Fatal("expected handled=true")
	}
	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %q", decision)
	}
	if reason != ReasonRLMHaltMaxSubcalls {
		t.Fatalf("expected ReasonRLMHaltMaxSubcalls, got %q", reason)
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("expected status 429, got %d", status)
	}
}

func TestRLMEngine_BudgetExceedsMax(t *testing.T) {
	engine := newRLMGovernanceEngine()

	lineage := "lineage-budget-limit"
	attrs := func(cost float64) map[string]any {
		return map[string]any{
			"uasgs_mediated":           true,
			"rlm_subcall_budget_units": cost,
			"rlm_limits": map[string]any{
				"max_depth":        10,
				"max_subcalls":     100,
				"max_budget_units": 5.0,
			},
		}
	}

	// Root call with cost 2.0.
	req0 := makeRLMRequest("run-0", lineage, "rlm", 0, attrs(2.0))
	if handled, decision, _, _, _ := engine.evaluate(req0); !handled || decision != DecisionAllow {
		t.Fatal("root request should be allowed (budget 2/5)")
	}

	// Subcall with cost 2.5 (total: 4.5, under 5.0).
	req1 := makeRLMSubcallRequest("run-1", lineage, "run-0", "dec-0", 1, attrs(2.5))
	if handled, decision, _, _, _ := engine.evaluate(req1); !handled || decision != DecisionAllow {
		t.Fatal("2nd call should be allowed (budget 4.5/5)")
	}

	// Subcall with cost 1.0 (total would be 5.5, exceeding 5.0).
	req2 := makeRLMSubcallRequest("run-2", lineage, "run-0", "dec-0", 1, attrs(1.0))
	handled, decision, reason, status, _ := engine.evaluate(req2)

	if !handled {
		t.Fatal("expected handled=true")
	}
	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %q", decision)
	}
	if reason != ReasonRLMHaltMaxBudget {
		t.Fatalf("expected ReasonRLMHaltMaxBudget, got %q", reason)
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("expected status 429, got %d", status)
	}
}

func TestRLMEngine_MissingLineageID(t *testing.T) {
	engine := newRLMGovernanceEngine()

	req := makeRLMRequest("run-1", "", "rlm", 0, nil)
	// Remove lineage_id from envelope too (makeRLMRequest already sets it empty).
	handled, decision, reason, status, meta := engine.evaluate(req)

	if !handled {
		t.Fatal("expected handled=true for schema error")
	}
	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %q", decision)
	}
	if reason != ReasonRLMSchemaInvalid {
		t.Fatalf("expected ReasonRLMSchemaInvalid, got %q", reason)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", status)
	}
	if _, ok := meta["rlm_schema_error"]; !ok {
		t.Error("expected rlm_schema_error in metadata")
	}
}

func TestRLMEngine_MissingRLMDepth(t *testing.T) {
	engine := newRLMGovernanceEngine()

	// Build request manually to omit rlm_depth.
	envelope := RunEnvelope{
		RunID:         "run-nodepth",
		SessionID:     "sess-rlm-test",
		Tenant:        "test-tenant",
		ActorSPIFFEID: "spiffe://test/actor",
		Plane:         PlaneModel,
		ExecutionMode: "rlm",
		LineageID:     "lineage-nodepth",
	}
	req := PlaneRequestV2{
		Envelope: envelope,
		Policy: PolicyInputV2{
			Envelope:   envelope,
			Action:     "model.call",
			Resource:   "model/inference",
			Attributes: map[string]any{}, // no rlm_depth
		},
	}

	handled, decision, reason, status, _ := engine.evaluate(req)

	if !handled {
		t.Fatal("expected handled=true for missing rlm_depth")
	}
	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %q", decision)
	}
	if reason != ReasonRLMSchemaInvalid {
		t.Fatalf("expected ReasonRLMSchemaInvalid, got %q", reason)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", status)
	}
}

func TestRLMEngine_DepthGreaterThanZeroWithoutParentRunID(t *testing.T) {
	engine := newRLMGovernanceEngine()

	// Depth > 0 but no parent_run_id should be a schema error.
	attrs := map[string]any{
		"uasgs_mediated": true,
	}
	envelope := RunEnvelope{
		RunID:         "run-noparent",
		SessionID:     "sess-rlm-test",
		Tenant:        "test-tenant",
		ActorSPIFFEID: "spiffe://test/actor",
		Plane:         PlaneModel,
		ExecutionMode: "rlm",
		LineageID:     "lineage-noparent",
		// ParentRunID intentionally omitted.
	}
	attrs["rlm_depth"] = 2
	req := PlaneRequestV2{
		Envelope: envelope,
		Policy: PolicyInputV2{
			Envelope:   envelope,
			Action:     "model.call",
			Resource:   "model/inference",
			Attributes: attrs,
		},
	}

	handled, decision, reason, status, _ := engine.evaluate(req)

	if !handled {
		t.Fatal("expected handled=true for missing parent_run_id at depth>0")
	}
	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %q", decision)
	}
	if reason != ReasonRLMSchemaInvalid {
		t.Fatalf("expected ReasonRLMSchemaInvalid, got %q", reason)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", status)
	}
}

func TestRLMEngine_SubcallWithoutRLMMode(t *testing.T) {
	engine := newRLMGovernanceEngine()

	// rlm_subcall=true but execution_mode is "standard" -- schema error.
	envelope := RunEnvelope{
		RunID:         "run-badmode",
		SessionID:     "sess-rlm-test",
		Tenant:        "test-tenant",
		ActorSPIFFEID: "spiffe://test/actor",
		Plane:         PlaneModel,
		ExecutionMode: "standard",
	}
	req := PlaneRequestV2{
		Envelope: envelope,
		Policy: PolicyInputV2{
			Envelope: envelope,
			Action:   "model.call",
			Resource: "model/inference",
			Attributes: map[string]any{
				"rlm_subcall": true,
				"rlm_depth":   1,
			},
		},
	}

	handled, decision, reason, status, _ := engine.evaluate(req)

	if !handled {
		t.Fatal("expected handled=true for rlm_subcall with wrong mode")
	}
	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %q", decision)
	}
	if reason != ReasonRLMSchemaInvalid {
		t.Fatalf("expected ReasonRLMSchemaInvalid, got %q", reason)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", status)
	}
}

func TestRLMEngine_CustomLimitsOverrideDefaults(t *testing.T) {
	engine := newRLMGovernanceEngine()

	customLimits := map[string]any{
		"max_depth":        3,
		"max_subcalls":     10,
		"max_budget_units": 50.0,
	}
	attrs := map[string]any{
		"rlm_limits": customLimits,
	}

	// Request at depth 0 with custom limits should be allowed.
	req := makeRLMRequest("run-custom", "lineage-custom", "rlm", 0, attrs)
	handled, decision, _, _, meta := engine.evaluate(req)

	if !handled || decision != DecisionAllow {
		t.Fatal("expected allow for valid custom-limits request")
	}

	// Verify the limits in metadata reflect custom values.
	limits, ok := meta["rlm_limits"].(map[string]any)
	if !ok {
		t.Fatal("expected rlm_limits in metadata")
	}
	if limits["max_depth"] != 3 {
		t.Errorf("expected max_depth=3, got %v", limits["max_depth"])
	}
	if limits["max_subcalls"] != 10 {
		t.Errorf("expected max_subcalls=10, got %v", limits["max_subcalls"])
	}
	if limits["max_budget_units"] != 50.0 {
		t.Errorf("expected max_budget_units=50.0, got %v", limits["max_budget_units"])
	}

	// Now exceed custom max_depth: depth 4 > max_depth 3.
	attrs2 := map[string]any{
		"uasgs_mediated": true,
		"rlm_limits":     customLimits,
	}
	req2 := makeRLMSubcallRequest("run-deep-custom", "lineage-custom", "run-custom", "dec-custom", 4, attrs2)
	_, decision2, reason2, _, _ := engine.evaluate(req2)

	if decision2 != DecisionDeny || reason2 != ReasonRLMHaltMaxDepth {
		t.Fatalf("expected depth halt with custom max_depth=3 at depth=4, got decision=%q reason=%q", decision2, reason2)
	}
}

func TestRLMEngine_BudgetAccumulatesAcrossCalls(t *testing.T) {
	engine := newRLMGovernanceEngine()

	lineage := "lineage-budget-accumulate"
	baseLimits := map[string]any{
		"max_depth":        10,
		"max_subcalls":     100,
		"max_budget_units": 10.0,
	}

	// Root call, default cost = 1.0.
	req0 := makeRLMRequest("run-0", lineage, "rlm", 0, map[string]any{
		"rlm_limits": baseLimits,
	})
	_, _, _, _, meta0 := engine.evaluate(req0)
	if used, ok := meta0["rlm_budget_units_used"].(float64); !ok || used != 1.0 {
		t.Fatalf("expected budget_units_used=1.0 after root, got %v", meta0["rlm_budget_units_used"])
	}

	// Subcall with cost 3.5.
	req1 := makeRLMSubcallRequest("run-1", lineage, "run-0", "dec-0", 1, map[string]any{
		"uasgs_mediated":           true,
		"rlm_subcall_budget_units": 3.5,
		"rlm_limits":               baseLimits,
	})
	_, _, _, _, meta1 := engine.evaluate(req1)
	if used, ok := meta1["rlm_budget_units_used"].(float64); !ok || used != 4.5 {
		t.Fatalf("expected budget_units_used=4.5, got %v", meta1["rlm_budget_units_used"])
	}

	// Subcall with cost 2.0 (total 6.5).
	req2 := makeRLMSubcallRequest("run-2", lineage, "run-0", "dec-0", 1, map[string]any{
		"uasgs_mediated":           true,
		"rlm_subcall_budget_units": 2.0,
		"rlm_limits":               baseLimits,
	})
	_, _, _, _, meta2 := engine.evaluate(req2)
	if used, ok := meta2["rlm_budget_units_used"].(float64); !ok || used != 6.5 {
		t.Fatalf("expected budget_units_used=6.5, got %v", meta2["rlm_budget_units_used"])
	}

	remaining, ok := meta2["rlm_budget_units_remaining"].(float64)
	if !ok || remaining != 3.5 {
		t.Fatalf("expected budget_units_remaining=3.5, got %v", meta2["rlm_budget_units_remaining"])
	}
}

func TestRLMEngine_MultipleLineagesIndependent(t *testing.T) {
	engine := newRLMGovernanceEngine()

	limitsA := map[string]any{
		"max_depth":        10,
		"max_subcalls":     2,
		"max_budget_units": 100.0,
	}
	limitsB := map[string]any{
		"max_depth":        10,
		"max_subcalls":     2,
		"max_budget_units": 100.0,
	}

	// Lineage A: root call.
	reqA0 := makeRLMRequest("run-a0", "lineage-A", "rlm", 0, map[string]any{
		"rlm_limits": limitsA,
	})
	if _, d, _, _, _ := engine.evaluate(reqA0); d != DecisionAllow {
		t.Fatal("lineage A root should be allowed")
	}

	// Lineage B: root call.
	reqB0 := makeRLMRequest("run-b0", "lineage-B", "rlm", 0, map[string]any{
		"rlm_limits": limitsB,
	})
	if _, d, _, _, _ := engine.evaluate(reqB0); d != DecisionAllow {
		t.Fatal("lineage B root should be allowed")
	}

	// Lineage A: 2nd call (2/2 subcalls).
	reqA1 := makeRLMSubcallRequest("run-a1", "lineage-A", "run-a0", "dec-a0", 1, map[string]any{
		"uasgs_mediated": true,
		"rlm_limits":     limitsA,
	})
	if _, d, _, _, _ := engine.evaluate(reqA1); d != DecisionAllow {
		t.Fatal("lineage A 2nd call should be allowed (2/2)")
	}

	// Lineage A: 3rd call should be denied (3 > max_subcalls=2).
	reqA2 := makeRLMSubcallRequest("run-a2", "lineage-A", "run-a0", "dec-a0", 1, map[string]any{
		"uasgs_mediated": true,
		"rlm_limits":     limitsA,
	})
	_, dA2, reasonA2, _, _ := engine.evaluate(reqA2)
	if dA2 != DecisionDeny || reasonA2 != ReasonRLMHaltMaxSubcalls {
		t.Fatalf("lineage A 3rd call should hit subcall limit, got decision=%q reason=%q", dA2, reasonA2)
	}

	// Lineage B: 2nd call should still be allowed (independent tracking).
	reqB1 := makeRLMSubcallRequest("run-b1", "lineage-B", "run-b0", "dec-b0", 1, map[string]any{
		"uasgs_mediated": true,
		"rlm_limits":     limitsB,
	})
	_, dB1, _, _, _ := engine.evaluate(reqB1)
	if dB1 != DecisionAllow {
		t.Fatalf("lineage B 2nd call should be allowed (independent), got %q", dB1)
	}
}

func TestRLMEngine_DefaultLimits(t *testing.T) {
	engine := newRLMGovernanceEngine()

	// Root request with no explicit rlm_limits -- should use defaults.
	req := makeRLMRequest("run-defaults", "lineage-defaults", "rlm", 0, nil)
	handled, decision, _, _, meta := engine.evaluate(req)

	if !handled || decision != DecisionAllow {
		t.Fatal("expected allow for valid default-limits request")
	}

	limits, ok := meta["rlm_limits"].(map[string]any)
	if !ok {
		t.Fatal("expected rlm_limits in metadata")
	}
	if limits["max_depth"] != 6 {
		t.Errorf("default max_depth should be 6, got %v", limits["max_depth"])
	}
	if limits["max_subcalls"] != 64 {
		t.Errorf("default max_subcalls should be 64, got %v", limits["max_subcalls"])
	}
	if limits["max_budget_units"] != 128.0 {
		t.Errorf("default max_budget_units should be 128.0, got %v", limits["max_budget_units"])
	}
}

func TestRLMEngine_DefaultMaxDepthEnforcedAt6(t *testing.T) {
	engine := newRLMGovernanceEngine()

	// Depth 6 should be allowed (equal to max).
	attrs6 := map[string]any{
		"uasgs_mediated": true,
	}
	req6 := makeRLMSubcallRequest("run-d6", "lineage-depth-default", "run-parent", "dec-parent", 6, attrs6)
	_, d6, _, _, _ := engine.evaluate(req6)
	if d6 != DecisionAllow {
		t.Fatalf("depth 6 should be allowed with default max_depth=6, got %q", d6)
	}

	// Depth 7 should be denied.
	attrs7 := map[string]any{
		"uasgs_mediated": true,
	}
	req7 := makeRLMSubcallRequest("run-d7", "lineage-depth-default-2", "run-parent", "dec-parent", 7, attrs7)
	_, d7, r7, _, _ := engine.evaluate(req7)
	if d7 != DecisionDeny || r7 != ReasonRLMHaltMaxDepth {
		t.Fatalf("depth 7 should be denied with default max_depth=6, got decision=%q reason=%q", d7, r7)
	}
}

func TestRLMEngine_SubcallsRemaining(t *testing.T) {
	engine := newRLMGovernanceEngine()

	lineage := "lineage-remaining"
	limits := map[string]any{
		"max_depth":        10,
		"max_subcalls":     5,
		"max_budget_units": 100.0,
	}

	// Root call: used=1, remaining=4.
	req0 := makeRLMRequest("run-0", lineage, "rlm", 0, map[string]any{
		"rlm_limits": limits,
	})
	_, _, _, _, meta0 := engine.evaluate(req0)

	if meta0["rlm_subcalls_used"] != 1 {
		t.Errorf("expected subcalls_used=1 after root, got %v", meta0["rlm_subcalls_used"])
	}
	if meta0["rlm_subcalls_remaining"] != 4 {
		t.Errorf("expected subcalls_remaining=4, got %v", meta0["rlm_subcalls_remaining"])
	}
}

func TestRLMEngine_MediatedSubcallAllowed(t *testing.T) {
	engine := newRLMGovernanceEngine()

	// Subcall at depth 1 WITH uasgs_mediated=true should be allowed.
	attrs := map[string]any{
		"uasgs_mediated": true,
	}
	req := makeRLMSubcallRequest("run-child-ok", "lineage-mediated", "run-root", "dec-root", 1, attrs)
	handled, decision, reason, status, _ := engine.evaluate(req)

	if !handled {
		t.Fatal("expected handled=true")
	}
	if decision != DecisionAllow {
		t.Fatalf("expected DecisionAllow, got %q", decision)
	}
	if reason != ReasonRLMAllow {
		t.Fatalf("expected ReasonRLMAllow, got %q", reason)
	}
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}
}

func TestRLMEngine_NegativeDepthIsSchemaInvalid(t *testing.T) {
	engine := newRLMGovernanceEngine()

	// rlm_depth = -1 should fail schema validation.
	envelope := RunEnvelope{
		RunID:         "run-neg",
		SessionID:     "sess-rlm-test",
		Tenant:        "test-tenant",
		ActorSPIFFEID: "spiffe://test/actor",
		Plane:         PlaneModel,
		ExecutionMode: "rlm",
		LineageID:     "lineage-neg",
	}
	req := PlaneRequestV2{
		Envelope: envelope,
		Policy: PolicyInputV2{
			Envelope: envelope,
			Action:   "model.call",
			Resource: "model/inference",
			Attributes: map[string]any{
				"rlm_depth": -1,
			},
		},
	}

	handled, decision, reason, status, _ := engine.evaluate(req)

	if !handled {
		t.Fatal("expected handled=true")
	}
	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %q", decision)
	}
	if reason != ReasonRLMSchemaInvalid {
		t.Fatalf("expected ReasonRLMSchemaInvalid, got %q", reason)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", status)
	}
}

func TestRLMEngine_ZeroCostDefaultsToOne(t *testing.T) {
	engine := newRLMGovernanceEngine()

	attrs := map[string]any{
		"rlm_subcall_budget_units": 0.0, // Should default to 1.0.
		"rlm_limits": map[string]any{
			"max_depth":        10,
			"max_subcalls":     100,
			"max_budget_units": 100.0,
		},
	}
	req := makeRLMRequest("run-zerocost", "lineage-zerocost", "rlm", 0, attrs)
	_, _, _, _, meta := engine.evaluate(req)

	// Cost should be treated as 1.0 when <=0.
	if meta["rlm_subcall_budget_units"] != 1.0 {
		t.Errorf("expected subcall_budget_units=1.0 for zero cost, got %v", meta["rlm_subcall_budget_units"])
	}
	if meta["rlm_budget_units_used"] != 1.0 {
		t.Errorf("expected budget_units_used=1.0, got %v", meta["rlm_budget_units_used"])
	}
}

// ===========================================================================
// INTEGRATION TESTS -- exercise Gateway.evaluateRLMGovernance via full Gateway
// ===========================================================================

func TestRLMGovernance_IntegrationViaGateway_AllowRootRLM(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)

	req := makeRLMRequest("run-integ-root", "lineage-integ-1", "rlm", 0, nil)
	handled, decision, reason, status, meta := gw.evaluateRLMGovernance(req)

	if !handled {
		t.Fatal("expected handled=true via gateway for RLM request")
	}
	if decision != DecisionAllow {
		t.Fatalf("expected DecisionAllow, got %q", decision)
	}
	if reason != ReasonRLMAllow {
		t.Fatalf("expected ReasonRLMAllow, got %q", reason)
	}
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	// Verify all required metadata keys are present.
	requiredKeys := []string{
		"rlm_mode", "rlm_lineage_id", "rlm_root_run_id",
		"rlm_current_run_id", "rlm_parent_run_id", "rlm_parent_decision_id",
		"rlm_depth", "rlm_subcall_budget_units", "rlm_subcalls_used",
		"rlm_subcalls_remaining", "rlm_budget_units_used",
		"rlm_budget_units_remaining", "rlm_limits",
	}
	for _, key := range requiredKeys {
		if _, ok := meta[key]; !ok {
			t.Errorf("missing metadata key %q in gateway integration response", key)
		}
	}

	// Verify metadata values for root invocation.
	if meta["rlm_mode"] != true {
		t.Errorf("expected rlm_mode=true, got %v", meta["rlm_mode"])
	}
	if meta["rlm_lineage_id"] != "lineage-integ-1" {
		t.Errorf("expected rlm_lineage_id=lineage-integ-1, got %v", meta["rlm_lineage_id"])
	}
	if meta["rlm_root_run_id"] != "run-integ-root" {
		t.Errorf("expected rlm_root_run_id=run-integ-root, got %v", meta["rlm_root_run_id"])
	}
	if meta["rlm_current_run_id"] != "run-integ-root" {
		t.Errorf("expected rlm_current_run_id=run-integ-root, got %v", meta["rlm_current_run_id"])
	}
	if meta["rlm_depth"] != 0 {
		t.Errorf("expected rlm_depth=0, got %v", meta["rlm_depth"])
	}
	if meta["rlm_subcalls_used"] != 1 {
		t.Errorf("expected rlm_subcalls_used=1, got %v", meta["rlm_subcalls_used"])
	}

	// Verify rlm_limits sub-object.
	limits, ok := meta["rlm_limits"].(map[string]any)
	if !ok {
		t.Fatal("expected rlm_limits to be map[string]any")
	}
	if limits["max_depth"] != 6 {
		t.Errorf("expected rlm_limits.max_depth=6, got %v", limits["max_depth"])
	}
	if limits["max_subcalls"] != 64 {
		t.Errorf("expected rlm_limits.max_subcalls=64, got %v", limits["max_subcalls"])
	}
	if limits["max_budget_units"] != 128.0 {
		t.Errorf("expected rlm_limits.max_budget_units=128.0, got %v", limits["max_budget_units"])
	}
}

func TestRLMGovernance_IntegrationViaGateway_BypassDenied(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)

	// Subcall without mediation via gateway path.
	req := makeRLMSubcallRequest("run-integ-bypass", "lineage-integ-2", "run-parent", "dec-parent", 1, nil)
	handled, decision, reason, status, _ := gw.evaluateRLMGovernance(req)

	if !handled {
		t.Fatal("expected handled=true")
	}
	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %q", decision)
	}
	if reason != ReasonRLMBypassDenied {
		t.Fatalf("expected ReasonRLMBypassDenied, got %q", reason)
	}
	if status != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", status)
	}
}

func TestRLMGovernance_IntegrationViaGateway_StatefulBudgetTracking(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)

	lineage := "lineage-integ-stateful"
	limits := map[string]any{
		"max_depth":        10,
		"max_subcalls":     3,
		"max_budget_units": 5.0,
	}

	// Root: 1 subcall, 1.0 budget units.
	req0 := makeRLMRequest("run-integ-0", lineage, "rlm", 0, map[string]any{
		"rlm_limits": limits,
	})
	handled0, d0, _, _, meta0 := gw.evaluateRLMGovernance(req0)
	if !handled0 || d0 != DecisionAllow {
		t.Fatal("root should be allowed via gateway")
	}
	if meta0["rlm_subcalls_used"] != 1 {
		t.Errorf("expected subcalls_used=1 after root, got %v", meta0["rlm_subcalls_used"])
	}

	// Subcall: 2 subcalls, 1.0+2.0=3.0 budget units.
	req1 := makeRLMSubcallRequest("run-integ-1", lineage, "run-integ-0", "dec-0", 1, map[string]any{
		"uasgs_mediated":           true,
		"rlm_subcall_budget_units": 2.0,
		"rlm_limits":               limits,
	})
	_, d1, _, _, meta1 := gw.evaluateRLMGovernance(req1)
	if d1 != DecisionAllow {
		t.Fatal("2nd call should be allowed via gateway")
	}
	if meta1["rlm_subcalls_used"] != 2 {
		t.Errorf("expected subcalls_used=2, got %v", meta1["rlm_subcalls_used"])
	}
	if used, ok := meta1["rlm_budget_units_used"].(float64); !ok || used != 3.0 {
		t.Errorf("expected budget_units_used=3.0, got %v", meta1["rlm_budget_units_used"])
	}

	// Subcall: 3 subcalls, 3.0+2.5=5.5 budget units -> exceeds 5.0 budget.
	req2 := makeRLMSubcallRequest("run-integ-2", lineage, "run-integ-0", "dec-0", 1, map[string]any{
		"uasgs_mediated":           true,
		"rlm_subcall_budget_units": 2.5,
		"rlm_limits":               limits,
	})
	_, d2, r2, s2, _ := gw.evaluateRLMGovernance(req2)
	if d2 != DecisionDeny {
		t.Fatalf("3rd call should be denied (budget exceeded), got %q", d2)
	}
	if r2 != ReasonRLMHaltMaxBudget {
		t.Fatalf("expected ReasonRLMHaltMaxBudget, got %q", r2)
	}
	if s2 != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", s2)
	}
}

func TestRLMGovernance_IntegrationViaGateway_NonRLMBypass(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)

	// Standard-mode request: gateway should return handled=false.
	req := makeRLMRequest("run-integ-std", "", "standard", 0, nil)
	handled, _, _, _, _ := gw.evaluateRLMGovernance(req)

	if handled {
		t.Fatal("expected handled=false for standard mode via gateway")
	}
}

func TestRLMGovernance_IntegrationViaGateway_DepthHalt(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)

	// Exceed default max_depth=6 via gateway.
	attrs := map[string]any{
		"uasgs_mediated": true,
	}
	req := makeRLMSubcallRequest("run-integ-deep", "lineage-integ-deep", "run-parent", "dec-parent", 7, attrs)
	handled, decision, reason, status, meta := gw.evaluateRLMGovernance(req)

	if !handled {
		t.Fatal("expected handled=true")
	}
	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %q", decision)
	}
	if reason != ReasonRLMHaltMaxDepth {
		t.Fatalf("expected ReasonRLMHaltMaxDepth, got %q", reason)
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", status)
	}

	// Even on denial, metadata should contain full state.
	if _, ok := meta["rlm_lineage_id"]; !ok {
		t.Error("expected rlm_lineage_id in deny metadata")
	}
	if _, ok := meta["rlm_limits"]; !ok {
		t.Error("expected rlm_limits in deny metadata")
	}
}

func TestRLMGovernance_IntegrationViaGateway_SchemaErrors(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)

	cases := []struct {
		name string
		req  PlaneRequestV2
	}{
		{
			name: "missing_lineage_id",
			req:  makeRLMRequest("run-schema-1", "", "rlm", 0, nil),
		},
		{
			name: "missing_rlm_depth",
			req: func() PlaneRequestV2 {
				envelope := RunEnvelope{
					RunID:         "run-schema-2",
					SessionID:     "sess-rlm-test",
					Tenant:        "test-tenant",
					ActorSPIFFEID: "spiffe://test/actor",
					Plane:         PlaneModel,
					ExecutionMode: "rlm",
					LineageID:     "lineage-schema-2",
				}
				return PlaneRequestV2{
					Envelope: envelope,
					Policy: PolicyInputV2{
						Envelope:   envelope,
						Action:     "model.call",
						Resource:   "model/inference",
						Attributes: map[string]any{},
					},
				}
			}(),
		},
		{
			name: "depth_gt_0_no_parent",
			req: func() PlaneRequestV2 {
				envelope := RunEnvelope{
					RunID:         "run-schema-3",
					SessionID:     "sess-rlm-test",
					Tenant:        "test-tenant",
					ActorSPIFFEID: "spiffe://test/actor",
					Plane:         PlaneModel,
					ExecutionMode: "rlm",
					LineageID:     "lineage-schema-3",
				}
				return PlaneRequestV2{
					Envelope: envelope,
					Policy: PolicyInputV2{
						Envelope: envelope,
						Action:   "model.call",
						Resource: "model/inference",
						Attributes: map[string]any{
							"rlm_depth":      2,
							"uasgs_mediated": true,
						},
					},
				}
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handled, decision, reason, status, _ := gw.evaluateRLMGovernance(tc.req)
			if !handled {
				t.Fatal("expected handled=true for schema error")
			}
			if decision != DecisionDeny {
				t.Fatalf("expected DecisionDeny, got %q", decision)
			}
			if reason != ReasonRLMSchemaInvalid {
				t.Fatalf("expected ReasonRLMSchemaInvalid, got %q", reason)
			}
			if status != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", status)
			}
		})
	}
}

func TestRLMGovernance_IntegrationViaGateway_ConcurrentLineages(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)

	// Simulate two lineages hitting the gateway concurrently. Since this test
	// runs sequentially, it verifies the gateway-internal engine tracks lineages
	// independently through the public evaluateRLMGovernance method.

	limits := map[string]any{
		"max_depth":        10,
		"max_subcalls":     2,
		"max_budget_units": 100.0,
	}

	// Lineage X: 2 calls exhausts subcalls.
	for i := 0; i < 2; i++ {
		var req PlaneRequestV2
		if i == 0 {
			req = makeRLMRequest(fmt.Sprintf("run-x%d", i), "lineage-X", "rlm", 0, map[string]any{
				"rlm_limits": limits,
			})
		} else {
			req = makeRLMSubcallRequest(fmt.Sprintf("run-x%d", i), "lineage-X", "run-x0", "dec-x0", 1, map[string]any{
				"uasgs_mediated": true,
				"rlm_limits":     limits,
			})
		}
		_, d, _, _, _ := gw.evaluateRLMGovernance(req)
		if d != DecisionAllow {
			t.Fatalf("lineage X call %d should be allowed", i)
		}
	}

	// Lineage X: 3rd call should be denied.
	reqX2 := makeRLMSubcallRequest("run-x2", "lineage-X", "run-x0", "dec-x0", 1, map[string]any{
		"uasgs_mediated": true,
		"rlm_limits":     limits,
	})
	_, dX, rX, _, _ := gw.evaluateRLMGovernance(reqX2)
	if dX != DecisionDeny || rX != ReasonRLMHaltMaxSubcalls {
		t.Fatalf("lineage X 3rd call should hit subcall limit, got decision=%q reason=%q", dX, rX)
	}

	// Lineage Y: should still work (independent state).
	reqY0 := makeRLMRequest("run-y0", "lineage-Y", "rlm", 0, map[string]any{
		"rlm_limits": limits,
	})
	_, dY, _, _, _ := gw.evaluateRLMGovernance(reqY0)
	if dY != DecisionAllow {
		t.Fatalf("lineage Y should be allowed (independent), got %q", dY)
	}
}

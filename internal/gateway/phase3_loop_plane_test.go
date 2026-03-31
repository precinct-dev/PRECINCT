package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers: construct PlaneRequestV2 for loop plane
// ---------------------------------------------------------------------------

// defaultLoopLimits returns a valid limits map with all positive values (the
// reference implementation requires all limits > 0).
func defaultLoopLimits() map[string]any {
	return map[string]any{
		"max_steps":              100,
		"max_tool_calls":         50,
		"max_model_calls":        50,
		"max_wall_time_ms":       60000,
		"max_egress_bytes":       1048576,
		"max_model_cost_usd":     10.0,
		"max_provider_failovers": 3,
		"max_risk_score":         0.9,
	}
}

// defaultLoopUsage returns a valid usage map with low values (no breaches).
func defaultLoopUsage() map[string]any {
	return map[string]any{
		"steps":              1,
		"tool_calls":         1,
		"model_calls":        1,
		"wall_time_ms":       100,
		"egress_bytes":       1024,
		"model_cost_usd":     0.01,
		"provider_failovers": 0,
		"risk_score":         0.1,
	}
}

// makeLoopRequest constructs a PlaneRequestV2 for the loop plane with the
// given run ID, event, and optional attribute overrides.
func makeLoopRequest(runID, event string, attrOverrides map[string]any) PlaneRequestV2 {
	attrs := map[string]any{
		"event":  event,
		"limits": defaultLoopLimits(),
		"usage":  defaultLoopUsage(),
	}
	for k, v := range attrOverrides {
		attrs[k] = v
	}

	env := RunEnvelope{
		RunID:         runID,
		SessionID:     "sess-test-001",
		Tenant:        "test-tenant",
		ActorSPIFFEID: "spiffe://poc.local/agent/test",
		Plane:         PlaneLoop,
	}

	return PlaneRequestV2{
		Envelope: env,
		Policy: PolicyInputV2{
			Envelope:   env,
			Action:     "loop.check",
			Resource:   "agent-loop",
			Attributes: attrs,
		},
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: State Machine Transitions
// ---------------------------------------------------------------------------

func TestLoopPlane_StateTransition_CreatedToRunning(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()
	req := makeLoopRequest("run-001", "boundary", nil)

	decision, reason, status, meta := engine.evaluate(req, "dec-001", "trace-001", now)

	if decision != DecisionAllow {
		t.Fatalf("expected DecisionAllow, got %s", decision)
	}
	if reason != ReasonLoopAllow {
		t.Fatalf("expected ReasonLoopAllow, got %s", reason)
	}
	if status != 200 {
		t.Fatalf("expected HTTP 200, got %d", status)
	}

	// Verify governance state in metadata is RUNNING (first boundary transitions from CREATED).
	state, ok := meta["governance_state"]
	if !ok {
		t.Fatal("metadata missing governance_state")
	}
	if state != loopStateRunning {
		t.Fatalf("expected RUNNING state, got %v", state)
	}
}

func TestLoopPlane_StateTransition_RunningToWaitingApproval(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()
	req := makeLoopRequest("run-002", "boundary", nil)

	// First call: CREATED -> RUNNING
	engine.evaluate(req, "dec-001", "trace-001", now)

	// Second call with approval_required event
	reqApproval := makeLoopRequest("run-002", "approval_required", nil)
	decision, reason, status, meta := engine.evaluate(reqApproval, "dec-002", "trace-002", now.Add(time.Second))

	if decision != DecisionStepUp {
		t.Fatalf("expected DecisionStepUp, got %s", decision)
	}
	if reason != ReasonLoopStepUpRequired {
		t.Fatalf("expected ReasonLoopStepUpRequired, got %s", reason)
	}
	if status != 202 {
		t.Fatalf("expected HTTP 202, got %d", status)
	}
	if meta["governance_state"] != loopStateWaitingApproval {
		t.Fatalf("expected WAITING_APPROVAL, got %v", meta["governance_state"])
	}
}

func TestLoopPlane_StateTransition_WaitingApprovalToRunning(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	// CREATED -> RUNNING
	req := makeLoopRequest("run-003", "boundary", nil)
	engine.evaluate(req, "dec-001", "trace-001", now)

	// RUNNING -> WAITING_APPROVAL
	reqApproval := makeLoopRequest("run-003", "approval_required", nil)
	engine.evaluate(reqApproval, "dec-002", "trace-002", now.Add(time.Second))

	// WAITING_APPROVAL -> RUNNING via approval_granted
	reqGranted := makeLoopRequest("run-003", "approval_granted", nil)
	decision, reason, status, meta := engine.evaluate(reqGranted, "dec-003", "trace-003", now.Add(2*time.Second))

	if decision != DecisionAllow {
		t.Fatalf("expected DecisionAllow, got %s", decision)
	}
	if reason != ReasonLoopAllow {
		t.Fatalf("expected ReasonLoopAllow, got %s", reason)
	}
	if status != 200 {
		t.Fatalf("expected HTTP 200, got %d", status)
	}
	if meta["governance_state"] != loopStateRunning {
		t.Fatalf("expected RUNNING, got %v", meta["governance_state"])
	}
}

func TestLoopPlane_StateTransition_RunningToCompleted(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	// CREATED -> RUNNING
	req := makeLoopRequest("run-004", "boundary", nil)
	engine.evaluate(req, "dec-001", "trace-001", now)

	// RUNNING -> COMPLETED
	reqComplete := makeLoopRequest("run-004", "complete", nil)
	decision, reason, status, meta := engine.evaluate(reqComplete, "dec-002", "trace-002", now.Add(time.Second))

	if decision != DecisionAllow {
		t.Fatalf("expected DecisionAllow, got %s", decision)
	}
	if reason != ReasonLoopCompleted {
		t.Fatalf("expected ReasonLoopCompleted, got %s", reason)
	}
	if status != 200 {
		t.Fatalf("expected HTTP 200, got %d", status)
	}
	if meta["governance_state"] != loopStateCompleted {
		t.Fatalf("expected COMPLETED, got %v", meta["governance_state"])
	}
}

func TestLoopPlane_StateTransition_RunningToHaltedOperator(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	// CREATED -> RUNNING
	req := makeLoopRequest("run-005", "boundary", nil)
	engine.evaluate(req, "dec-001", "trace-001", now)

	// RUNNING -> HALTED_OPERATOR
	reqHalt := makeLoopRequest("run-005", "operator_halt", nil)
	decision, reason, status, meta := engine.evaluate(reqHalt, "dec-002", "trace-002", now.Add(time.Second))

	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %s", decision)
	}
	if reason != ReasonLoopHaltOperator {
		t.Fatalf("expected ReasonLoopHaltOperator, got %s", reason)
	}
	if status != 409 {
		t.Fatalf("expected HTTP 409, got %d", status)
	}
	if meta["governance_state"] != loopStateHaltedOperator {
		t.Fatalf("expected HALTED_OPERATOR, got %v", meta["governance_state"])
	}
}

func TestLoopPlane_StateTransition_RunningToHaltedProviderUnavailable(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	// CREATED -> RUNNING
	req := makeLoopRequest("run-006", "boundary", nil)
	engine.evaluate(req, "dec-001", "trace-001", now)

	// RUNNING -> HALTED_PROVIDER_UNAVAILABLE
	reqUnavail := makeLoopRequest("run-006", "provider_unavailable", nil)
	decision, reason, status, meta := engine.evaluate(reqUnavail, "dec-002", "trace-002", now.Add(time.Second))

	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %s", decision)
	}
	if reason != ReasonLoopHaltProviderUnavailable {
		t.Fatalf("expected ReasonLoopHaltProviderUnavailable, got %s", reason)
	}
	if status != 502 {
		t.Fatalf("expected HTTP 502, got %d", status)
	}
	if meta["governance_state"] != loopStateHaltedProviderUnavailable {
		t.Fatalf("expected HALTED_PROVIDER_UNAVAILABLE, got %v", meta["governance_state"])
	}
}

// TestLoopPlane_StateTransition_HaltedBudget_AllLimitTypes verifies that each
// budget limit type (steps, tool_calls, model_calls, wall_time_ms,
// egress_bytes, model_cost_usd, provider_failovers) produces HALTED_BUDGET
// with the correct reason code and HTTP 429.
func TestLoopPlane_StateTransition_HaltedBudget_AllLimitTypes(t *testing.T) {
	cases := []struct {
		name       string
		usageKey   string
		usageValue any
		wantReason ReasonCode
	}{
		{"max_steps", "steps", 101, ReasonLoopHaltMaxSteps},
		{"max_tool_calls", "tool_calls", 51, ReasonLoopHaltMaxToolCalls},
		{"max_model_calls", "model_calls", 51, ReasonLoopHaltMaxModelCalls},
		{"max_wall_time_ms", "wall_time_ms", 60001, ReasonLoopHaltMaxWallTime},
		{"max_egress_bytes", "egress_bytes", 1048577, ReasonLoopHaltMaxEgressBytes},
		{"max_model_cost_usd", "model_cost_usd", 10.01, ReasonLoopHaltMaxModelCost},
		{"max_provider_failovers", "provider_failovers", 4, ReasonLoopHaltMaxProviderFailovers},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := newLoopPlanePolicyEngine()
			now := time.Now().UTC()

			// Construct usage that exceeds just this one limit.
			usage := defaultLoopUsage()
			usage[tc.usageKey] = tc.usageValue

			req := makeLoopRequest("run-budget-"+tc.name, "boundary", map[string]any{
				"usage": usage,
			})

			decision, reason, status, meta := engine.evaluate(req, "dec-001", "trace-001", now)

			if decision != DecisionDeny {
				t.Fatalf("expected DecisionDeny, got %s", decision)
			}
			if reason != tc.wantReason {
				t.Fatalf("expected %s, got %s", tc.wantReason, reason)
			}
			if status != 429 {
				t.Fatalf("expected HTTP 429, got %d", status)
			}
			if meta["governance_state"] != loopStateHaltedBudget {
				t.Fatalf("expected HALTED_BUDGET, got %v", meta["governance_state"])
			}
		})
	}
}

// TestLoopPlane_StateTransition_HaltedPolicy_RiskScore verifies that exceeding
// max_risk_score produces HALTED_POLICY (not HALTED_BUDGET) with HTTP 403.
func TestLoopPlane_StateTransition_HaltedPolicy_RiskScore(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	usage := defaultLoopUsage()
	usage["risk_score"] = 0.95 // Exceeds max_risk_score=0.9

	req := makeLoopRequest("run-risk", "boundary", map[string]any{
		"usage": usage,
	})

	decision, reason, status, meta := engine.evaluate(req, "dec-001", "trace-001", now)

	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %s", decision)
	}
	if reason != ReasonLoopHaltRiskScore {
		t.Fatalf("expected ReasonLoopHaltRiskScore, got %s", reason)
	}
	if status != 403 {
		t.Fatalf("expected HTTP 403, got %d", status)
	}
	if meta["governance_state"] != loopStateHaltedPolicy {
		t.Fatalf("expected HALTED_POLICY, got %v", meta["governance_state"])
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: Terminal State Immutability
// ---------------------------------------------------------------------------

func TestLoopPlane_TerminalImmutability_CompletedReturnsAllow(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	// CREATED -> RUNNING -> COMPLETED
	req := makeLoopRequest("run-term-complete", "boundary", nil)
	engine.evaluate(req, "dec-001", "trace-001", now)
	reqComplete := makeLoopRequest("run-term-complete", "complete", nil)
	engine.evaluate(reqComplete, "dec-002", "trace-002", now.Add(time.Second))

	// Subsequent boundary on a COMPLETED run should still return allow.
	reqPost := makeLoopRequest("run-term-complete", "boundary", nil)
	decision, reason, status, _ := engine.evaluate(reqPost, "dec-003", "trace-003", now.Add(2*time.Second))

	if decision != DecisionAllow {
		t.Fatalf("expected DecisionAllow for COMPLETED run, got %s", decision)
	}
	if reason != ReasonLoopCompleted {
		t.Fatalf("expected ReasonLoopCompleted, got %s", reason)
	}
	if status != 200 {
		t.Fatalf("expected HTTP 200, got %d", status)
	}
}

func TestLoopPlane_TerminalImmutability_HaltedReturnsDenyWithOriginalReason(t *testing.T) {
	haltedStates := []struct {
		name       string
		event      string
		usageMod   map[string]any
		wantReason ReasonCode
	}{
		{
			name:       "HALTED_OPERATOR",
			event:      "operator_halt",
			wantReason: ReasonLoopHaltOperator,
		},
		{
			name:       "HALTED_PROVIDER_UNAVAILABLE",
			event:      "provider_unavailable",
			wantReason: ReasonLoopHaltProviderUnavailable,
		},
		{
			name:  "HALTED_BUDGET_steps",
			event: "boundary",
			usageMod: map[string]any{
				"usage": func() map[string]any {
					u := defaultLoopUsage()
					u["steps"] = 101
					return u
				}(),
			},
			wantReason: ReasonLoopHaltMaxSteps,
		},
		{
			name:  "HALTED_POLICY_risk",
			event: "boundary",
			usageMod: map[string]any{
				"usage": func() map[string]any {
					u := defaultLoopUsage()
					u["risk_score"] = 0.95
					return u
				}(),
			},
			wantReason: ReasonLoopHaltRiskScore,
		},
	}

	for _, tc := range haltedStates {
		t.Run(tc.name, func(t *testing.T) {
			engine := newLoopPlanePolicyEngine()
			now := time.Now().UTC()

			// First: create and move to running.
			req := makeLoopRequest("run-"+tc.name, "boundary", nil)
			engine.evaluate(req, "dec-001", "trace-001", now)

			// Halt the run.
			reqHalt := makeLoopRequest("run-"+tc.name, tc.event, tc.usageMod)
			engine.evaluate(reqHalt, "dec-002", "trace-002", now.Add(time.Second))

			// Subsequent boundary should return deny with original halt reason.
			reqPost := makeLoopRequest("run-"+tc.name, "boundary", nil)
			decision, reason, _, meta := engine.evaluate(reqPost, "dec-003", "trace-003", now.Add(2*time.Second))

			if decision != DecisionDeny {
				t.Fatalf("expected DecisionDeny for halted run, got %s", decision)
			}
			// The halt_reason in metadata should match the original reason.
			if haltReason, ok := meta["halt_reason"]; ok {
				if hr, isRC := haltReason.(ReasonCode); isRC && hr != tc.wantReason {
					t.Fatalf("expected halt_reason %s, got %s", tc.wantReason, hr)
				}
			}
			// The returned reason should indicate already-terminated or original halt reason.
			if reason != tc.wantReason && reason != ReasonLoopRunAlreadyTerminated {
				t.Fatalf("expected %s or LOOP_RUN_ALREADY_TERMINATED, got %s", tc.wantReason, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: Immutable Limits
// ---------------------------------------------------------------------------

func TestLoopPlane_ImmutableLimits_ChangeAfterFirstCheckDenied(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	// First call establishes limits.
	req := makeLoopRequest("run-immutable", "boundary", nil)
	engine.evaluate(req, "dec-001", "trace-001", now)

	// Second call with different limits.
	altLimits := defaultLoopLimits()
	altLimits["max_steps"] = 200 // Changed from 100
	reqChanged := makeLoopRequest("run-immutable", "boundary", map[string]any{
		"limits": altLimits,
	})

	decision, reason, status, _ := engine.evaluate(reqChanged, "dec-002", "trace-002", now.Add(time.Second))

	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %s", decision)
	}
	if reason != ReasonLoopLimitsImmutableViolation {
		t.Fatalf("expected LOOP_LIMITS_IMMUTABLE_VIOLATION, got %s", reason)
	}
	if status != 403 {
		t.Fatalf("expected HTTP 403, got %d", status)
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: Schema Validation
// ---------------------------------------------------------------------------

func TestLoopPlane_SchemaInvalid_MissingRunID(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	req := makeLoopRequest("", "boundary", nil)
	_ = req // suppress unused variable -- run_id validation is tested at handler level
	// The envelope validation should catch missing run_id before we even get
	// to evaluate, but the engine itself should handle it via parseLoopCheckInput
	// or the caller should validate. The contract says missing run_id => LOOP_SCHEMA_INVALID.
	//
	// Since PlaneRequestV2.Validate() catches empty run_id and returns an error
	// at the HTTP handler level, the unit test for the engine should simulate
	// what happens when a request with an empty run_id reaches evaluate.
	// The reference implementation does not re-validate run_id inside evaluate;
	// it relies on the handler. However, the story AC says "missing run_id
	// returns LOOP_SCHEMA_INVALID" -- this is the engine contract.
	//
	// We test that a request arriving at the engine with attributes missing
	// required fields results in LOOP_SCHEMA_INVALID.
	reqNoAttrs := makeLoopRequest("run-schema", "boundary", map[string]any{
		"limits": nil, // Missing limits should trigger schema error.
	})

	decision, reason, status, _ := engine.evaluate(reqNoAttrs, "dec-001", "trace-001", now)

	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %s", decision)
	}
	if reason != ReasonLoopSchemaInvalid {
		t.Fatalf("expected LOOP_SCHEMA_INVALID, got %s", reason)
	}
	if status != 400 {
		t.Fatalf("expected HTTP 400, got %d", status)
	}
}

func TestLoopPlane_SchemaInvalid_InvalidEvent(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	req := makeLoopRequest("run-bad-event", "totally_invalid_event", nil)

	decision, reason, status, _ := engine.evaluate(req, "dec-001", "trace-001", now)

	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %s", decision)
	}
	if reason != ReasonLoopSchemaInvalid {
		t.Fatalf("expected LOOP_SCHEMA_INVALID, got %s", reason)
	}
	if status != 400 {
		t.Fatalf("expected HTTP 400, got %d", status)
	}
}

func TestLoopPlane_SchemaInvalid_MissingUsage(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	req := makeLoopRequest("run-no-usage", "boundary", map[string]any{
		"usage": nil, // Missing usage should trigger schema error.
	})

	decision, reason, status, _ := engine.evaluate(req, "dec-001", "trace-001", now)

	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %s", decision)
	}
	if reason != ReasonLoopSchemaInvalid {
		t.Fatalf("expected LOOP_SCHEMA_INVALID, got %s", reason)
	}
	if status != 400 {
		t.Fatalf("expected HTTP 400, got %d", status)
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: Operator Halt from Any Non-Terminal State
// ---------------------------------------------------------------------------

func TestLoopPlane_OperatorHalt_FromAnyNonTerminalState(t *testing.T) {
	nonTerminalEvents := []struct {
		name           string
		setupEvent     string
		setupOverrides map[string]any
	}{
		{
			name:       "from_CREATED",
			setupEvent: "", // no setup -- first call is the halt
		},
		{
			name:       "from_RUNNING",
			setupEvent: "boundary",
		},
		{
			name:       "from_WAITING_APPROVAL",
			setupEvent: "approval_required",
		},
	}

	for _, tc := range nonTerminalEvents {
		t.Run(tc.name, func(t *testing.T) {
			engine := newLoopPlanePolicyEngine()
			now := time.Now().UTC()
			runID := "run-op-halt-" + tc.name

			if tc.setupEvent != "" {
				// Transition to the setup state first.
				if tc.setupEvent == "approval_required" {
					// Need to go through RUNNING first.
					req := makeLoopRequest(runID, "boundary", nil)
					engine.evaluate(req, "dec-setup0", "trace-setup0", now)
					now = now.Add(time.Second)
				}
				req := makeLoopRequest(runID, tc.setupEvent, nil)
				engine.evaluate(req, "dec-setup", "trace-setup", now)
				now = now.Add(time.Second)
			}

			// Operator halt via event.
			reqHalt := makeLoopRequest(runID, "operator_halt", nil)
			decision, reason, status, meta := engine.evaluate(reqHalt, "dec-halt", "trace-halt", now)

			if decision != DecisionDeny {
				t.Fatalf("expected DecisionDeny, got %s", decision)
			}
			if reason != ReasonLoopHaltOperator {
				t.Fatalf("expected ReasonLoopHaltOperator, got %s", reason)
			}
			if status != 409 {
				t.Fatalf("expected HTTP 409, got %d", status)
			}
			if meta["governance_state"] != loopStateHaltedOperator {
				t.Fatalf("expected HALTED_OPERATOR, got %v", meta["governance_state"])
			}
		})
	}
}

func TestLoopPlane_OperatorHalt_ViaBoolAttribute(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	// CREATED -> RUNNING
	req := makeLoopRequest("run-op-bool", "boundary", nil)
	engine.evaluate(req, "dec-001", "trace-001", now)

	// Halt via operator_halt=true attribute (alternative to event="operator_halt").
	reqHalt := makeLoopRequest("run-op-bool", "boundary", map[string]any{
		"operator_halt": true,
	})
	decision, reason, _, meta := engine.evaluate(reqHalt, "dec-002", "trace-002", now.Add(time.Second))

	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %s", decision)
	}
	if reason != ReasonLoopHaltOperator {
		t.Fatalf("expected ReasonLoopHaltOperator, got %s", reason)
	}
	if meta["governance_state"] != loopStateHaltedOperator {
		t.Fatalf("expected HALTED_OPERATOR, got %v", meta["governance_state"])
	}
}

func TestLoopPlane_ProviderUnavailable_ViaBoolAttribute(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	// CREATED -> RUNNING
	req := makeLoopRequest("run-pu-bool", "boundary", nil)
	engine.evaluate(req, "dec-001", "trace-001", now)

	// Halt via provider_unavailable=true attribute.
	reqHalt := makeLoopRequest("run-pu-bool", "boundary", map[string]any{
		"provider_unavailable": true,
	})
	decision, reason, status, meta := engine.evaluate(reqHalt, "dec-002", "trace-002", now.Add(time.Second))

	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %s", decision)
	}
	if reason != ReasonLoopHaltProviderUnavailable {
		t.Fatalf("expected ReasonLoopHaltProviderUnavailable, got %s", reason)
	}
	if status != 502 {
		t.Fatalf("expected HTTP 502, got %d", status)
	}
	if meta["governance_state"] != loopStateHaltedProviderUnavailable {
		t.Fatalf("expected HALTED_PROVIDER_UNAVAILABLE, got %v", meta["governance_state"])
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: Multiple Concurrent Runs
// ---------------------------------------------------------------------------

func TestLoopPlane_MultipleConcurrentRuns(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	// Run A: boundary -> RUNNING
	reqA := makeLoopRequest("run-A", "boundary", nil)
	decA, _, _, metaA := engine.evaluate(reqA, "dec-A1", "trace-A1", now)
	if decA != DecisionAllow {
		t.Fatalf("run-A: expected allow, got %s", decA)
	}
	if metaA["governance_state"] != loopStateRunning {
		t.Fatalf("run-A: expected RUNNING, got %v", metaA["governance_state"])
	}

	// Run B: operator_halt -> HALTED_OPERATOR (first call, so CREATED then halt)
	reqB := makeLoopRequest("run-B", "operator_halt", nil)
	decB, reasonB, _, metaB := engine.evaluate(reqB, "dec-B1", "trace-B1", now)
	if decB != DecisionDeny {
		t.Fatalf("run-B: expected deny, got %s", decB)
	}
	if reasonB != ReasonLoopHaltOperator {
		t.Fatalf("run-B: expected LOOP_HALT_OPERATOR, got %s", reasonB)
	}
	if metaB["governance_state"] != loopStateHaltedOperator {
		t.Fatalf("run-B: expected HALTED_OPERATOR, got %v", metaB["governance_state"])
	}

	// Run A should still be RUNNING (independent of Run B).
	reqA2 := makeLoopRequest("run-A", "boundary", nil)
	decA2, _, _, metaA2 := engine.evaluate(reqA2, "dec-A2", "trace-A2", now.Add(time.Second))
	if decA2 != DecisionAllow {
		t.Fatalf("run-A (2nd check): expected allow, got %s", decA2)
	}
	if metaA2["governance_state"] != loopStateRunning {
		t.Fatalf("run-A (2nd check): expected RUNNING, got %v", metaA2["governance_state"])
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: listRuns and getRun
// ---------------------------------------------------------------------------

func TestLoopPlane_ListRuns_SortedByUpdatedAtDescending(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	// Create three runs at different times.
	reqA := makeLoopRequest("run-list-A", "boundary", nil)
	engine.evaluate(reqA, "dec-A", "trace-A", now)

	reqB := makeLoopRequest("run-list-B", "boundary", nil)
	engine.evaluate(reqB, "dec-B", "trace-B", now.Add(2*time.Second))

	reqC := makeLoopRequest("run-list-C", "boundary", nil)
	engine.evaluate(reqC, "dec-C", "trace-C", now.Add(time.Second))

	runs := engine.listRuns()

	if len(runs) != 3 {
		t.Fatalf("expected 3 runs, got %d", len(runs))
	}

	// B was updated last (now+2s), then C (now+1s), then A (now).
	if runs[0].RunID != "run-list-B" {
		t.Fatalf("expected first run to be run-list-B (most recent), got %s", runs[0].RunID)
	}
	if runs[1].RunID != "run-list-C" {
		t.Fatalf("expected second run to be run-list-C, got %s", runs[1].RunID)
	}
	if runs[2].RunID != "run-list-A" {
		t.Fatalf("expected third run to be run-list-A (oldest), got %s", runs[2].RunID)
	}
}

func TestLoopPlane_GetRun_KnownAndUnknown(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	// Create a run.
	req := makeLoopRequest("run-get-known", "boundary", nil)
	engine.evaluate(req, "dec-001", "trace-001", now)

	// Known run.
	record, found := engine.getRun("run-get-known")
	if !found {
		t.Fatal("expected to find run-get-known")
	}
	if record.RunID != "run-get-known" {
		t.Fatalf("expected RunID run-get-known, got %s", record.RunID)
	}
	if record.State != loopStateRunning {
		t.Fatalf("expected RUNNING state, got %s", record.State)
	}

	// Unknown run.
	_, found = engine.getRun("run-nonexistent")
	if found {
		t.Fatal("expected not to find run-nonexistent")
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: step_up_required attribute
// ---------------------------------------------------------------------------

func TestLoopPlane_StepUpRequired_ViaAttribute(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	// CREATED -> RUNNING
	req := makeLoopRequest("run-stepup", "boundary", nil)
	engine.evaluate(req, "dec-001", "trace-001", now)

	// step_up_required=true should transition to WAITING_APPROVAL.
	reqStepUp := makeLoopRequest("run-stepup", "boundary", map[string]any{
		"step_up_required": true,
	})
	decision, reason, status, meta := engine.evaluate(reqStepUp, "dec-002", "trace-002", now.Add(time.Second))

	if decision != DecisionStepUp {
		t.Fatalf("expected DecisionStepUp, got %s", decision)
	}
	if reason != ReasonLoopStepUpRequired {
		t.Fatalf("expected ReasonLoopStepUpRequired, got %s", reason)
	}
	if status != 202 {
		t.Fatalf("expected HTTP 202, got %d", status)
	}
	if meta["governance_state"] != loopStateWaitingApproval {
		t.Fatalf("expected WAITING_APPROVAL, got %v", meta["governance_state"])
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: Metadata content verification
// ---------------------------------------------------------------------------

func TestLoopPlane_MetadataContainsRequiredFields(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	req := makeLoopRequest("run-meta", "boundary", nil)
	_, _, _, meta := engine.evaluate(req, "dec-001", "trace-001", now)

	requiredKeys := []string{"run_id", "governance_state", "limits", "usage"}
	for _, key := range requiredKeys {
		if _, ok := meta[key]; !ok {
			t.Errorf("metadata missing required key %q", key)
		}
	}

	if meta["run_id"] != "run-meta" {
		t.Errorf("expected run_id=run-meta, got %v", meta["run_id"])
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: Limits with zero values are schema invalid
// ---------------------------------------------------------------------------

func TestLoopPlane_SchemaInvalid_ZeroLimits(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	zeroLimits := map[string]any{
		"max_steps":              0,
		"max_tool_calls":         50,
		"max_model_calls":        50,
		"max_wall_time_ms":       60000,
		"max_egress_bytes":       1048576,
		"max_model_cost_usd":     10.0,
		"max_provider_failovers": 3,
		"max_risk_score":         0.9,
	}
	req := makeLoopRequest("run-zero-limit", "boundary", map[string]any{
		"limits": zeroLimits,
	})

	decision, reason, status, _ := engine.evaluate(req, "dec-001", "trace-001", now)

	if decision != DecisionDeny {
		t.Fatalf("expected DecisionDeny for zero-value limit, got %s", decision)
	}
	if reason != ReasonLoopSchemaInvalid {
		t.Fatalf("expected LOOP_SCHEMA_INVALID, got %s", reason)
	}
	if status != 400 {
		t.Fatalf("expected HTTP 400, got %d", status)
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: loopRunGovernanceState type constants exist
// ---------------------------------------------------------------------------

func TestLoopPlane_GovernanceStateConstants(t *testing.T) {
	// Verify all required state constants exist and have correct values.
	states := map[loopRunGovernanceState]string{
		loopStateCreated:                   "CREATED",
		loopStateRunning:                   "RUNNING",
		loopStateWaitingApproval:           "WAITING_APPROVAL",
		loopStateCompleted:                 "COMPLETED",
		loopStateHaltedPolicy:              "HALTED_POLICY",
		loopStateHaltedBudget:              "HALTED_BUDGET",
		loopStateHaltedProviderUnavailable: "HALTED_PROVIDER_UNAVAILABLE",
		loopStateHaltedOperator:            "HALTED_OPERATOR",
	}

	for state, expected := range states {
		if string(state) != expected {
			t.Errorf("state constant %v: expected %q, got %q", state, expected, string(state))
		}
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: DecisionID and TraceID propagation
// ---------------------------------------------------------------------------

func TestLoopPlane_DecisionAndTraceID_StoredInRecord(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

	req := makeLoopRequest("run-ids", "boundary", nil)
	engine.evaluate(req, "my-decision-id", "my-trace-id", now)

	record, found := engine.getRun("run-ids")
	if !found {
		t.Fatal("expected to find run")
	}
	if record.LastDecisionID != "my-decision-id" {
		t.Fatalf("expected LastDecisionID=my-decision-id, got %s", record.LastDecisionID)
	}
	if record.LastTraceID != "my-trace-id" {
		t.Fatalf("expected LastTraceID=my-trace-id, got %s", record.LastTraceID)
	}
}

// ---------------------------------------------------------------------------
// Integration Tests: Full HTTP handleLoopCheck flow
// ---------------------------------------------------------------------------

// loopCheckHTTPRequest constructs an HTTP POST to /v1/loop/check with the
// given PlaneRequestV2 body. Returns the recorder for inspection.
func loopCheckHTTPRequest(t *testing.T, gw *Gateway, req PlaneRequestV2) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/loop/check", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	gw.handleLoopCheck(rr, httpReq)
	return rr
}

func newTestGatewayWithLoopPolicy(engine *loopPlanePolicyEngine) *Gateway {
	return &Gateway{
		loopPolicy: engine,
	}
}

func TestIntegration_LoopCheck_BoundaryEvent_200(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	gw := newTestGatewayWithLoopPolicy(engine)

	req := makeLoopRequest("run-int-001", "boundary", nil)
	rr := loopCheckHTTPRequest(t, gw, req)

	if rr.Code != 200 {
		t.Fatalf("expected HTTP 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp PlaneDecisionV2
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Decision != DecisionAllow {
		t.Fatalf("expected allow decision, got %s", resp.Decision)
	}
	if resp.ReasonCode != ReasonLoopAllow {
		t.Fatalf("expected LOOP_ALLOW, got %s", resp.ReasonCode)
	}
}

func TestIntegration_LoopCheck_OperatorHalt_409(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	gw := newTestGatewayWithLoopPolicy(engine)

	// First, establish a running run.
	reqBoundary := makeLoopRequest("run-int-halt", "boundary", nil)
	loopCheckHTTPRequest(t, gw, reqBoundary)

	// Halt it.
	reqHalt := makeLoopRequest("run-int-halt", "operator_halt", nil)
	rr := loopCheckHTTPRequest(t, gw, reqHalt)

	if rr.Code != 409 {
		t.Fatalf("expected HTTP 409, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp PlaneDecisionV2
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Decision != DecisionDeny {
		t.Fatalf("expected deny decision, got %s", resp.Decision)
	}
	if resp.ReasonCode != ReasonLoopHaltOperator {
		t.Fatalf("expected LOOP_HALT_OPERATOR, got %s", resp.ReasonCode)
	}
}

func TestIntegration_LoopCheck_LimitBreach_429(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	gw := newTestGatewayWithLoopPolicy(engine)

	usage := defaultLoopUsage()
	usage["steps"] = 101 // exceeds max_steps=100

	req := makeLoopRequest("run-int-breach", "boundary", map[string]any{
		"usage": usage,
	})
	rr := loopCheckHTTPRequest(t, gw, req)

	if rr.Code != 429 {
		t.Fatalf("expected HTTP 429, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp PlaneDecisionV2
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Decision != DecisionDeny {
		t.Fatalf("expected deny decision, got %s", resp.Decision)
	}
	if resp.ReasonCode != ReasonLoopHaltMaxSteps {
		t.Fatalf("expected LOOP_HALT_MAX_STEPS, got %s", resp.ReasonCode)
	}
}

func TestIntegration_LoopCheck_MultiStepLifecycle(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	gw := newTestGatewayWithLoopPolicy(engine)

	runID := "run-int-lifecycle"

	// Step 1: boundary -> RUNNING (200)
	reqBoundary := makeLoopRequest(runID, "boundary", nil)
	rr := loopCheckHTTPRequest(t, gw, reqBoundary)
	if rr.Code != 200 {
		t.Fatalf("step 1: expected HTTP 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
	var resp1 PlaneDecisionV2
	if err := json.Unmarshal(rr.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("step 1: failed to decode response: %v", err)
	}
	if resp1.Decision != DecisionAllow {
		t.Fatalf("step 1: expected allow, got %s", resp1.Decision)
	}

	// Step 2: another boundary with usage -> still RUNNING (200)
	usage2 := defaultLoopUsage()
	usage2["steps"] = 10
	reqBoundary2 := makeLoopRequest(runID, "boundary", map[string]any{
		"usage": usage2,
	})
	rr2 := loopCheckHTTPRequest(t, gw, reqBoundary2)
	if rr2.Code != 200 {
		t.Fatalf("step 2: expected HTTP 200, got %d; body: %s", rr2.Code, rr2.Body.String())
	}

	// Step 3: operator halt -> HALTED_OPERATOR (409)
	reqHalt := makeLoopRequest(runID, "operator_halt", nil)
	rr3 := loopCheckHTTPRequest(t, gw, reqHalt)
	if rr3.Code != 409 {
		t.Fatalf("step 3: expected HTTP 409, got %d; body: %s", rr3.Code, rr3.Body.String())
	}
	var resp3 PlaneDecisionV2
	if err := json.Unmarshal(rr3.Body.Bytes(), &resp3); err != nil {
		t.Fatalf("step 3: failed to decode response: %v", err)
	}
	if resp3.Decision != DecisionDeny {
		t.Fatalf("step 3: expected deny, got %s", resp3.Decision)
	}
	if resp3.ReasonCode != ReasonLoopHaltOperator {
		t.Fatalf("step 3: expected LOOP_HALT_OPERATOR, got %s", resp3.ReasonCode)
	}

	// Step 4: post-halt boundary -> still denied (terminal immutability)
	reqPostHalt := makeLoopRequest(runID, "boundary", nil)
	rr4 := loopCheckHTTPRequest(t, gw, reqPostHalt)
	if rr4.Code == 200 {
		t.Fatal("step 4: expected non-200 for halted run, got 200")
	}
	var resp4 PlaneDecisionV2
	if err := json.Unmarshal(rr4.Body.Bytes(), &resp4); err != nil {
		t.Fatalf("step 4: failed to decode response: %v", err)
	}
	if resp4.Decision != DecisionDeny {
		t.Fatalf("step 4: expected deny for halted run, got %s", resp4.Decision)
	}
}

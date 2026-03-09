package gateway

import (
	"testing"
	"time"
)

func baseLoopAttributes() map[string]any {
	return map[string]any{
		"event": "boundary",
		"limits": map[string]any{
			"max_steps":              10,
			"max_tool_calls":         10,
			"max_model_calls":        10,
			"max_wall_time_ms":       60000,
			"max_egress_bytes":       100000,
			"max_model_cost_usd":     5.0,
			"max_provider_failovers": 3,
			"max_risk_score":         0.8,
		},
		"usage": map[string]any{
			"steps":              1,
			"tool_calls":         1,
			"model_calls":        1,
			"wall_time_ms":       1000,
			"egress_bytes":       256,
			"model_cost_usd":     0.1,
			"provider_failovers": 0,
			"risk_score":         0.1,
		},
	}
}

func baseLoopRequest() PlaneRequestV2 {
	envelope := RunEnvelope{
		RunID:         "run-loop-1",
		SessionID:     "sess-loop-1",
		Tenant:        "tenant-loop",
		ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Plane:         PlaneLoop,
	}
	return PlaneRequestV2{
		Envelope: envelope,
		Policy: PolicyInputV2{
			Envelope:   envelope,
			Action:     "loop.check",
			Resource:   "loop/external-governor",
			Attributes: baseLoopAttributes(),
		},
	}
}

func TestLoopPlanePolicyAllowAndImmutableLimits(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()
	req := baseLoopRequest()

	decision, reason, status, _ := engine.evaluate(req, "dec-1", "trace-1", now)
	if decision != DecisionAllow || reason != ReasonLoopAllow || status != 200 {
		t.Fatalf("expected allow/LOOP_ALLOW/200, got %s/%s/%d", decision, reason, status)
	}

	changed := baseLoopRequest()
	changed.Policy.Attributes["limits"].(map[string]any)["max_steps"] = 20
	decision, reason, status, metadata := engine.evaluate(changed, "dec-2", "trace-2", now.Add(time.Second))
	if decision != DecisionDeny || reason != ReasonLoopLimitsImmutableViolation || status != httpStatusForbidden {
		t.Fatalf("expected immutable limits deny, got %s/%s/%d", decision, reason, status)
	}
	if metadata["run_id"] != "run-loop-1" {
		t.Fatalf("expected run_id metadata, got %+v", metadata)
	}
}

func TestLoopPlanePolicyHaltReasonDeterminism(t *testing.T) {
	cases := []struct {
		name       string
		override   func(map[string]any)
		wantReason ReasonCode
		wantStatus int
	}{
		{
			name: "max_steps",
			override: func(attrs map[string]any) {
				attrs["usage"].(map[string]any)["steps"] = 11
			},
			wantReason: ReasonLoopHaltMaxSteps,
			wantStatus: httpStatusTooManyRequests,
		},
		{
			name: "max_tool_calls",
			override: func(attrs map[string]any) {
				attrs["usage"].(map[string]any)["tool_calls"] = 11
			},
			wantReason: ReasonLoopHaltMaxToolCalls,
			wantStatus: httpStatusTooManyRequests,
		},
		{
			name: "max_model_calls",
			override: func(attrs map[string]any) {
				attrs["usage"].(map[string]any)["model_calls"] = 11
			},
			wantReason: ReasonLoopHaltMaxModelCalls,
			wantStatus: httpStatusTooManyRequests,
		},
		{
			name: "max_wall_time",
			override: func(attrs map[string]any) {
				attrs["usage"].(map[string]any)["wall_time_ms"] = 60001
			},
			wantReason: ReasonLoopHaltMaxWallTime,
			wantStatus: httpStatusTooManyRequests,
		},
		{
			name: "max_egress_bytes",
			override: func(attrs map[string]any) {
				attrs["usage"].(map[string]any)["egress_bytes"] = 100001
			},
			wantReason: ReasonLoopHaltMaxEgressBytes,
			wantStatus: httpStatusTooManyRequests,
		},
		{
			name: "max_model_cost",
			override: func(attrs map[string]any) {
				attrs["usage"].(map[string]any)["model_cost_usd"] = 5.1
			},
			wantReason: ReasonLoopHaltMaxModelCost,
			wantStatus: httpStatusTooManyRequests,
		},
		{
			name: "max_provider_failovers",
			override: func(attrs map[string]any) {
				attrs["usage"].(map[string]any)["provider_failovers"] = 4
			},
			wantReason: ReasonLoopHaltMaxProviderFailovers,
			wantStatus: httpStatusTooManyRequests,
		},
		{
			name: "max_risk_score",
			override: func(attrs map[string]any) {
				attrs["usage"].(map[string]any)["risk_score"] = 0.81
			},
			wantReason: ReasonLoopHaltRiskScore,
			wantStatus: httpStatusForbidden,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := newLoopPlanePolicyEngine()
			req := baseLoopRequest()
			req.Envelope.RunID = "run-loop-" + string(rune('a'+i))
			req.Policy.Envelope.RunID = req.Envelope.RunID
			attrs := baseLoopAttributes()
			tc.override(attrs)
			req.Policy.Attributes = attrs

			decision, reason, status, _ := engine.evaluate(req, "dec-halt", "trace-halt", time.Now().UTC())
			if decision != DecisionDeny {
				t.Fatalf("expected deny, got %s", decision)
			}
			if reason != tc.wantReason {
				t.Fatalf("expected reason=%s got=%s", tc.wantReason, reason)
			}
			if status != tc.wantStatus {
				t.Fatalf("expected status=%d got=%d", tc.wantStatus, status)
			}
		})
	}
}

func TestLoopPlanePolicyStateTransitions(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	req := baseLoopRequest()
	now := time.Now().UTC()

	stepUpReq := req
	stepUpReq.Policy.Attributes = baseLoopAttributes()
	stepUpReq.Policy.Attributes["step_up_required"] = true
	decision, reason, status, _ := engine.evaluate(stepUpReq, "dec-stepup", "trace-stepup", now)
	if decision != DecisionStepUp || reason != ReasonLoopStepUpRequired || status != httpStatusAccepted {
		t.Fatalf("expected step-up decision, got %s/%s/%d", decision, reason, status)
	}

	approvedReq := req
	approvedReq.Policy.Attributes = baseLoopAttributes()
	approvedReq.Policy.Attributes["event"] = "approval_granted"
	decision, reason, status, _ = engine.evaluate(approvedReq, "dec-approval", "trace-approval", now.Add(time.Second))
	if decision != DecisionAllow || reason != ReasonLoopAllow || status != 200 {
		t.Fatalf("expected running allow after approval, got %s/%s/%d", decision, reason, status)
	}

	completedReq := req
	completedReq.Policy.Attributes = baseLoopAttributes()
	completedReq.Policy.Attributes["event"] = "complete"
	decision, reason, status, _ = engine.evaluate(completedReq, "dec-complete", "trace-complete", now.Add(2*time.Second))
	if decision != DecisionAllow || reason != ReasonLoopCompleted || status != 200 {
		t.Fatalf("expected complete allow, got %s/%s/%d", decision, reason, status)
	}

	operatorReq := req
	operatorReq.Envelope.RunID = "run-loop-operator"
	operatorReq.Policy.Envelope.RunID = "run-loop-operator"
	operatorReq.Policy.Attributes = baseLoopAttributes()
	operatorReq.Policy.Attributes["event"] = "operator_halt"
	decision, reason, status, _ = engine.evaluate(operatorReq, "dec-op", "trace-op", now)
	if decision != DecisionDeny || reason != ReasonLoopHaltOperator || status != httpStatusConflict {
		t.Fatalf("expected operator halt, got %s/%s/%d", decision, reason, status)
	}
}

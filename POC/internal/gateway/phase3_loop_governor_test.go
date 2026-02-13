package gateway

import (
	"net/http"
	"testing"
)

func TestLoopGovernorReasonMapping_AllDimensions(t *testing.T) {
	cases := []struct {
		name     string
		limits   map[string]any
		usage    map[string]any
		wantCode ReasonCode
		wantHTTP int
	}{
		{
			name: "max_steps",
			limits: map[string]any{
				"max_steps": 2,
			},
			usage:    map[string]any{"steps": 3},
			wantCode: ReasonLoopHaltMaxSteps,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name: "max_tool_calls",
			limits: map[string]any{
				"max_tool_calls": 1,
			},
			usage:    map[string]any{"tool_calls": 2},
			wantCode: ReasonLoopHaltMaxToolCalls,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name: "max_model_calls",
			limits: map[string]any{
				"max_model_calls": 1,
			},
			usage:    map[string]any{"model_calls": 2},
			wantCode: ReasonLoopHaltMaxModelCalls,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name: "max_wall_time_ms",
			limits: map[string]any{
				"max_wall_time_ms": 1000,
			},
			usage:    map[string]any{"wall_time_ms": 1001},
			wantCode: ReasonLoopHaltMaxWallTime,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name: "max_egress_bytes",
			limits: map[string]any{
				"max_egress_bytes": 10,
			},
			usage:    map[string]any{"egress_bytes": 11},
			wantCode: ReasonLoopHaltMaxEgressBytes,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name: "max_model_cost_usd",
			limits: map[string]any{
				"max_model_cost_usd": 0.2,
			},
			usage:    map[string]any{"model_cost_usd": 0.21},
			wantCode: ReasonLoopHaltMaxModelCost,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name: "max_provider_failovers",
			limits: map[string]any{
				"max_provider_failovers": 1,
			},
			usage:    map[string]any{"provider_failovers": 2},
			wantCode: ReasonLoopHaltMaxProviderFailovers,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name: "max_risk_score",
			limits: map[string]any{
				"max_risk_score": 0.5,
			},
			usage:    map[string]any{"risk_score": 0.8},
			wantCode: ReasonLoopHaltRiskScore,
			wantHTTP: http.StatusTooManyRequests,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			engine := newLoopPlanePolicyEngine()
			res := engine.evaluate(loopPlaneReq("run-"+tt.name, "session-loop", tt.limits, tt.usage))
			if res.Reason != tt.wantCode {
				t.Fatalf("expected reason %s, got %s (metadata=%v)", tt.wantCode, res.Reason, res.Metadata)
			}
			if res.HTTPStatus != tt.wantHTTP {
				t.Fatalf("expected status %d, got %d", tt.wantHTTP, res.HTTPStatus)
			}
		})
	}
}

func TestLoopGovernorDurableStateAndImmutableLimits(t *testing.T) {
	engine := newLoopPlanePolicyEngine()

	limits := map[string]any{
		"max_steps":              5,
		"max_tool_calls":         5,
		"max_model_calls":        5,
		"max_wall_time_ms":       5000,
		"max_egress_bytes":       1000,
		"max_model_cost_usd":     1.0,
		"max_provider_failovers": 2,
		"max_risk_score":         0.9,
	}

	allow1 := engine.evaluate(loopPlaneReq("run-durable", "session-loop", limits, map[string]any{
		"steps":              2,
		"tool_calls":         1,
		"model_calls":        1,
		"wall_time_ms":       1000,
		"egress_bytes":       100,
		"model_cost_usd":     0.1,
		"provider_failovers": 0,
		"risk_score":         0.2,
	}))
	if allow1.Reason != ReasonLoopAllow || allow1.HTTPStatus != http.StatusOK {
		t.Fatalf("expected allow on first run, got reason=%s status=%d", allow1.Reason, allow1.HTTPStatus)
	}

	allow2 := engine.evaluate(loopPlaneReq("run-durable", "session-loop", limits, map[string]any{
		"steps": 4,
	}))
	if allow2.Reason != ReasonLoopAllow || allow2.HTTPStatus != http.StatusOK {
		t.Fatalf("expected allow on second run, got reason=%s status=%d", allow2.Reason, allow2.HTTPStatus)
	}

	halt := engine.evaluate(loopPlaneReq("run-durable", "session-loop", limits, map[string]any{
		"steps": 6,
	}))
	if halt.Reason != ReasonLoopHaltMaxSteps || halt.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("expected max-steps halt, got reason=%s status=%d", halt.Reason, halt.HTTPStatus)
	}

	terminated := engine.evaluate(loopPlaneReq("run-durable", "session-loop", limits, map[string]any{
		"steps": 1,
	}))
	if terminated.Reason != ReasonLoopRunAlreadyTerminated || terminated.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("expected run already terminated, got reason=%s status=%d", terminated.Reason, terminated.HTTPStatus)
	}

	first := engine.evaluate(loopPlaneReq("run-immutable", "session-loop", limits, map[string]any{
		"steps": 1,
	}))
	if first.Reason != ReasonLoopAllow {
		t.Fatalf("expected allow on immutable baseline, got reason=%s", first.Reason)
	}
	mutated := map[string]any{
		"max_steps":              6,
		"max_tool_calls":         5,
		"max_model_calls":        5,
		"max_wall_time_ms":       5000,
		"max_egress_bytes":       1000,
		"max_model_cost_usd":     1.0,
		"max_provider_failovers": 2,
		"max_risk_score":         0.9,
	}
	immutable := engine.evaluate(loopPlaneReq("run-immutable", "session-loop", mutated, map[string]any{
		"steps": 2,
	}))
	if immutable.Reason != ReasonLoopLimitsImmutableViolation || immutable.HTTPStatus != http.StatusForbidden {
		t.Fatalf("expected immutable limits violation, got reason=%s status=%d", immutable.Reason, immutable.HTTPStatus)
	}
}

func loopPlaneReq(runID, sessionID string, limits, usage map[string]any) PlaneRequestV2 {
	attrs := map[string]any{
		"limits": limits,
		"usage":  usage,
	}
	return PlaneRequestV2{
		Envelope: RunEnvelope{
			RunID:         runID,
			SessionID:     sessionID,
			Tenant:        "tenant-a",
			ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			Plane:         PlaneLoop,
		},
		Policy: PolicyInputV2{
			Envelope: RunEnvelope{
				RunID:         runID,
				SessionID:     sessionID,
				Tenant:        "tenant-a",
				ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Plane:         PlaneLoop,
			},
			Action:     "loop.check",
			Resource:   "loop/external-governor",
			Attributes: attrs,
		},
	}
}

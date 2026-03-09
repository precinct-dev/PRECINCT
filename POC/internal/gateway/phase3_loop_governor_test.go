package gateway

import (
	"net/http"
	"testing"
	"time"
)

// fullLimitsWithOverride returns a complete limits map (all values > 0) with one
// dimension overridden. The new state-machine engine requires all limits > 0.
func fullLimitsWithOverride(key string, val any) map[string]any {
	m := map[string]any{
		"max_steps":              100,
		"max_tool_calls":         100,
		"max_model_calls":        100,
		"max_wall_time_ms":       100000,
		"max_egress_bytes":       100000,
		"max_model_cost_usd":     100.0,
		"max_provider_failovers": 100,
		"max_risk_score":         1.0,
	}
	m[key] = val
	return m
}

func TestLoopGovernorReasonMapping_AllDimensions(t *testing.T) {
	cases := []struct {
		name     string
		limits   map[string]any
		usage    map[string]any
		wantCode ReasonCode
		wantHTTP int
	}{
		{
			name:     "max_steps",
			limits:   fullLimitsWithOverride("max_steps", 2),
			usage:    map[string]any{"steps": 3},
			wantCode: ReasonLoopHaltMaxSteps,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name:     "max_tool_calls",
			limits:   fullLimitsWithOverride("max_tool_calls", 1),
			usage:    map[string]any{"tool_calls": 2},
			wantCode: ReasonLoopHaltMaxToolCalls,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name:     "max_model_calls",
			limits:   fullLimitsWithOverride("max_model_calls", 1),
			usage:    map[string]any{"model_calls": 2},
			wantCode: ReasonLoopHaltMaxModelCalls,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name:     "max_wall_time_ms",
			limits:   fullLimitsWithOverride("max_wall_time_ms", 1000),
			usage:    map[string]any{"wall_time_ms": 1001},
			wantCode: ReasonLoopHaltMaxWallTime,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name:     "max_egress_bytes",
			limits:   fullLimitsWithOverride("max_egress_bytes", 10),
			usage:    map[string]any{"egress_bytes": 11},
			wantCode: ReasonLoopHaltMaxEgressBytes,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name:     "max_model_cost_usd",
			limits:   fullLimitsWithOverride("max_model_cost_usd", 0.2),
			usage:    map[string]any{"model_cost_usd": 0.21},
			wantCode: ReasonLoopHaltMaxModelCost,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name:     "max_provider_failovers",
			limits:   fullLimitsWithOverride("max_provider_failovers", 1),
			usage:    map[string]any{"provider_failovers": 2},
			wantCode: ReasonLoopHaltMaxProviderFailovers,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name:     "max_risk_score",
			limits:   fullLimitsWithOverride("max_risk_score", 0.5),
			usage:    map[string]any{"risk_score": 0.8},
			wantCode: ReasonLoopHaltRiskScore,
			wantHTTP: http.StatusForbidden,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			engine := newLoopPlanePolicyEngine()
			now := time.Now().UTC()
			_, reason, httpStatus, _ := engine.evaluate(loopPlaneReq("run-"+tt.name, "session-loop", tt.limits, tt.usage), "dec-001", "trace-001", now)
			if reason != tt.wantCode {
				t.Fatalf("expected reason %s, got %s", tt.wantCode, reason)
			}
			if httpStatus != tt.wantHTTP {
				t.Fatalf("expected status %d, got %d", tt.wantHTTP, httpStatus)
			}
		})
	}
}

func TestLoopGovernorDurableStateAndImmutableLimits(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	now := time.Now().UTC()

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

	_, reason1, status1, _ := engine.evaluate(loopPlaneReq("run-durable", "session-loop", limits, map[string]any{
		"steps":              2,
		"tool_calls":         1,
		"model_calls":        1,
		"wall_time_ms":       1000,
		"egress_bytes":       100,
		"model_cost_usd":     0.1,
		"provider_failovers": 0,
		"risk_score":         0.2,
	}), "dec-001", "trace-001", now)
	if reason1 != ReasonLoopAllow || status1 != http.StatusOK {
		t.Fatalf("expected allow on first run, got reason=%s status=%d", reason1, status1)
	}

	_, reason2, status2, _ := engine.evaluate(loopPlaneReq("run-durable", "session-loop", limits, map[string]any{
		"steps": 4,
	}), "dec-002", "trace-002", now.Add(time.Second))
	if reason2 != ReasonLoopAllow || status2 != http.StatusOK {
		t.Fatalf("expected allow on second run, got reason=%s status=%d", reason2, status2)
	}

	_, reason3, status3, _ := engine.evaluate(loopPlaneReq("run-durable", "session-loop", limits, map[string]any{
		"steps": 6,
	}), "dec-003", "trace-003", now.Add(2*time.Second))
	if reason3 != ReasonLoopHaltMaxSteps || status3 != http.StatusTooManyRequests {
		t.Fatalf("expected max-steps halt, got reason=%s status=%d", reason3, status3)
	}

	// After halt, subsequent calls return the original halt reason (terminal immutability).
	_, reason4, _, _ := engine.evaluate(loopPlaneReq("run-durable", "session-loop", limits, map[string]any{
		"steps": 1,
	}), "dec-004", "trace-004", now.Add(3*time.Second))
	if reason4 != ReasonLoopHaltMaxSteps && reason4 != ReasonLoopRunAlreadyTerminated {
		t.Fatalf("expected halt reason or already terminated, got reason=%s", reason4)
	}

	_, reason5, _, _ := engine.evaluate(loopPlaneReq("run-immutable", "session-loop", limits, map[string]any{
		"steps": 1,
	}), "dec-005", "trace-005", now.Add(4*time.Second))
	if reason5 != ReasonLoopAllow {
		t.Fatalf("expected allow on immutable baseline, got reason=%s", reason5)
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
	_, reason6, status6, _ := engine.evaluate(loopPlaneReq("run-immutable", "session-loop", mutated, map[string]any{
		"steps": 2,
	}), "dec-006", "trace-006", now.Add(5*time.Second))
	if reason6 != ReasonLoopLimitsImmutableViolation || status6 != http.StatusForbidden {
		t.Fatalf("expected immutable limits violation, got reason=%s status=%d", reason6, status6)
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

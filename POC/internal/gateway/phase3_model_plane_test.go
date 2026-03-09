package gateway

import (
	"net/http"
	"testing"
)

func modelRequestForTest(tenant string, attrs map[string]any) PlaneRequestV2 {
	envelope := RunEnvelope{
		RunID:         "run-model-test",
		SessionID:     "sess-model-test",
		Tenant:        tenant,
		ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Plane:         PlaneModel,
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

func TestModelPlanePolicyEngineNearLimitAndExhausted(t *testing.T) {
	engine := newModelPlanePolicyEngine()

	allowReq := modelRequestForTest("tenant-near-limit", map[string]any{
		"budget_profile": "tiny",
		"budget_units":   2,
	})
	decision, reason, status, _ := engine.evaluate(allowReq)
	if decision != DecisionAllow || reason != ReasonModelBudgetNearLimit || status != http.StatusOK {
		t.Fatalf("expected near-limit allow, got decision=%s reason=%s status=%d", decision, reason, status)
	}

	denyReq := modelRequestForTest("tenant-near-limit", map[string]any{
		"budget_profile": "tiny",
		"budget_units":   1,
	})
	decision, reason, status, _ = engine.evaluate(denyReq)
	if decision != DecisionDeny || reason != ReasonModelBudgetExhausted || status != http.StatusTooManyRequests {
		t.Fatalf("expected budget exhausted deny, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

func TestModelPlanePolicyEngineFallbackApplied(t *testing.T) {
	engine := newModelPlanePolicyEngine()
	req := modelRequestForTest("tenant-fallback", map[string]any{
		"provider":                "openai",
		"model":                   "gpt-4o",
		"residency_intent":        "us",
		"simulate_provider_error": true,
	})

	decision, reason, status, metadata := engine.evaluate(req)
	if decision != DecisionAllow || reason != ReasonModelFallbackApplied || status != http.StatusOK {
		t.Fatalf("expected fallback allow, got decision=%s reason=%s status=%d", decision, reason, status)
	}
	if got := metadata["provider_used"]; got != "azure_openai" {
		t.Fatalf("expected provider_used=azure_openai, got=%v", got)
	}
}

func TestModelPlanePolicyEngineNoFallback(t *testing.T) {
	engine := newModelPlanePolicyEngine()
	req := modelRequestForTest("tenant-no-fallback", map[string]any{
		"provider":                "anthropic",
		"model":                   "claude-3-5-sonnet",
		"residency_intent":        "us",
		"simulate_provider_error": true,
	})

	decision, reason, status, _ := engine.evaluate(req)
	if decision != DecisionDeny || reason != ReasonModelNoFallback || status != http.StatusBadGateway {
		t.Fatalf("expected no-fallback deny, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

func TestModelPlaneBypassDetection(t *testing.T) {
	if !isBypassRequested(map[string]any{"direct_egress": true}) {
		t.Fatal("expected direct_egress to be detected as bypass")
	}
	if !isBypassRequested(map[string]any{"mediation_mode": "bypass"}) {
		t.Fatal("expected mediation_mode=bypass to be detected as bypass")
	}
	if isBypassRequested(map[string]any{"mediation_mode": "mediated"}) {
		t.Fatal("expected mediation_mode=mediated to not be bypass")
	}
}

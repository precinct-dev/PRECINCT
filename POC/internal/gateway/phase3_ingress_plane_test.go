package gateway

import (
	"net/http"
	"testing"
	"time"
)

func ingressRequestForTest(actorSPIFFE string, attrs map[string]any) PlaneRequestV2 {
	envelope := RunEnvelope{
		RunID:         "run-ingress-test",
		SessionID:     "sess-ingress-test",
		Tenant:        "tenant-ingress",
		ActorSPIFFEID: actorSPIFFE,
		Plane:         PlaneIngress,
	}
	return PlaneRequestV2{
		Envelope: envelope,
		Policy: PolicyInputV2{
			Envelope:   envelope,
			Action:     "ingress.admit",
			Resource:   "ingress/event",
			Attributes: attrs,
		},
	}
}

func ingressAttrsForTest(connector, sourcePrincipal, nonce, eventID string, ts time.Time) map[string]any {
	return map[string]any{
		"connector_type":   connector,
		"source_id":        "source-1",
		"source_principal": sourcePrincipal,
		"event_id":         eventID,
		"nonce":            nonce,
		"event_timestamp":  ts.UTC().Format(time.RFC3339),
		"payload": map[string]any{
			"text": "external payload",
		},
	}
}

func TestParseIngressCanonicalEnvelopeValidation(t *testing.T) {
	actor := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	attrs := ingressAttrsForTest("webhook", actor, "nonce-1", "event-1", time.Now().UTC())

	parsed, err := parseIngressCanonicalEnvelope(attrs)
	if err != nil {
		t.Fatalf("expected valid ingress envelope, got: %v", err)
	}
	if parsed.ConnectorType != "webhook" {
		t.Fatalf("expected connector_type=webhook got=%s", parsed.ConnectorType)
	}

	delete(attrs, "nonce")
	if _, err := parseIngressCanonicalEnvelope(attrs); err == nil {
		t.Fatal("expected missing nonce to fail canonical envelope validation")
	}
}

func TestIngressPlanePolicyReplayAndFreshness(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	actor := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"

	allowReq := ingressRequestForTest(actor, ingressAttrsForTest("webhook", actor, "nonce-replay", "event-1", now))
	decision, reason, status, _ := engine.evaluate(allowReq, now)
	if decision != DecisionAllow || reason != ReasonIngressAllow || status != http.StatusOK {
		t.Fatalf("expected allow on first seen nonce, got decision=%s reason=%s status=%d", decision, reason, status)
	}

	replayReq := ingressRequestForTest(actor, ingressAttrsForTest("webhook", actor, "nonce-replay", "event-1", now))
	decision, reason, status, _ = engine.evaluate(replayReq, now)
	if decision != DecisionDeny || reason != ReasonIngressReplayDetected || status != http.StatusConflict {
		t.Fatalf("expected replay deny, got decision=%s reason=%s status=%d", decision, reason, status)
	}

	staleReq := ingressRequestForTest(actor, ingressAttrsForTest("queue", actor, "nonce-stale", "event-2", now.Add(-2*time.Hour)))
	decision, reason, status, _ = engine.evaluate(staleReq, now)
	if decision != DecisionQuarantine || reason != ReasonIngressFreshnessStale || status != http.StatusAccepted {
		t.Fatalf("expected stale quarantine, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

func TestIngressPlanePolicyStepUpAndSourceAuth(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	actor := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"

	stepUpAttrs := ingressAttrsForTest("queue", actor, "nonce-stepup", "event-stepup", now)
	stepUpAttrs["requires_step_up"] = true
	stepUpReq := ingressRequestForTest(actor, stepUpAttrs)
	decision, reason, status, _ := engine.evaluate(stepUpReq, now)
	if decision != DecisionStepUp || reason != ReasonIngressStepUpRequired || status != http.StatusAccepted {
		t.Fatalf("expected step_up decision, got decision=%s reason=%s status=%d", decision, reason, status)
	}

	unauthReq := ingressRequestForTest(actor, ingressAttrsForTest("webhook", "spiffe://poc.local/agents/other/dev", "nonce-unauth", "event-unauth", now))
	decision, reason, status, _ = engine.evaluate(unauthReq, now)
	if decision != DecisionDeny || reason != ReasonIngressSourceUnauth || status != http.StatusUnauthorized {
		t.Fatalf("expected source unauth deny, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

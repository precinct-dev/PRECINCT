package gateway

import (
	"net/http"
	"testing"
	"time"
)

func contextRequestForTest(attrs map[string]any) PlaneRequestV2 {
	envelope := RunEnvelope{
		RunID:         "run-context-test",
		SessionID:     "sess-context-test",
		Tenant:        "tenant-context",
		ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Plane:         PlaneContext,
	}
	return PlaneRequestV2{
		Envelope: envelope,
		Policy: PolicyInputV2{
			Envelope:   envelope,
			Action:     "context.admit",
			Resource:   "context/segment",
			Attributes: attrs,
		},
	}
}

func baseContextAttrs() map[string]any {
	return map[string]any{
		"segment_id":                "segment-1",
		"content":                   "safe context content",
		"scan_passed":               true,
		"prompt_check_passed":       true,
		"prompt_injection_detected": false,
		"dlp_classification":        "clean",
		"model_egress":              true,
		"memory_operation":          "none",
		"memory_tier":               "session",
		"provenance": map[string]any{
			"source":    "external",
			"checksum":  "sha256:test",
			"connector": "webhook",
		},
	}
}

func TestContextPlanePolicySafeAndUnsafe(t *testing.T) {
	engine := newContextPlanePolicyEngine()
	now := time.Now().UTC()

	safeReq := contextRequestForTest(baseContextAttrs())
	decision, reason, status, metadata := engine.evaluate(safeReq, "decision-safe", "trace-safe", now)
	if decision != DecisionAllow || reason != ReasonContextAllow || status != http.StatusOK {
		t.Fatalf("expected safe allow, got decision=%s reason=%s status=%d", decision, reason, status)
	}
	if metadata["persisted"] != true {
		t.Fatalf("expected persisted metadata=true, got=%v", metadata["persisted"])
	}

	unsafeAttrs := baseContextAttrs()
	unsafeAttrs["prompt_check_passed"] = false
	unsafeAttrs["prompt_injection_detected"] = true
	unsafeReq := contextRequestForTest(unsafeAttrs)
	decision, reason, status, _ = engine.evaluate(unsafeReq, "decision-unsafe", "trace-unsafe", now)
	if decision != DecisionDeny || reason != ReasonContextPromptUnsafe || status != http.StatusForbidden {
		t.Fatalf("expected unsafe prompt deny, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

func TestContextPlanePolicyMemoryMediation(t *testing.T) {
	engine := newContextPlanePolicyEngine()
	now := time.Now().UTC()

	readAttrs := baseContextAttrs()
	readAttrs["memory_operation"] = "read"
	readAttrs["memory_tier"] = "regulated"
	readReq := contextRequestForTest(readAttrs)
	decision, reason, status, _ := engine.evaluate(readReq, "decision-read", "trace-read", now)
	if decision != DecisionStepUp || reason != ReasonContextMemoryReadStepUp || status != http.StatusAccepted {
		t.Fatalf("expected memory read step-up, got decision=%s reason=%s status=%d", decision, reason, status)
	}

	writeAttrs := baseContextAttrs()
	writeAttrs["memory_operation"] = "write"
	writeAttrs["memory_tier"] = "long_term"
	writeAttrs["dlp_classification"] = "sensitive"
	writeReq := contextRequestForTest(writeAttrs)
	decision, reason, status, _ = engine.evaluate(writeReq, "decision-write", "trace-write", now)
	if decision != DecisionDeny || reason != ReasonContextMemoryWriteDenied || status != http.StatusForbidden {
		t.Fatalf("expected memory write deny, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

func TestContextPlanePolicyNoScanNoSend(t *testing.T) {
	engine := newContextPlanePolicyEngine()
	now := time.Now().UTC()

	attrs := baseContextAttrs()
	attrs["scan_passed"] = false
	req := contextRequestForTest(attrs)
	decision, reason, status, _ := engine.evaluate(req, "decision-noscan", "trace-noscan", now)
	if decision != DecisionDeny || reason != ReasonContextNoScanNoSend || status != http.StatusForbidden {
		t.Fatalf("expected no-scan-no-send deny, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

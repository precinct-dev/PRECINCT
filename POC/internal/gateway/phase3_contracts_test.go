package gateway

import "testing"

func TestRunEnvelopeValidate(t *testing.T) {
	valid := RunEnvelope{
		RunID:         "run-1",
		SessionID:     "sess-1",
		Tenant:        "tenant-a",
		ActorSPIFFEID: "spiffe://poc.local/agents/test/dev",
		Plane:         PlaneIngress,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid envelope, got error: %v", err)
	}

	invalid := valid
	invalid.Plane = "unsupported"
	if err := invalid.Validate(); err == nil {
		t.Fatal("expected unsupported plane to fail validation")
	}

	invalid = valid
	invalid.ExecutionMode = "rlm"
	if err := invalid.Validate(); err == nil {
		t.Fatal("expected execution_mode=rlm without lineage_id to fail validation")
	}

	valid.ExecutionMode = "rlm"
	valid.LineageID = "lineage-1"
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected rlm envelope with lineage_id to pass validation: %v", err)
	}
}

func TestPolicyInputV2Validate(t *testing.T) {
	p := PolicyInputV2{
		Envelope: RunEnvelope{
			RunID:         "run-1",
			SessionID:     "sess-1",
			Tenant:        "tenant-a",
			ActorSPIFFEID: "spiffe://poc.local/agents/test/dev",
			Plane:         PlaneModel,
		},
		Action:   "call_model",
		Resource: "provider/openai/gpt-4o",
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("expected valid policy input, got error: %v", err)
	}

	p.Action = ""
	if err := p.Validate(); err == nil {
		t.Fatal("expected empty action to fail validation")
	}
}

func TestAuditEventV2Validate(t *testing.T) {
	evt := AuditEventV2{
		EventType:  phase3AuditEventTypeDecisionV2,
		Plane:      PlaneContext,
		ReasonCode: ReasonContextAllow,
		Decision:   DecisionAllow,
		RunID:      "run-1",
		SessionID:  "sess-1",
		DecisionID: "dec-1",
		TraceID:    "trace-1",
	}
	if err := evt.Validate(); err != nil {
		t.Fatalf("expected valid audit event, got error: %v", err)
	}

	evt.Decision = "bad"
	if err := evt.Validate(); err == nil {
		t.Fatal("expected invalid decision to fail validation")
	}
}

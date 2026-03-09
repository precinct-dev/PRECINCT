package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// Unit tests for evaluateContextInvariants
// ---------------------------------------------------------------------------

func TestEvaluateContextInvariants_NoScanNoSend(t *testing.T) {
	decision, reason, status, _ := evaluateContextInvariants(map[string]any{
		"scan_passed":               false,
		"prompt_check_passed":       false,
		"prompt_injection_detected": true,
	})
	if decision != DecisionDeny || reason != ReasonContextNoScanNoSend || status != 403 {
		t.Fatalf("expected deny CONTEXT_NO_SCAN_NO_SEND/403, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

func TestEvaluateContextInvariants_NoProvenanceNoPersist(t *testing.T) {
	decision, reason, status, _ := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_operation":    "write",
	})
	if decision != DecisionDeny || reason != ReasonContextMemoryWriteDenied || status != 403 {
		t.Fatalf("expected deny CONTEXT_MEMORY_WRITE_DENIED/403, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

func TestEvaluateContextInvariants_NoVerificationNoLoad(t *testing.T) {
	decision, reason, status, _ := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"model_egress":        true,
		"provenance": map[string]any{
			"source":   "ingress",
			"checksum": "sha256:abc",
			"verified": false,
		},
	})
	if decision != DecisionDeny || reason != ReasonContextSchemaInvalid || status != 403 {
		t.Fatalf("expected deny CONTEXT_SCHEMA_INVALID/403, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

func TestEvaluateContextInvariants_MinimumNecessarySensitiveDenied(t *testing.T) {
	decision, reason, status, metadata := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"model_egress":        true,
		"dlp_classification":  "phi",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})
	if decision != DecisionDeny || reason != ReasonContextDLPDenied || status != 403 {
		t.Fatalf("expected deny CONTEXT_DLP_CLASSIFICATION_DENIED/403, got decision=%s reason=%s status=%d", decision, reason, status)
	}
	if metadata["minimum_necessary_outcome"] != "deny" {
		t.Fatalf("expected minimum_necessary_outcome=deny, got %v", metadata["minimum_necessary_outcome"])
	}
}

func TestEvaluateContextInvariants_MinimumNecessaryTokenizedAllow(t *testing.T) {
	decision, reason, status, metadata := evaluateContextInvariants(map[string]any{
		"scan_passed":               true,
		"prompt_check_passed":       true,
		"model_egress":              true,
		"dlp_classification":        "phi",
		"minimum_necessary_outcome": "tokenize",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})
	if decision != DecisionAllow || reason != ReasonContextAllow || status != 200 {
		t.Fatalf("expected allow CONTEXT_ALLOW/200, got decision=%s reason=%s status=%d", decision, reason, status)
	}
	if metadata["minimum_necessary_outcome"] != "tokenize" {
		t.Fatalf("expected minimum_necessary_outcome=tokenize, got %v", metadata["minimum_necessary_outcome"])
	}
}

// ---------------------------------------------------------------------------
// Unit tests for memory tier classification
// ---------------------------------------------------------------------------

func TestEvaluateContextInvariants_MemoryTierDefaultsToEphemeral(t *testing.T) {
	// When memory_tier is not provided, it should default to "ephemeral".
	decision, reason, status, metadata := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
	})
	if decision != DecisionAllow || reason != ReasonContextAllow || status != 200 {
		t.Fatalf("expected allow/200, got decision=%s reason=%s status=%d", decision, reason, status)
	}
	if metadata["memory_tier"] != "ephemeral" {
		t.Fatalf("expected memory_tier=ephemeral, got %v", metadata["memory_tier"])
	}
}

func TestEvaluateContextInvariants_InvalidMemoryTierReturnsSchemaInvalid(t *testing.T) {
	decision, reason, status, metadata := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_tier":         "permanent",
	})
	if decision != DecisionDeny || reason != ReasonContextSchemaInvalid || status != 400 {
		t.Fatalf("expected deny CONTEXT_SCHEMA_INVALID/400, got decision=%s reason=%s status=%d", decision, reason, status)
	}
	if metadata["memory_tier"] != "permanent" {
		t.Fatalf("expected metadata memory_tier=permanent, got %v", metadata["memory_tier"])
	}
}

func TestEvaluateContextInvariants_WriteLongTermCleanDLPAllowed(t *testing.T) {
	decision, reason, status, metadata := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_operation":    "write",
		"memory_tier":         "long_term",
		"dlp_classification":  "clean",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})
	if decision != DecisionAllow || reason != ReasonContextAllow || status != 200 {
		t.Fatalf("expected allow/200, got decision=%s reason=%s status=%d", decision, reason, status)
	}
	if metadata["memory_tier"] != "long_term" {
		t.Fatalf("expected memory_tier=long_term, got %v", metadata["memory_tier"])
	}
}

func TestEvaluateContextInvariants_WriteLongTermPIIDenied(t *testing.T) {
	decision, reason, status, metadata := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_operation":    "write",
		"memory_tier":         "long_term",
		"dlp_classification":  "pii",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})
	if decision != DecisionDeny || reason != ReasonContextMemoryWriteDenied || status != 403 {
		t.Fatalf("expected deny CONTEXT_MEMORY_WRITE_DENIED/403, got decision=%s reason=%s status=%d", decision, reason, status)
	}
	if metadata["memory_tier"] != "long_term" {
		t.Fatalf("expected memory_tier=long_term, got %v", metadata["memory_tier"])
	}
	if metadata["dlp_classification"] != "pii" {
		t.Fatalf("expected dlp_classification=pii, got %v", metadata["dlp_classification"])
	}
}

func TestEvaluateContextInvariants_WriteLongTermEmptyDLPDenied(t *testing.T) {
	decision, reason, status, metadata := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_operation":    "write",
		"memory_tier":         "long_term",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})
	if decision != DecisionDeny || reason != ReasonContextMemoryWriteDenied || status != 403 {
		t.Fatalf("expected deny CONTEXT_MEMORY_WRITE_DENIED/403, got decision=%s reason=%s status=%d", decision, reason, status)
	}
	if metadata["dlp_classification"] != "" {
		t.Fatalf("expected dlp_classification='', got %v", metadata["dlp_classification"])
	}
}

func TestEvaluateContextInvariants_WriteSessionPIINotAffectedByTierRule(t *testing.T) {
	// write + session + pii DLP: NOT affected by tier rule. The session tier has
	// no special write denial. This should be allowed (no model egress, so DLP
	// minimum-necessary rules are not triggered either).
	decision, reason, status, metadata := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_operation":    "write",
		"memory_tier":         "session",
		"dlp_classification":  "pii",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})
	if decision != DecisionAllow || reason != ReasonContextAllow || status != 200 {
		t.Fatalf("expected allow/200, got decision=%s reason=%s status=%d", decision, reason, status)
	}
	if metadata["memory_tier"] != "session" {
		t.Fatalf("expected memory_tier=session, got %v", metadata["memory_tier"])
	}
}

func TestEvaluateContextInvariants_ReadRegulatedStepUp(t *testing.T) {
	decision, reason, status, metadata := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_operation":    "read",
		"memory_tier":         "regulated",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})
	if decision != DecisionStepUp || reason != ReasonContextMemoryReadStepUp || status != 202 {
		t.Fatalf("expected step_up CONTEXT_MEMORY_READ_STEP_UP_REQUIRED/202, got decision=%s reason=%s status=%d", decision, reason, status)
	}
	if metadata["memory_tier"] != "regulated" {
		t.Fatalf("expected memory_tier=regulated, got %v", metadata["memory_tier"])
	}
}

func TestEvaluateContextInvariants_ReadLongTermNoStepUp(t *testing.T) {
	decision, reason, status, _ := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_operation":    "read",
		"memory_tier":         "long_term",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})
	if decision == DecisionStepUp {
		t.Fatalf("expected no step_up for read+long_term, got step_up")
	}
	if decision != DecisionAllow || reason != ReasonContextAllow || status != 200 {
		t.Fatalf("expected allow/200, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

func TestEvaluateContextInvariants_ReadEphemeralNoStepUp(t *testing.T) {
	decision, reason, status, _ := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_operation":    "read",
		"memory_tier":         "ephemeral",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})
	if decision == DecisionStepUp {
		t.Fatalf("expected no step_up for read+ephemeral, got step_up")
	}
	if decision != DecisionAllow || reason != ReasonContextAllow || status != 200 {
		t.Fatalf("expected allow/200, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

func TestEvaluateContextInvariants_WriteRegulatedNoStepUp(t *testing.T) {
	// write + regulated: the step_up rule only applies to reads, not writes.
	decision, reason, status, _ := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_operation":    "write",
		"memory_tier":         "regulated",
		"dlp_classification":  "clean",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})
	if decision == DecisionStepUp {
		t.Fatalf("expected no step_up for write+regulated, got step_up")
	}
	// Write to regulated with clean DLP should be allowed.
	if decision != DecisionAllow || reason != ReasonContextAllow || status != 200 {
		t.Fatalf("expected allow/200, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

func TestEvaluateContextInvariants_MemoryTierInModelEgressMetadata(t *testing.T) {
	// Verify memory_tier appears in model egress metadata when DLP is sensitive.
	_, _, _, metadata := evaluateContextInvariants(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"model_egress":        true,
		"dlp_classification":  "phi",
		"memory_tier":         "session",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})
	if metadata["memory_tier"] != "session" {
		t.Fatalf("expected memory_tier=session in model egress metadata, got %v", metadata["memory_tier"])
	}
}

// ---------------------------------------------------------------------------
// Integration tests: full handleContextAdmit HTTP flow (no mocks)
// ---------------------------------------------------------------------------

// contextAdmitEnvelope returns a valid envelope for context plane requests.
func contextAdmitEnvelope() RunEnvelope {
	return RunEnvelope{
		RunID:         "run-tier-test",
		SessionID:     "sess-tier-test",
		Tenant:        "test-tenant",
		ActorSPIFFEID: "spiffe://poc.local/agents/test",
		Plane:         PlaneContext,
	}
}

// contextAdmitRequest builds a full PlaneRequestV2 for the context plane.
func contextAdmitRequest(attrs map[string]any) PlaneRequestV2 {
	env := contextAdmitEnvelope()
	return PlaneRequestV2{
		Envelope: env,
		Policy: PolicyInputV2{
			Envelope:   env,
			Action:     "admit",
			Resource:   "context/segment",
			Attributes: attrs,
		},
	}
}

// postContextAdmit creates an HTTP POST to /v1/context/admit with the given request body.
func postContextAdmit(t *testing.T, gw *Gateway, req PlaneRequestV2) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/context/admit", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	gw.handleContextAdmit(w, r)
	return w
}

func TestIntegration_HandleContextAdmit_WriteLongTermPIIDenied(t *testing.T) {
	gw := &Gateway{}
	req := contextAdmitRequest(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_operation":    "write",
		"memory_tier":         "long_term",
		"dlp_classification":  "pii",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})

	w := postContextAdmit(t, gw, req)
	if w.Code != 403 {
		t.Fatalf("expected HTTP 403, got %d", w.Code)
	}

	var resp PlaneDecisionV2
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Decision != DecisionDeny {
		t.Fatalf("expected decision=deny, got %s", resp.Decision)
	}
	if resp.ReasonCode != ReasonContextMemoryWriteDenied {
		t.Fatalf("expected reason_code=CONTEXT_MEMORY_WRITE_DENIED, got %s", resp.ReasonCode)
	}
	if resp.Metadata["memory_tier"] != "long_term" {
		t.Fatalf("expected memory_tier=long_term in metadata, got %v", resp.Metadata["memory_tier"])
	}
}

func TestIntegration_HandleContextAdmit_ReadRegulatedStepUp(t *testing.T) {
	gw := &Gateway{}
	req := contextAdmitRequest(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_operation":    "read",
		"memory_tier":         "regulated",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})

	w := postContextAdmit(t, gw, req)
	if w.Code != 202 {
		t.Fatalf("expected HTTP 202, got %d", w.Code)
	}

	var resp PlaneDecisionV2
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Decision != DecisionStepUp {
		t.Fatalf("expected decision=step_up, got %s", resp.Decision)
	}
	if resp.ReasonCode != ReasonContextMemoryReadStepUp {
		t.Fatalf("expected reason_code=CONTEXT_MEMORY_READ_STEP_UP_REQUIRED, got %s", resp.ReasonCode)
	}
	if resp.Metadata["memory_tier"] != "regulated" {
		t.Fatalf("expected memory_tier=regulated in metadata, got %v", resp.Metadata["memory_tier"])
	}
}

func TestIntegration_HandleContextAdmit_WriteSessionCleanDLPAllowed(t *testing.T) {
	gw := &Gateway{}
	req := contextAdmitRequest(map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_operation":    "write",
		"memory_tier":         "session",
		"dlp_classification":  "clean",
		"provenance": map[string]any{
			"source":              "ingress",
			"checksum":            "sha256:abc",
			"verified":            true,
			"verifier":            "sigstore",
			"verification_method": "sha256+sigstore",
		},
	})

	w := postContextAdmit(t, gw, req)
	if w.Code != 200 {
		t.Fatalf("expected HTTP 200, got %d", w.Code)
	}

	var resp PlaneDecisionV2
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Decision != DecisionAllow {
		t.Fatalf("expected decision=allow, got %s", resp.Decision)
	}
	if resp.ReasonCode != ReasonContextAllow {
		t.Fatalf("expected reason_code=CONTEXT_ALLOW, got %s", resp.ReasonCode)
	}
	if resp.Metadata["memory_tier"] != "session" {
		t.Fatalf("expected memory_tier=session in metadata, got %v", resp.Metadata["memory_tier"])
	}
}

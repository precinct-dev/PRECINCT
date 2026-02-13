package gateway

import (
	"net/http"
	"testing"
)

func TestEvaluatePromptSafety_NoPolicyRequestIsNotHandled(t *testing.T) {
	decision, reason, status, metadata, handled := evaluatePromptSafety(nil, true)
	if handled {
		t.Fatal("expected handled=false when no prompt safety policy is requested")
	}
	if decision != DecisionAllow {
		t.Fatalf("expected decision allow, got %s", decision)
	}
	if reason != "" {
		t.Fatalf("expected empty reason, got %s", reason)
	}
	if status != 0 {
		t.Fatalf("expected status 0 for unhandled request, got %d", status)
	}
	if metadata != nil {
		t.Fatalf("expected nil metadata, got %v", metadata)
	}
}

func TestEvaluatePromptSafety_HIPAARawDenied(t *testing.T) {
	attrs := map[string]any{
		"compliance_profile": "hipaa",
		"prompt":             "Patient SSN 123-45-6789 with diagnosis details",
		"prompt_has_phi":     true,
	}

	decision, reason, status, metadata, handled := evaluatePromptSafety(attrs, true)
	if !handled {
		t.Fatal("expected handled=true for HIPAA prompt safety evaluation")
	}
	if decision != DecisionDeny {
		t.Fatalf("expected decision deny, got %s", decision)
	}
	if reason != ReasonPromptSafetyRawDenied {
		t.Fatalf("expected reason %s, got %s", ReasonPromptSafetyRawDenied, reason)
	}
	if status != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, status)
	}
	if metadata["prompt_safety_action"] != "deny_raw" {
		t.Fatalf("expected prompt_safety_action=deny_raw, got %v", metadata["prompt_safety_action"])
	}
}

func TestEvaluatePromptSafety_HIPAATokenizationQuarantine(t *testing.T) {
	attrs := map[string]any{
		"compliance_profile": "hipaa",
		"prompt_action":      "tokenize",
		"prompt":             "Patient SSN 123-45-6789 with diagnosis details",
		"prompt_has_phi":     true,
	}

	decision, reason, status, metadata, handled := evaluatePromptSafety(attrs, true)
	if !handled {
		t.Fatal("expected handled=true for HIPAA tokenization path")
	}
	if decision != DecisionQuarantine {
		t.Fatalf("expected decision quarantine, got %s", decision)
	}
	if reason != ReasonPromptSafetyTokenized {
		t.Fatalf("expected reason %s, got %s", ReasonPromptSafetyTokenized, reason)
	}
	if status != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, status)
	}
	if metadata["minimum_necessary_outcome"] != "tokenize" {
		t.Fatalf("expected minimum_necessary_outcome=tokenize, got %v", metadata["minimum_necessary_outcome"])
	}
}

func TestEvaluatePromptSafety_HIPAARedactionQuarantine(t *testing.T) {
	attrs := map[string]any{
		"compliance_profile": "hipaa",
		"prompt_action":      "redact",
		"prompt":             "Patient SSN 123-45-6789 with diagnosis details",
		"prompt_has_phi":     true,
	}

	decision, reason, status, metadata, handled := evaluatePromptSafety(attrs, true)
	if !handled {
		t.Fatal("expected handled=true for HIPAA redaction path")
	}
	if decision != DecisionQuarantine {
		t.Fatalf("expected decision quarantine, got %s", decision)
	}
	if reason != ReasonPromptSafetyRedacted {
		t.Fatalf("expected reason %s, got %s", ReasonPromptSafetyRedacted, reason)
	}
	if status != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, status)
	}
	if metadata["minimum_necessary_outcome"] != "redact" {
		t.Fatalf("expected minimum_necessary_outcome=redact, got %v", metadata["minimum_necessary_outcome"])
	}
}

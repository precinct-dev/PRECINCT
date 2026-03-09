package gateway

import "testing"

func TestPromptSafetyPolicyMapping(t *testing.T) {
	base := map[string]any{
		"compliance_profile": "hipaa",
		"model_scope":        "external",
		"prompt_has_phi":     true,
		"prompt":             "Patient SSN 123-45-6789 email user@example.com",
	}

	decision, reason, status, _, handled := evaluatePromptSafety(base)
	if !handled {
		t.Fatal("expected regulated prompt safety handling to be active")
	}
	if decision != DecisionDeny || reason != ReasonPromptSafetyRawDenied || status != 403 {
		t.Fatalf("expected deny raw regulated prompt, got decision=%s reason=%s status=%d", decision, reason, status)
	}

	redact := cloneAttrs(base)
	redact["prompt_action"] = "redact"
	decision, reason, status, meta, handled := evaluatePromptSafety(redact)
	if !handled || decision != DecisionAllow || reason != ReasonPromptSafetyRedacted || status != 200 {
		t.Fatalf("expected redaction allow, got decision=%s reason=%s status=%d handled=%v", decision, reason, status, handled)
	}
	if meta["prompt_transformed_digest"] == "" {
		t.Fatal("expected transformed digest for redaction")
	}

	tokenize := cloneAttrs(base)
	tokenize["prompt_action"] = "tokenize"
	decision, reason, status, meta, handled = evaluatePromptSafety(tokenize)
	if !handled || decision != DecisionAllow || reason != ReasonPromptSafetyTokenized || status != 200 {
		t.Fatalf("expected tokenization allow, got decision=%s reason=%s status=%d handled=%v", decision, reason, status, handled)
	}
	if meta["prompt_transformed_digest"] == "" {
		t.Fatal("expected transformed digest for tokenization")
	}

	overrideNoMarker := cloneAttrs(base)
	overrideNoMarker["prompt_action"] = "override"
	decision, reason, status, _, handled = evaluatePromptSafety(overrideNoMarker)
	if !handled || decision != DecisionDeny || reason != ReasonPromptSafetyOverrideReq || status != 403 {
		t.Fatalf("expected override without marker deny, got decision=%s reason=%s status=%d handled=%v", decision, reason, status, handled)
	}

	overrideWithMarker := cloneAttrs(base)
	overrideWithMarker["prompt_action"] = "override"
	overrideWithMarker["approval_marker"] = "ticket-123"
	decision, reason, status, _, handled = evaluatePromptSafety(overrideWithMarker)
	if !handled || decision != DecisionAllow || reason != ReasonPromptSafetyOverride || status != 200 {
		t.Fatalf("expected override with marker allow, got decision=%s reason=%s status=%d handled=%v", decision, reason, status, handled)
	}
}

func TestPromptSafetyTransformsDeterministic(t *testing.T) {
	prompt := "Contact user@example.com and SSN 123-45-6789"
	r1 := deterministicRedactPrompt(prompt)
	r2 := deterministicRedactPrompt(prompt)
	if r1 != r2 {
		t.Fatalf("expected deterministic redaction, got %q vs %q", r1, r2)
	}
	if digestString(r1) != digestString(r2) {
		t.Fatal("expected deterministic redaction digest")
	}

	t1 := deterministicTokenizePrompt(prompt)
	t2 := deterministicTokenizePrompt(prompt)
	if t1 != t2 {
		t.Fatalf("expected deterministic tokenization, got %q vs %q", t1, t2)
	}
	if digestString(t1) != digestString(t2) {
		t.Fatal("expected deterministic tokenization digest")
	}
}

func cloneAttrs(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

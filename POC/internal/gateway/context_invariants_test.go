package gateway

import "testing"

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

func TestEvaluateContextInvariants_NeuroSymbolicCSVValidationDenied(t *testing.T) {
	decision, reason, status, metadata := evaluateContextInvariants(map[string]any{
		"ingestion_type":                 "neuro_symbolic_csv",
		"context_kind":                   "neuro_symbolic_csv",
		"context_reference_mode":         "handle",
		"context_handle":                 "facts:abc123",
		"csv_schema_valid":               false,
		"csv_size_bytes":                 128,
		"csv_size_limit_bytes":           1024,
		"csv_row_count":                  2,
		"csv_malicious_content_detected": false,
		"scan_passed":                    true,
		"prompt_check_passed":            true,
		"prompt_injection_detected":      false,
	})
	if decision != DecisionDeny || reason != ReasonContextFactsCSVValidation || status != 403 {
		t.Fatalf("expected deny CONTEXT_FACTS_CSV_VALIDATION_FAILED/403, got decision=%s reason=%s status=%d", decision, reason, status)
	}
	if metadata["invariant"] != "neuro_symbolic_csv_validation" {
		t.Fatalf("expected invariant=neuro_symbolic_csv_validation, got %v", metadata["invariant"])
	}
}

func TestEvaluateContextInvariants_NeuroSymbolicCSVProvenanceDenied(t *testing.T) {
	decision, reason, status, metadata := evaluateContextInvariants(map[string]any{
		"ingestion_type":                 "neuro_symbolic_csv",
		"context_kind":                   "neuro_symbolic_csv",
		"context_reference_mode":         "handle",
		"context_handle":                 "facts:abc123",
		"csv_schema_valid":               true,
		"csv_size_bytes":                 128,
		"csv_size_limit_bytes":           1024,
		"csv_row_count":                  2,
		"csv_malicious_content_detected": false,
		"facts_hash":                     "sha256:deadbeef",
		"facts_hash_algorithm":           "sha256",
		"facts_hash_verified":            true,
		"scan_passed":                    true,
		"prompt_check_passed":            true,
		"prompt_injection_detected":      false,
		"memory_operation":               "write",
		"model_egress":                   true,
		"dlp_classification":             "clean",
		"minimum_necessary_applied":      true,
		"provenance": map[string]any{
			"source":              "upload://facts/it.csv",
			"checksum":            "sha256:feedface",
			"verified":            true,
			"verifier":            "sha256-csv-ingestion",
			"verification_method": "sha256",
		},
	})
	if decision != DecisionDeny || reason != ReasonContextFactsProvenanceInvalid || status != 403 {
		t.Fatalf("expected deny CONTEXT_FACTS_PROVENANCE_INVALID/403, got decision=%s reason=%s status=%d", decision, reason, status)
	}
	if metadata["invariant"] != "neuro_symbolic_csv_provenance" {
		t.Fatalf("expected invariant=neuro_symbolic_csv_provenance, got %v", metadata["invariant"])
	}
}

func TestEvaluateContextInvariants_NeuroSymbolicCSVStillHonorsNoScanNoSend(t *testing.T) {
	decision, reason, status, _ := evaluateContextInvariants(map[string]any{
		"ingestion_type":                 "neuro_symbolic_csv",
		"context_kind":                   "neuro_symbolic_csv",
		"context_reference_mode":         "handle",
		"context_handle":                 "facts:abc123",
		"csv_schema_valid":               true,
		"csv_size_bytes":                 128,
		"csv_size_limit_bytes":           1024,
		"csv_row_count":                  2,
		"csv_malicious_content_detected": false,
		"facts_hash":                     "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"facts_hash_algorithm":           "sha256",
		"facts_hash_verified":            true,
		"scan_passed":                    false,
		"prompt_check_passed":            true,
		"prompt_injection_detected":      false,
		"memory_operation":               "write",
		"model_egress":                   true,
		"dlp_classification":             "clean",
		"minimum_necessary_applied":      true,
		"provenance": map[string]any{
			"source":              "upload://facts/it.csv",
			"checksum":            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"verified":            true,
			"verifier":            "sha256-csv-ingestion",
			"verification_method": "sha256",
		},
	})
	if decision != DecisionDeny || reason != ReasonContextNoScanNoSend || status != 403 {
		t.Fatalf("expected deny CONTEXT_NO_SCAN_NO_SEND/403, got decision=%s reason=%s status=%d", decision, reason, status)
	}
}

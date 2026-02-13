package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestContextAdmissionInvariants_DenyAndTokenizeOutcomes(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := fmt.Sprintf("context-it-%d", time.Now().UnixNano())

	buildContextReq := func(runID string, attrs map[string]any) map[string]any {
		return map[string]any{
			"envelope": map[string]any{
				"run_id":          runID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "context",
			},
			"policy": map[string]any{
				"envelope": map[string]any{
					"run_id":          runID,
					"session_id":      sessionID,
					"tenant":          "tenant-a",
					"actor_spiffe_id": spiffeID,
					"plane":           "context",
				},
				"action":     "context.admit",
				"resource":   "context/segment",
				"attributes": attrs,
			},
		}
	}

	code, body := ruleOpsPost(t, baseURL+"/v1/context/admit", buildContextReq("ctx-it-persist-no-provenance", map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"memory_operation":    "write",
	}))
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 for no_provenance_no_persist, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "CONTEXT_MEMORY_WRITE_DENIED" {
		t.Fatalf("expected CONTEXT_MEMORY_WRITE_DENIED, got %q body=%v", reason, body)
	}

	code, body = ruleOpsPost(t, baseURL+"/v1/context/admit", buildContextReq("ctx-it-no-verification-no-load", map[string]any{
		"scan_passed":         true,
		"prompt_check_passed": true,
		"model_egress":        true,
		"dlp_classification":  "clean",
		"provenance": map[string]any{
			"source":   "ingress",
			"checksum": "sha256:abc",
			"verified": false,
		},
	}))
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 for no_verification_no_load, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "CONTEXT_SCHEMA_INVALID" {
		t.Fatalf("expected CONTEXT_SCHEMA_INVALID, got %q body=%v", reason, body)
	}

	code, body = ruleOpsPost(t, baseURL+"/v1/context/admit", buildContextReq("ctx-it-minimum-necessary-deny", map[string]any{
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
	}))
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 for minimum_necessary deny path, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "CONTEXT_DLP_CLASSIFICATION_DENIED" {
		t.Fatalf("expected CONTEXT_DLP_CLASSIFICATION_DENIED, got %q body=%v", reason, body)
	}

	code, body = ruleOpsPost(t, baseURL+"/v1/context/admit", buildContextReq("ctx-it-minimum-necessary-tokenize", map[string]any{
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
	}))
	if code != http.StatusOK {
		t.Fatalf("expected 200 for minimum_necessary tokenize path, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "CONTEXT_ALLOW" {
		t.Fatalf("expected CONTEXT_ALLOW, got %q body=%v", reason, body)
	}
	metadata, _ := body["metadata"].(map[string]any)
	if stringField(metadata["minimum_necessary_outcome"]) != "tokenize" {
		t.Fatalf("expected metadata.minimum_necessary_outcome=tokenize, got %v", metadata)
	}
}

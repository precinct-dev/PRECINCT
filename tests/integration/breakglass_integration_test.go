// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestBreakGlassActivateRevertScopeBoundModelOverride(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := fmt.Sprintf("breakglass-it-%d", time.Now().UnixNano())

	highRiskCall := func(runID, model string) (int, map[string]any) {
		return ruleOpsPost(t, baseURL+"/v1/model/call", map[string]any{
			"envelope": map[string]any{
				"run_id":          runID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "model",
			},
			"policy": map[string]any{
				"envelope": map[string]any{
					"run_id":          runID,
					"session_id":      sessionID,
					"tenant":          "tenant-a",
					"actor_spiffe_id": spiffeID,
					"plane":           "model",
				},
				"action":   "model.call",
				"resource": "model/inference",
				"attributes": map[string]any{
					"provider":  "openai",
					"model":     model,
					"risk_mode": "high",
				},
			},
		})
	}

	// Baseline: high-risk model mode denied without break-glass.
	code, body := highRiskCall("bg-it-deny-before", "gpt-4o")
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 before activation, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "MODEL_PROVIDER_RISK_MODE_DENIED" {
		t.Fatalf("expected MODEL_PROVIDER_RISK_MODE_DENIED before activation, got %q body=%v", reason, body)
	}

	// Request break-glass override scoped to model.call + gpt-4o + actor.
	code, body = approvalAdminPost(t, baseURL+"/admin/breakglass/request", map[string]any{
		"incident_id": "INC-BG-001",
		"scope": map[string]any{
			"action":          "model.call",
			"resource":        "gpt-4o",
			"actor_spiffe_id": spiffeID,
		},
		"requested_by": "security@corp",
		"ttl_seconds":  120,
	})
	if code != http.StatusOK {
		t.Fatalf("breakglass request expected 200, got %d body=%v", code, body)
	}
	requestID := nestedRuleOpsField(body, "record", "request_id")
	if requestID == "" {
		t.Fatalf("breakglass request missing request_id body=%v", body)
	}

	// Dual authorization.
	for _, approver := range []string{"security-1@corp", "security-2@corp"} {
		code, body = approvalAdminPost(t, baseURL+"/admin/breakglass/approve", map[string]any{
			"request_id":  requestID,
			"approved_by": approver,
		})
		if code != http.StatusOK {
			t.Fatalf("breakglass approve expected 200, got %d body=%v", code, body)
		}
	}

	// Activate override.
	code, body = approvalAdminPost(t, baseURL+"/admin/breakglass/activate", map[string]any{
		"request_id":   requestID,
		"activated_by": "ops@corp",
	})
	if code != http.StatusOK {
		t.Fatalf("breakglass activate expected 200, got %d body=%v", code, body)
	}

	// Within scope: same high-risk model call now allowed.
	code, body = highRiskCall("bg-it-allow-active", "gpt-4o")
	if code != http.StatusOK {
		t.Fatalf("expected 200 while break-glass active in scope, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "MODEL_ALLOW" {
		t.Fatalf("expected MODEL_ALLOW while active, got %q body=%v", reason, body)
	}
	metadata, _ := body["metadata"].(map[string]any)
	if stringField(metadata["break_glass_incident_id"]) != "INC-BG-001" {
		t.Fatalf("expected break_glass_incident_id metadata, got %v", metadata)
	}

	// Out of scope resource remains denied.
	code, body = highRiskCall("bg-it-deny-out-of-scope", "gpt-4o-mini")
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 for out-of-scope model, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "MODEL_PROVIDER_RISK_MODE_DENIED" {
		t.Fatalf("expected MODEL_PROVIDER_RISK_MODE_DENIED out-of-scope, got %q body=%v", reason, body)
	}

	// Revert and verify deny again.
	code, body = approvalAdminPost(t, baseURL+"/admin/breakglass/revert", map[string]any{
		"request_id":  requestID,
		"reverted_by": "ops@corp",
	})
	if code != http.StatusOK {
		t.Fatalf("breakglass revert expected 200, got %d body=%v", code, body)
	}

	code, body = highRiskCall("bg-it-deny-after-revert", "gpt-4o")
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 after revert, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "MODEL_PROVIDER_RISK_MODE_DENIED" {
		t.Fatalf("expected MODEL_PROVIDER_RISK_MODE_DENIED after revert, got %q body=%v", reason, body)
	}
}

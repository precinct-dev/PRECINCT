// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestApprovalCapabilityLifecycleAndReplay(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)
	scope := map[string]any{
		"action":          "tool.call",
		"resource":        "bash",
		"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"session_id":      "sess-approval-integration",
	}

	// request
	code, body := approvalAdminPost(t, baseURL+"/admin/approvals/request", map[string]any{
		"scope":        scope,
		"requested_by": "integration@test",
		"ttl_seconds":  120,
	})
	if code != http.StatusOK {
		t.Fatalf("request expected 200, got %d body=%v", code, body)
	}
	requestID := nestedRuleOpsField(body, "record", "request_id")
	if requestID == "" {
		t.Fatalf("request response missing request_id body=%v", body)
	}

	// grant
	code, body = approvalAdminPost(t, baseURL+"/admin/approvals/grant", map[string]any{
		"request_id":  requestID,
		"approved_by": "security@corp",
		"reason":      "integration-test",
	})
	if code != http.StatusOK {
		t.Fatalf("grant expected 200, got %d body=%v", code, body)
	}
	token := stringField(body["capability_token"])
	if token == "" {
		t.Fatalf("grant response missing token body=%v", body)
	}

	// consume once
	code, body = approvalAdminPost(t, baseURL+"/admin/approvals/consume", map[string]any{
		"capability_token": token,
		"scope":            scope,
	})
	if code != http.StatusOK {
		t.Fatalf("consume expected 200, got %d body=%v", code, body)
	}

	// replay consume should be denied
	code, body = approvalAdminPost(t, baseURL+"/admin/approvals/consume", map[string]any{
		"capability_token": token,
		"scope":            scope,
	})
	if code != http.StatusConflict {
		t.Fatalf("replay consume expected 409, got %d body=%v", code, body)
	}
	if got := stringField(body["code"]); got != "stepup_denied" {
		t.Fatalf("replay consume expected code stepup_denied, got %q body=%v", got, body)
	}
}

func TestHighRiskModelOperationApprovalTokenEnforcement(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)
	sessionID := "11111111-1111-4111-8111-111111111111"
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	modelPayload := map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]any{
			{"role": "user", "content": "test"},
		},
	}

	// High-risk model call without token must be denied by step-up.
	code, body := callOpenAICompat(t, baseURL+openAICompatPath, spiffeID, sessionID, "", modelPayload)
	if code != http.StatusForbidden {
		t.Fatalf("without token expected 403, got %d body=%v", code, body)
	}
	if got := stringField(body["code"]); got != "stepup_approval_required" {
		t.Fatalf("without token expected code stepup_approval_required, got %q body=%v", got, body)
	}

	// Create + grant token scoped for this model operation.
	scope := map[string]any{
		"action":          "model.call",
		"resource":        "gpt-4o",
		"actor_spiffe_id": spiffeID,
		"session_id":      sessionID,
	}
	code, body = approvalAdminPost(t, baseURL+"/admin/approvals/request", map[string]any{
		"scope":        scope,
		"requested_by": "integration@test",
		"ttl_seconds":  120,
	})
	if code != http.StatusOK {
		t.Fatalf("approval request expected 200, got %d body=%v", code, body)
	}
	requestID := nestedRuleOpsField(body, "record", "request_id")
	if requestID == "" {
		t.Fatalf("missing request_id body=%v", body)
	}

	code, body = approvalAdminPost(t, baseURL+"/admin/approvals/grant", map[string]any{
		"request_id":  requestID,
		"approved_by": "security@corp",
	})
	if code != http.StatusOK {
		t.Fatalf("approval grant expected 200, got %d body=%v", code, body)
	}
	token := stringField(body["capability_token"])
	if token == "" {
		t.Fatalf("missing capability_token body=%v", body)
	}

	// Same high-risk model call with valid token must pass step-up gate.
	code, body = callOpenAICompat(t, baseURL+openAICompatPath, spiffeID, sessionID, token, modelPayload)
	if code == http.StatusForbidden && (stringField(body["code"]) == "stepup_approval_required" || stringField(body["code"]) == "stepup_denied") {
		t.Fatalf("with token expected step-up pass-through, got %d body=%v", code, body)
	}
}

const openAICompatPath = "/openai/v1/chat/completions"

func approvalAdminPost(t *testing.T, url string, payload map[string]any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post %s failed: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func callOpenAICompat(t *testing.T, url, spiffeID, sessionID, token string, payload map[string]any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)
	req.Header.Set("X-Session-ID", sessionID)
	// Spoofed downgrade headers must not bypass trusted approval requirements.
	req.Header.Set("X-Risk-Mode", "low")
	req.Header.Set("X-Compliance-Profile", "standard")
	req.Header.Set("X-Step-Up-Approved", "true")
	req.Header.Set("X-Model-Provider", "openai")
	req.Header.Set("X-Provider-Endpoint", "http://127.0.0.1:65535/openai/v1/chat/completions")
	if token != "" {
		req.Header.Set("X-Step-Up-Token", token)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("call openai compat failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

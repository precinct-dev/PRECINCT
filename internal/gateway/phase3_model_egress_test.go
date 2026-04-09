// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

func postOpenAICompat(t *testing.T, handler http.Handler, headers map[string]string, payload map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, openAICompatChatCompletionsPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func issueModelApprovalToken(t *testing.T, gw *Gateway, model, spiffeID, sessionID string) string {
	t.Helper()
	if gw == nil || gw.approvalCapabilities == nil {
		t.Fatal("approval capability service unavailable in test gateway")
	}
	created, err := gw.approvalCapabilities.CreateRequest(middleware.ApprovalRequestInput{
		Scope: middleware.ApprovalScope{
			Action:        "model.call",
			Resource:      model,
			ActorSPIFFEID: spiffeID,
			SessionID:     sessionID,
		},
	})
	if err != nil {
		t.Fatalf("create approval request: %v", err)
	}
	grant, err := gw.approvalCapabilities.GrantRequest(middleware.ApprovalGrantInput{
		RequestID:  created.RequestID,
		ApprovedBy: "security@test",
	})
	if err != nil {
		t.Fatalf("grant approval request: %v", err)
	}
	return grant.Token
}

func TestOpenAICompat_ModelEgressSuccess(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("expected Authorization header to be forwarded")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer provider.Close()

	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	rec := postOpenAICompat(t, handler, map[string]string{
		"Authorization":            "Bearer test-token",
		"X-Model-Provider":         "groq",
		"X-Provider-Endpoint-Groq": provider.URL,
		"X-Residency-Intent":       "us",
		"X-Budget-Profile":         "standard",
		"X-Budget-Units":           "1",
	}, map[string]any{
		"model": "llama-3.3-70b-versatile",
		"messages": []map[string]any{
			{"role": "user", "content": "Hello model"},
		},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Precinct-Reason-Code") != string(ReasonModelAllow) {
		t.Fatalf("expected reason %s, got %s", ReasonModelAllow, rec.Header().Get("X-Precinct-Reason-Code"))
	}
	if rec.Header().Get("X-Precinct-Provider-Used") != "groq" {
		t.Fatalf("expected provider groq, got %s", rec.Header().Get("X-Precinct-Provider-Used"))
	}
}

func TestOpenAICompat_ModelPlaneDenied(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	rec := postOpenAICompat(t, handler, map[string]string{
		"X-Model-Provider": "unknown-provider",
	}, map[string]any{
		"model": "whatever",
		"messages": []map[string]any{
			{"role": "user", "content": "test"},
		},
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if got := body["reason_code"]; got != string(ReasonModelProviderDenied) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonModelProviderDenied, got)
	}
}

func TestOpenAICompat_DestinationAllowlistDenied(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()
	sessionID := "phase3-destination-deny-session"
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	token := issueModelApprovalToken(t, gw, "gpt-4o", spiffeID, sessionID)

	rec := postOpenAICompat(t, handler, map[string]string{
		"X-Model-Provider":    "openai",
		"X-Provider-Endpoint": "https://evil.example.com/v1/chat/completions",
		"X-Residency-Intent":  "us",
		"X-Budget-Profile":    "standard",
		"X-Budget-Units":      "1",
		"X-Session-ID":        sessionID,
		"X-Step-Up-Token":     token,
	}, map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]any{
			{"role": "user", "content": "hello"},
		},
	})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if got := body["reason_code"]; got != string(ReasonModelDestinationDenied) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonModelDestinationDenied, got)
	}
}

func TestBuildModelPlaneRequestFromOpenAI_UsesTrustedContextForRiskCompliance(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	req := httptest.NewRequest(http.MethodPost, openAICompatChatCompletionsPath, bytes.NewBuffer(body))
	req.Header.Set("X-Risk-Mode", "low")               // spoofed downgrade attempt
	req.Header.Set("X-Compliance-Profile", "standard") // spoofed downgrade attempt
	req.Header.Set("X-Step-Up-Approved", "true")       // spoofed approval marker
	req.Header.Set("X-Approval-Marker", "spoofed")

	ctx := req.Context()
	ctx = middleware.WithSessionContextData(ctx, &middleware.AgentSession{
		DataClassifications: []string{"sensitive"},
		RiskScore:           0.7,
	})
	req = req.WithContext(ctx)

	planeReq := gw.buildModelPlaneRequestFromOpenAI(req, map[string]any{
		"model": "gpt-4o",
		"messages": []any{
			map[string]any{"role": "user", "content": "hi"},
		},
	})
	attrs := planeReq.Policy.Attributes

	if got := attrs["risk_mode"]; got != "high" {
		t.Fatalf("expected trusted risk_mode=high, got %v", got)
	}
	if got := attrs["compliance_profile"]; got != "hipaa" {
		t.Fatalf("expected trusted compliance_profile=hipaa, got %v", got)
	}
	if got, _ := attrs["step_up_approved"].(bool); got {
		t.Fatalf("expected step_up_approved=false without trusted step-up context, got %v", attrs["step_up_approved"])
	}
	if got := attrs["approval_marker"]; got != "" {
		t.Fatalf("expected approval_marker empty without trusted step-up context, got %v", got)
	}
}

func TestBuildModelPlaneRequestFromOpenAI_DefaultsSafeWhenTrustedContextMissing(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	req := httptest.NewRequest(http.MethodPost, openAICompatChatCompletionsPath, bytes.NewBuffer(body))
	req.Header.Set("X-Risk-Mode", "low")
	req.Header.Set("X-Compliance-Profile", "standard")

	planeReq := gw.buildModelPlaneRequestFromOpenAI(req, map[string]any{
		"model": "gpt-4o",
		"messages": []any{
			map[string]any{"role": "user", "content": "hi"},
		},
	})
	attrs := planeReq.Policy.Attributes

	if got := attrs["risk_mode"]; got != "high" {
		t.Fatalf("expected safe default risk_mode=high when trusted context missing, got %v", got)
	}
}

func TestBuildModelPlaneRequestFromOpenAI_TrustedStepUpContextSetsApproval(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	req := httptest.NewRequest(http.MethodPost, openAICompatChatCompletionsPath, bytes.NewBuffer(body))
	req.Header.Set("X-Approval-Marker", "trusted-request-id")
	ctx := middleware.WithStepUpResult(req.Context(), &middleware.StepUpGatingResult{
		Allowed: true,
		Gate:    "approval",
	})
	req = req.WithContext(ctx)

	planeReq := gw.buildModelPlaneRequestFromOpenAI(req, map[string]any{
		"model": "gpt-4o",
		"messages": []any{
			map[string]any{"role": "user", "content": "hi"},
		},
	})
	attrs := planeReq.Policy.Attributes

	if got, _ := attrs["step_up_approved"].(bool); !got {
		t.Fatalf("expected step_up_approved=true from trusted step-up context, got %v", attrs["step_up_approved"])
	}
	if got := attrs["approval_marker"]; got != "trusted-request-id" {
		t.Fatalf("expected approval_marker from trusted step-up pass-through, got %v", got)
	}
}

func TestBuildModelPlaneRequestFromOpenAI_ParsesMissionBoundaryHeaders(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	body := []byte(`{"model":"llama-3.3-70b-versatile","messages":[{"role":"user","content":"Where is my order?"}]}`)
	req := httptest.NewRequest(http.MethodPost, openAICompatChatCompletionsPath, bytes.NewBuffer(body))
	req.Header.Set("X-Agent-Purpose", "restaurant_order_support")
	req.Header.Set("X-Mission-Boundary-Mode", "enforce")
	req.Header.Set("X-Mission-Allowed-Intents", "place_order,order_status")
	req.Header.Set("X-Mission-Allowed-Topics", "order,menu")
	req.Header.Set("X-Mission-Blocked-Topics", "python,linked list")
	req.Header.Set("X-Mission-Out-Of-Scope-Action", "rewrite")

	planeReq := gw.buildModelPlaneRequestFromOpenAI(req, map[string]any{
		"model": "llama-3.3-70b-versatile",
		"messages": []any{
			map[string]any{"role": "user", "content": "Where is my order?"},
		},
	})
	attrs := planeReq.Policy.Attributes

	if got := attrs["agent_purpose"]; got != "restaurant_order_support" {
		t.Fatalf("expected agent_purpose header to round-trip, got %v", got)
	}
	if got := attrs["mission_boundary_mode"]; got != "enforce" {
		t.Fatalf("expected mission_boundary_mode=enforce, got %v", got)
	}
	if got := getStringListAttr(attrs, "allowed_intents"); len(got) != 2 || got[0] != "place_order" || got[1] != "order_status" {
		t.Fatalf("expected allowed_intents parsed, got %#v", got)
	}
	if got := getStringListAttr(attrs, "blocked_topics"); len(got) != 2 || got[0] != "python" || got[1] != "linked list" {
		t.Fatalf("expected blocked_topics parsed, got %#v", got)
	}
	if got := attrs["out_of_scope_action"]; got != "rewrite" {
		t.Fatalf("expected out_of_scope_action=rewrite, got %v", got)
	}
}

func TestOpenAICompat_FallbackApplied(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"message":"provider outage"}}`))
	}))
	defer primary.Close()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-fallback","choices":[{"index":0,"message":{"role":"assistant","content":"fallback-ok"}}]}`))
	}))
	defer fallback.Close()

	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()
	sessionID := "phase3-fallback-session"
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	token := issueModelApprovalToken(t, gw, "gpt-4o", spiffeID, sessionID)

	rec := postOpenAICompat(t, handler, map[string]string{
		"X-Model-Provider":                 "openai",
		"X-Provider-Endpoint-OpenAI":       primary.URL,
		"X-Provider-Endpoint-Azure-OpenAI": fallback.URL,
		"X-Residency-Intent":               "us",
		"X-Session-ID":                     sessionID,
		"X-Step-Up-Token":                  token,
	}, map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]any{
			{"role": "user", "content": "hello"},
		},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Precinct-Reason-Code") != string(ReasonModelFallbackApplied) {
		t.Fatalf("expected reason %s, got %s", ReasonModelFallbackApplied, rec.Header().Get("X-Precinct-Reason-Code"))
	}
	if rec.Header().Get("X-Precinct-Provider-Used") != "azure_openai" {
		t.Fatalf("expected fallback provider azure_openai, got %s", rec.Header().Get("X-Precinct-Provider-Used"))
	}
}

func TestOpenAICompat_ModelPolicyIntentProjectionPrepended(t *testing.T) {
	var capturedMessages []any
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var upstreamPayload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&upstreamPayload); err != nil {
			t.Fatalf("decode upstream payload: %v", err)
		}
		capturedMessages, _ = upstreamPayload["messages"].([]any)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-proj","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer provider.Close()

	gw, _ := newPhase3TestGateway(t)
	gw.config.ModelPolicyIntentPrependEnabled = true
	handler := gw.Handler()

	rec := postOpenAICompat(t, handler, map[string]string{
		"Authorization":            "Bearer test-token",
		"X-Model-Provider":         "groq",
		"X-Provider-Endpoint-Groq": provider.URL,
		"X-Residency-Intent":       "us",
		"X-Budget-Profile":         "standard",
		"X-Budget-Units":           "1",
	}, map[string]any{
		"model": "llama-3.3-70b-versatile",
		"messages": []map[string]any{
			{"role": "user", "content": "Hello model"},
		},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Precinct-Policy-Intent-Projection") != "applied" {
		t.Fatalf("expected projection header applied, got %q", rec.Header().Get("X-Precinct-Policy-Intent-Projection"))
	}
	if len(capturedMessages) < 2 {
		t.Fatalf("expected prepended + original messages, got %d", len(capturedMessages))
	}

	first, ok := capturedMessages[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first message object, got %T", capturedMessages[0])
	}
	if role := stringValue(first["role"]); role != "system" {
		t.Fatalf("expected first message role=system, got %q", role)
	}
	content := stringValue(first["content"])
	if !strings.Contains(content, "<policy_intent version=\"1\">") {
		t.Fatalf("expected XML policy intent projection, got %q", content)
	}
	if strings.Contains(strings.ToLower(content), "package ") || strings.Contains(strings.ToLower(content), "rego") {
		t.Fatalf("projection should not disclose policy code, got %q", content)
	}

	second, ok := capturedMessages[1].(map[string]any)
	if !ok {
		t.Fatalf("expected second message object, got %T", capturedMessages[1])
	}
	if text := stringValue(second["content"]); text != "Hello model" {
		t.Fatalf("expected original user message preserved, got %q", text)
	}
}

func TestOpenAICompat_ModelPlaneDenied_PolicyIntentAdvisoryOnly(t *testing.T) {
	upstreamCalled := false
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer provider.Close()

	gw, _ := newPhase3TestGateway(t)
	gw.config.ModelPolicyIntentPrependEnabled = true
	handler := gw.Handler()

	rec := postOpenAICompat(t, handler, map[string]string{
		"X-Model-Provider":         "unknown-provider",
		"X-Provider-Endpoint-Groq": provider.URL,
	}, map[string]any{
		"model": "whatever",
		"messages": []map[string]any{
			{"role": "user", "content": "test"},
		},
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	if upstreamCalled {
		t.Fatal("provider should not be called when model plane denies request")
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	details, _ := body["details"].(map[string]any)
	if got, _ := details["policy_intent_projection_enabled"].(bool); !got {
		t.Fatalf("expected projection_enabled=true in deny details, got %v", details["policy_intent_projection_enabled"])
	}
	if got, _ := details["policy_intent_projection_applied"].(bool); got {
		t.Fatalf("expected projection_applied=false on deny path, got %v", got)
	}
}

func TestOpenAICompat_PolicyIntentProjection_DeterministicAndRedacted(t *testing.T) {
	attrs := map[string]any{
		"provider":              "groq",
		"model":                 "llama-3.3-70b-versatile",
		"residency_intent":      "us",
		"risk_mode":             "high",
		"compliance_profile":    "hipaa",
		"mediation_mode":        "mediated",
		"prompt_has_phi":        true,
		"prompt_has_pii":        true,
		"step_up_approved":      false,
		"agent_purpose":         "restaurant_order_support",
		"mission_boundary_mode": "enforce",
		"allowed_intents":       []string{"place_order", "order_status"},
		"out_of_scope_action":   "rewrite",
		"prompt":                `package mcp_policy default allow = true`,
	}
	envelope := RunEnvelope{ActorSPIFFEID: "spiffe://poc.local/agents/test/prod"}

	first := buildModelPolicyIntentProjection(attrs, envelope)
	second := buildModelPolicyIntentProjection(attrs, envelope)
	if first != second {
		t.Fatalf("expected deterministic projection output, got mismatch\n1=%s\n2=%s", first, second)
	}
	if !strings.Contains(first, "<policy_intent version=\"1\">") {
		t.Fatalf("expected XML envelope, got %q", first)
	}
	if !strings.Contains(first, "<item>phi_disclosure</item>") || !strings.Contains(first, "<item>pii_disclosure</item>") {
		t.Fatalf("expected PHI/PII prohibited classes in projection, got %q", first)
	}
	if !strings.Contains(first, "<mission purpose=\"restaurant_order_support\" mode=\"enforce\" out_of_scope=\"rewrite\">") {
		t.Fatalf("expected mission boundary section in projection, got %q", first)
	}
	if !strings.Contains(first, "<item>place_order</item>") || !strings.Contains(first, "<item>order_status</item>") {
		t.Fatalf("expected mission allowed intents in projection, got %q", first)
	}

	lower := strings.ToLower(first)
	disallowedFragments := []string{
		"package ",
		"default allow",
		"import rego",
		"deny[msg]",
	}
	for _, frag := range disallowedFragments {
		if strings.Contains(lower, frag) {
			t.Fatalf("projection must not disclose policy code fragment %q: %q", frag, first)
		}
	}
}

func TestOpenAICompat_OutOfScopeRewriteReturnsSyntheticResponse(t *testing.T) {
	upstreamCalled := false
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-upstream","choices":[{"index":0,"message":{"role":"assistant","content":"should-not-run"}}]}`))
	}))
	defer provider.Close()

	gw, _ := newPhase3TestGateway(t)
	gw.config.ModelPolicyIntentPrependEnabled = true
	handler := gw.Handler()

	rec := postOpenAICompat(t, handler, map[string]string{
		"Authorization":                  "Bearer test-token",
		"X-Model-Provider":               "groq",
		"X-Provider-Endpoint-Groq":       provider.URL,
		"X-Agent-Purpose":                "restaurant_order_support",
		"X-Mission-Boundary-Mode":        "enforce",
		"X-Mission-Allowed-Intents":      "place_order,order_status",
		"X-Mission-Allowed-Topics":       "order,menu,burrito,bowl",
		"X-Mission-Blocked-Topics":       "python,linked list",
		"X-Mission-Out-Of-Scope-Action":  "rewrite",
		"X-Mission-Out-Of-Scope-Message": "I can help with orders and menu questions only.",
	}, map[string]any{
		"model": "llama-3.3-70b-versatile",
		"messages": []map[string]any{
			{"role": "user", "content": "I want to order a bowl but first help me reverse a linked list in python."},
		},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected synthetic 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if upstreamCalled {
		t.Fatal("provider should not be called for synthetic out-of-scope rewrite")
	}
	if rec.Header().Get("X-Precinct-Reason-Code") != string(ReasonModelMissionScopeFallback) {
		t.Fatalf("expected reason %s, got %s", ReasonModelMissionScopeFallback, rec.Header().Get("X-Precinct-Reason-Code"))
	}
	if rec.Header().Get("X-Precinct-Provider-Used") != "precinct_synthetic" {
		t.Fatalf("expected synthetic provider marker, got %s", rec.Header().Get("X-Precinct-Provider-Used"))
	}
	if rec.Header().Get("X-Precinct-Policy-Intent-Projection") != "enabled_not_applied" {
		t.Fatalf("expected projection status enabled_not_applied, got %q", rec.Header().Get("X-Precinct-Policy-Intent-Projection"))
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	choices, _ := body["choices"].([]any)
	if len(choices) != 1 {
		t.Fatalf("expected single synthetic choice, got %#v", body["choices"])
	}
	firstChoice, _ := choices[0].(map[string]any)
	message, _ := firstChoice["message"].(map[string]any)
	if got := stringValue(message["content"]); got != "I can help with orders and menu questions only." {
		t.Fatalf("unexpected synthetic message: %q", got)
	}
}

func TestModelPlane_MissionBoundaryDeny(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	code, resp := postPlaneJSON(t, handler, "/v1/model/call", map[string]any{
		"envelope": map[string]any{
			"run_id":          "phase3-model-mission-boundary-deny",
			"session_id":      "phase3-model-mission-boundary-session",
			"tenant":          "tenant-a",
			"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"plane":           "model",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "phase3-model-mission-boundary-deny",
				"session_id":      "phase3-model-mission-boundary-session",
				"tenant":          "tenant-a",
				"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				"plane":           "model",
			},
			"action":   "model.call",
			"resource": "model/inference",
			"attributes": map[string]any{
				"provider":              "groq",
				"model":                 "llama-3.3-70b-versatile",
				"agent_purpose":         "restaurant_order_support",
				"mission_boundary_mode": "enforce",
				"allowed_intents":       []string{"place_order", "order_status"},
				"allowed_topics":        []string{"order", "menu"},
				"blocked_topics":        []string{"python", "linked list"},
				"out_of_scope_action":   "deny",
				"prompt":                "Can you help me reverse a linked list in python?",
			},
		},
	})

	if code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonModelMissionScopeDenied) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonModelMissionScopeDenied, resp["reason_code"])
	}
	metadata, _ := resp["metadata"].(map[string]any)
	if got, _ := metadata["mission_boundary_verdict"].(string); got != "out_of_scope" {
		t.Fatalf("expected mission_boundary_verdict=out_of_scope, got %v", metadata["mission_boundary_verdict"])
	}
}

func TestModelPlane_DirectEgressBypassDenied(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	runID := "phase3-model-direct-egress-deny"
	code, resp := postPlaneJSON(t, handler, "/v1/model/call", map[string]any{
		"envelope": map[string]any{
			"run_id":          runID,
			"session_id":      "phase3-model-direct-egress-session",
			"tenant":          "tenant-a",
			"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"plane":           "model",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          runID,
				"session_id":      "phase3-model-direct-egress-session",
				"tenant":          "tenant-a",
				"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				"plane":           "model",
			},
			"action":   "model.call",
			"resource": "model/inference",
			"attributes": map[string]any{
				"provider":       "openai",
				"model":          "gpt-4o",
				"direct_egress":  true,
				"mediation_mode": "direct",
			},
		},
	})

	if code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonModelDirectEgressDeny) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonModelDirectEgressDeny, resp["reason_code"])
	}

	metadata, _ := resp["metadata"].(map[string]any)
	if got, _ := metadata["policy_gate"].(string); got != "direct_egress_blocked" {
		t.Fatalf("expected policy_gate=direct_egress_blocked, got %v", metadata["policy_gate"])
	}
}

// postModelProxy is a generic helper that posts a JSON payload to any model proxy path.
func postModelProxy(t *testing.T, handler http.Handler, path string, headers map[string]string, payload map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// isModelProxyPath unit tests
// ---------------------------------------------------------------------------

func TestIsModelProxyPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/openai/v1/chat/completions", true},
		{"/openai/v1/responses", true},
		{"/v1/messages", true},
		{"/openai/v1/chat/completions/", false},
		{"/v1/messages/", false},
		{"/other", false},
		{"/mcp/v1/call", false},
	}
	for _, tt := range tests {
		if got := isModelProxyPath(tt.path); got != tt.want {
			t.Errorf("isModelProxyPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// OpenAI Responses API (/openai/v1/responses) tests
// ---------------------------------------------------------------------------

func TestResponsesAPI_ModelEgressSuccess(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("expected Authorization header to be forwarded")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp-1","output":[{"type":"message","content":[{"type":"text","text":"ok"}]}]}`))
	}))
	defer provider.Close()

	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	rec := postModelProxy(t, handler, openAICompatResponsesPath, map[string]string{
		"Authorization":            "Bearer test-token",
		"X-Model-Provider":         "groq",
		"X-Provider-Endpoint-Groq": provider.URL,
		"X-Residency-Intent":       "us",
		"X-Budget-Profile":         "standard",
		"X-Budget-Units":           "1",
	}, map[string]any{
		"model": "llama-3.3-70b-versatile",
		"messages": []map[string]any{
			{"role": "user", "content": "Hello model"},
		},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Precinct-Reason-Code") != string(ReasonModelAllow) {
		t.Fatalf("expected reason %s, got %s", ReasonModelAllow, rec.Header().Get("X-Precinct-Reason-Code"))
	}
	if rec.Header().Get("X-Precinct-Provider-Used") != "groq" {
		t.Fatalf("expected provider groq, got %s", rec.Header().Get("X-Precinct-Provider-Used"))
	}
}

func TestResponsesAPI_InvalidJSON(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	req := httptest.NewRequest(http.MethodPost, openAICompatResponsesPath, bytes.NewBufferString(`{invalid`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if got := body["middleware"]; got != "model_plane" {
		t.Fatalf("expected middleware=model_plane, got %v", got)
	}
	if got, ok := body["middleware_step"].(float64); !ok || int(got) != 14 {
		t.Fatalf("expected middleware_step=14, got %v", body["middleware_step"])
	}
}

func TestResponsesAPI_MissingModel(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	rec := postModelProxy(t, handler, openAICompatResponsesPath, map[string]string{}, map[string]any{
		"messages": []map[string]any{
			{"role": "user", "content": "test"},
		},
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if got := body["middleware"]; got != "model_plane" {
		t.Fatalf("expected middleware=model_plane, got %v", got)
	}
	if got, ok := body["middleware_step"].(float64); !ok || int(got) != 14 {
		t.Fatalf("expected middleware_step=14, got %v", body["middleware_step"])
	}
}

func TestResponsesAPI_ModelPlaneDenied(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	rec := postModelProxy(t, handler, openAICompatResponsesPath, map[string]string{
		"X-Model-Provider": "unknown-provider",
	}, map[string]any{
		"model": "whatever",
		"messages": []map[string]any{
			{"role": "user", "content": "test"},
		},
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if got := body["reason_code"]; got != string(ReasonModelProviderDenied) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonModelProviderDenied, got)
	}
}

// ---------------------------------------------------------------------------
// Anthropic Messages API (/v1/messages) tests
// ---------------------------------------------------------------------------

func TestAnthropicMessages_ModelEgressSuccess(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-anthropic-key" {
			t.Fatalf("expected Authorization header to be forwarded")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg-1","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer provider.Close()

	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	rec := postModelProxy(t, handler, anthropicMessagesPath, map[string]string{
		"Authorization":            "Bearer test-anthropic-key",
		"X-Model-Provider":         "groq",
		"X-Provider-Endpoint-Groq": provider.URL,
		"X-Residency-Intent":       "us",
		"X-Budget-Profile":         "standard",
		"X-Budget-Units":           "1",
	}, map[string]any{
		"model":      "llama-3.3-70b-versatile",
		"max_tokens": 1024,
		"messages": []map[string]any{
			{"role": "user", "content": "Hello model"},
		},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Precinct-Reason-Code") != string(ReasonModelAllow) {
		t.Fatalf("expected reason %s, got %s", ReasonModelAllow, rec.Header().Get("X-Precinct-Reason-Code"))
	}
	if rec.Header().Get("X-Precinct-Provider-Used") != "groq" {
		t.Fatalf("expected provider groq, got %s", rec.Header().Get("X-Precinct-Provider-Used"))
	}
}

func TestAnthropicMessages_InvalidJSON(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	req := httptest.NewRequest(http.MethodPost, anthropicMessagesPath, bytes.NewBufferString(`not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if got := body["middleware"]; got != "model_plane" {
		t.Fatalf("expected middleware=model_plane, got %v", got)
	}
	if got, ok := body["middleware_step"].(float64); !ok || int(got) != 14 {
		t.Fatalf("expected middleware_step=14, got %v", body["middleware_step"])
	}
}

func TestAnthropicMessages_MissingModel(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	rec := postModelProxy(t, handler, anthropicMessagesPath, map[string]string{}, map[string]any{
		"max_tokens": 1024,
		"messages": []map[string]any{
			{"role": "user", "content": "test"},
		},
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if got := body["middleware"]; got != "model_plane" {
		t.Fatalf("expected middleware=model_plane, got %v", got)
	}
	if got, ok := body["middleware_step"].(float64); !ok || int(got) != 14 {
		t.Fatalf("expected middleware_step=14, got %v", body["middleware_step"])
	}
}

func TestAnthropicMessages_ModelPlaneDenied(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	rec := postModelProxy(t, handler, anthropicMessagesPath, map[string]string{
		"X-Model-Provider": "unknown-provider",
	}, map[string]any{
		"model": "whatever",
		"messages": []map[string]any{
			{"role": "user", "content": "test"},
		},
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if got := body["reason_code"]; got != string(ReasonModelProviderDenied) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonModelProviderDenied, got)
	}
}

// ---------------------------------------------------------------------------
// Cross-path: all model proxy paths produce logPlaneDecision audit entries
// ---------------------------------------------------------------------------

func TestAllModelProxyPaths_ProduceAuditMetadata(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer provider.Close()

	paths := []struct {
		name string
		path string
	}{
		{"chat_completions", openAICompatChatCompletionsPath},
		{"responses", openAICompatResponsesPath},
		{"anthropic_messages", anthropicMessagesPath},
	}

	for _, tt := range paths {
		t.Run(tt.name, func(t *testing.T) {
			gw, _ := newPhase3TestGateway(t)
			handler := gw.Handler()

			rec := postModelProxy(t, handler, tt.path, map[string]string{
				"Authorization":            "Bearer test-token",
				"X-Model-Provider":         "groq",
				"X-Provider-Endpoint-Groq": provider.URL,
				"X-Residency-Intent":       "us",
				"X-Budget-Profile":         "standard",
				"X-Budget-Units":           "1",
			}, map[string]any{
				"model": "llama-3.3-70b-versatile",
				"messages": []map[string]any{
					{"role": "user", "content": "Hello model"},
				},
			})

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
			}
			// All paths must produce Precinct decision headers (evidence of logPlaneDecision)
			if rec.Header().Get("X-Precinct-Decision-ID") == "" {
				t.Fatal("expected X-Precinct-Decision-ID header from logPlaneDecision")
			}
			if rec.Header().Get("X-Precinct-Trace-ID") == "" {
				t.Fatal("expected X-Precinct-Trace-ID header from logPlaneDecision")
			}
			if rec.Header().Get("X-Precinct-Reason-Code") == "" {
				t.Fatal("expected X-Precinct-Reason-Code header from logPlaneDecision")
			}
			if rec.Header().Get("X-Precinct-Provider-Used") == "" {
				t.Fatal("expected X-Precinct-Provider-Used header from logPlaneDecision")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cross-path: guard model, DLP, rate limiting apply equally (evaluateModelPlaneDecision)
// ---------------------------------------------------------------------------

func TestAllModelProxyPaths_EvaluateModelPlaneDecision(t *testing.T) {
	paths := []struct {
		name string
		path string
	}{
		{"chat_completions", openAICompatChatCompletionsPath},
		{"responses", openAICompatResponsesPath},
		{"anthropic_messages", anthropicMessagesPath},
	}

	for _, tt := range paths {
		t.Run(tt.name+"_unauthenticated", func(t *testing.T) {
			gw, _ := newPhase3TestGateway(t)
			handler := gw.Handler()

			body, _ := json.Marshal(map[string]any{
				"model": "llama-3.3-70b-versatile",
				"messages": []map[string]any{
					{"role": "user", "content": "test"},
				},
			})
			// No X-SPIFFE-ID header -> unauthenticated -> 401
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestModelPlane_RegulatedPromptUsesPhase3DecisionEnvelope(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	code, resp := postPlaneJSON(t, handler, "/v1/model/call", map[string]any{
		"envelope": map[string]any{
			"run_id":          "phase3-compose-1773129666-deny-model",
			"session_id":      "phase3-compose-session-1773129666",
			"tenant":          "tenant-a",
			"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"plane":           "model",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "phase3-compose-1773129666-deny-model",
				"session_id":      "phase3-compose-session-1773129666",
				"tenant":          "tenant-a",
				"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				"plane":           "model",
			},
			"action":   "model.call",
			"resource": "model/inference",
			"attributes": map[string]any{
				"provider":           "openai",
				"model":              "gpt-4o",
				"compliance_profile": "hipaa",
				"model_scope":        "external",
				"prompt_has_phi":     true,
				"prompt_action":      "deny",
				"prompt":             "Patient record with SSN 123-45-6789",
			},
		},
	})

	if code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonPromptSafetyRawDenied) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonPromptSafetyRawDenied, resp["reason_code"])
	}
	if got, _ := resp["middleware"].(string); got == "dlp_scan" {
		t.Fatalf("expected phase3 model decision, got generic dlp response: %v", resp)
	}
	envelope, _ := resp["envelope"].(map[string]any)
	if got, _ := envelope["session_id"].(string); got != "phase3-compose-session-1773129666" {
		t.Fatalf("expected response envelope session_id to round-trip, got %v", envelope["session_id"])
	}
}

// --- SPIKE reference token resolution tests (OC-s1o9) ---

// testSPIKERedeemer is a controllable SecretRedeemer for unit tests.
type testSPIKERedeemer struct {
	secrets map[string]string // ref -> secret value
	err     error             // error to return (simulates SPIKE unavailable)
	called  bool              // whether RedeemSecret was called
	lastRef string            // last ref that was redeemed
}

func (r *testSPIKERedeemer) RedeemSecret(_ context.Context, token *middleware.SPIKEToken) (*middleware.SPIKESecret, error) {
	r.called = true
	r.lastRef = token.Ref
	if r.err != nil {
		return nil, r.err
	}
	val, ok := r.secrets[token.Ref]
	if !ok {
		return nil, fmt.Errorf("secret not found: %s", token.Ref)
	}
	return &middleware.SPIKESecret{Value: val, ExpiresAt: 9999999999}, nil
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Bearer abc123", "abc123"},
		{"bearer abc123", "abc123"},
		{"BEARER abc123", "abc123"},
		{"Bearer spike:ref:groq-api-key", "spike:ref:groq-api-key"},
		{"Bearer ", ""},
		{"", ""},
		{"Basic dXNlcjpwYXNz", ""},
		{"Bear", ""},
		{"Bearer  extra-space-token", "extra-space-token"},
	}

	for _, tt := range tests {
		got := extractBearerToken(tt.input)
		if got != tt.expected {
			t.Errorf("extractBearerToken(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestResolveSPIKEAuthHeader_RegularBearerPassthrough(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	// Set a redeemer that should NOT be called for regular tokens.
	redeemer := &testSPIKERedeemer{secrets: map[string]string{}}
	gw.spikeRedeemer = redeemer

	result, err := gw.resolveSPIKEAuthHeader(context.Background(), "Bearer gsk_real_api_key_abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Bearer gsk_real_api_key_abc123" {
		t.Fatalf("expected passthrough of regular Bearer token, got %q", result)
	}
	if redeemer.called {
		t.Fatal("SPIKE redeemer should NOT be called for regular Bearer tokens")
	}
}

func TestResolveSPIKEAuthHeader_EmptyHeaderPassthrough(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	redeemer := &testSPIKERedeemer{secrets: map[string]string{}}
	gw.spikeRedeemer = redeemer

	result, err := gw.resolveSPIKEAuthHeader(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Fatalf("expected empty passthrough, got %q", result)
	}
	if redeemer.called {
		t.Fatal("SPIKE redeemer should NOT be called for empty auth header")
	}
}

func TestResolveSPIKEAuthHeader_SPIKERefRedeemed(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	redeemer := &testSPIKERedeemer{
		secrets: map[string]string{
			"groq-api-key": "gsk_REAL_SECRET_FROM_SPIKE",
		},
	}
	gw.spikeRedeemer = redeemer

	result, err := gw.resolveSPIKEAuthHeader(context.Background(), "Bearer spike:ref:groq-api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Bearer gsk_REAL_SECRET_FROM_SPIKE" {
		t.Fatalf("expected redeemed Bearer token, got %q", result)
	}
	if !redeemer.called {
		t.Fatal("SPIKE redeemer should have been called")
	}
	if redeemer.lastRef != "groq-api-key" {
		t.Fatalf("expected ref 'groq-api-key', got %q", redeemer.lastRef)
	}
}

func TestResolveSPIKEAuthHeader_SPIKEUnavailable_FailClosed(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	redeemer := &testSPIKERedeemer{
		err: fmt.Errorf("connection refused: SPIKE Nexus unreachable"),
	}
	gw.spikeRedeemer = redeemer

	_, err := gw.resolveSPIKEAuthHeader(context.Background(), "Bearer spike:ref:groq-api-key")
	if err == nil {
		t.Fatal("expected error when SPIKE is unavailable, got nil")
	}
	if !strings.Contains(err.Error(), "SPIKE Nexus redemption failed") {
		t.Fatalf("expected SPIKE redemption error, got: %v", err)
	}
	if !redeemer.called {
		t.Fatal("SPIKE redeemer should have been called")
	}
}

func TestResolveSPIKEAuthHeader_NoRedeemer_FailClosed(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.spikeRedeemer = nil

	_, err := gw.resolveSPIKEAuthHeader(context.Background(), "Bearer spike:ref:groq-api-key")
	if err == nil {
		t.Fatal("expected error when no SPIKE redeemer configured, got nil")
	}
	if !strings.Contains(err.Error(), "no SPIKE redeemer configured") {
		t.Fatalf("expected 'no SPIKE redeemer configured' error, got: %v", err)
	}
}

func TestResolveSPIKEAuthHeader_EmptySPIKERef_FailClosed(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	redeemer := &testSPIKERedeemer{secrets: map[string]string{}}
	gw.spikeRedeemer = redeemer

	_, err := gw.resolveSPIKEAuthHeader(context.Background(), "Bearer spike:ref:")
	if err == nil {
		t.Fatal("expected error for empty SPIKE reference name, got nil")
	}
	if !strings.Contains(err.Error(), "empty SPIKE reference name") {
		t.Fatalf("expected 'empty SPIKE reference name' error, got: %v", err)
	}
}

func TestResolveSPIKEAuthHeader_SPIKEReturnsEmptySecret_FailClosed(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	redeemer := &testSPIKERedeemer{
		secrets: map[string]string{
			"groq-api-key": "", // empty secret value
		},
	}
	gw.spikeRedeemer = redeemer

	_, err := gw.resolveSPIKEAuthHeader(context.Background(), "Bearer spike:ref:groq-api-key")
	if err == nil {
		t.Fatal("expected error when SPIKE returns empty secret, got nil")
	}
	if !strings.Contains(err.Error(), "empty secret") {
		t.Fatalf("expected 'empty secret' error, got: %v", err)
	}
}

func TestOpenAICompat_SPIKERefRedeemed_EndToEnd(t *testing.T) {
	// Upstream provider verifies it receives the REAL API key, not the spike:ref.
	var receivedAuth string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-spike","choices":[{"index":0,"message":{"role":"assistant","content":"spike-ok"}}]}`))
	}))
	defer provider.Close()

	gw, _ := newPhase3TestGateway(t)
	gw.spikeRedeemer = &testSPIKERedeemer{
		secrets: map[string]string{
			"groq-api-key": "gsk_REAL_GROQ_KEY_FROM_SPIKE",
		},
	}
	handler := gw.Handler()

	rec := postOpenAICompat(t, handler, map[string]string{
		"Authorization":            "Bearer spike:ref:groq-api-key",
		"X-Model-Provider":         "groq",
		"X-Provider-Endpoint-Groq": provider.URL,
		"X-Residency-Intent":       "us",
		"X-Budget-Profile":         "standard",
		"X-Budget-Units":           "1",
	}, map[string]any{
		"model": "llama-3.3-70b-versatile",
		"messages": []map[string]any{
			{"role": "user", "content": "Hello from SPIKE ref test"},
		},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	// The upstream provider must receive the real key, NOT the spike:ref token.
	if receivedAuth != "Bearer gsk_REAL_GROQ_KEY_FROM_SPIKE" {
		t.Fatalf("upstream provider received wrong auth header: %q (should be real key, not spike:ref)", receivedAuth)
	}
	if rec.Header().Get("X-Precinct-Provider-Used") != "groq" {
		t.Fatalf("expected provider groq, got %s", rec.Header().Get("X-Precinct-Provider-Used"))
	}
}

func TestOpenAICompat_SPIKEUnavailable_FailClosed_NoFallback(t *testing.T) {
	// When SPIKE is unavailable, the model proxy request MUST fail.
	// No fallback to raw keys, no fallback to empty Authorization header.
	providerCalled := false
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalled = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-should-not-reach","choices":[]}`))
	}))
	defer provider.Close()

	gw, _ := newPhase3TestGateway(t)
	gw.spikeRedeemer = &testSPIKERedeemer{
		err: fmt.Errorf("connection refused: SPIKE Nexus down"),
	}
	handler := gw.Handler()

	rec := postOpenAICompat(t, handler, map[string]string{
		"Authorization":            "Bearer spike:ref:groq-api-key",
		"X-Model-Provider":         "groq",
		"X-Provider-Endpoint-Groq": provider.URL,
		"X-Residency-Intent":       "us",
		"X-Budget-Profile":         "standard",
		"X-Budget-Units":           "1",
	}, map[string]any{
		"model": "llama-3.3-70b-versatile",
		"messages": []map[string]any{
			{"role": "user", "content": "This should fail"},
		},
	})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 when SPIKE unavailable, got %d body=%s", rec.Code, rec.Body.String())
	}
	if providerCalled {
		t.Fatal("upstream provider should NOT be called when SPIKE redemption fails")
	}

	// Verify the error body contains spike_redemption_failed indication.
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	details, _ := body["details"].(map[string]any)
	errorMsg, _ := details["error"].(string)
	if !strings.Contains(errorMsg, "spike_redemption_failed") {
		t.Fatalf("expected spike_redemption_failed in error details, got: %v", details)
	}
}

func TestOpenAICompat_RegularBearerToken_NotIntercepted(t *testing.T) {
	// Regular Bearer tokens (non-spike:ref) should pass through unchanged.
	var receivedAuth string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-regular","choices":[{"index":0,"message":{"role":"assistant","content":"regular-ok"}}]}`))
	}))
	defer provider.Close()

	gw, _ := newPhase3TestGateway(t)
	// Set a redeemer that records if it was called.
	redeemer := &testSPIKERedeemer{secrets: map[string]string{}}
	gw.spikeRedeemer = redeemer
	handler := gw.Handler()

	rec := postOpenAICompat(t, handler, map[string]string{
		"Authorization":            "Bearer gsk_regular_api_key_xyz",
		"X-Model-Provider":         "groq",
		"X-Provider-Endpoint-Groq": provider.URL,
		"X-Residency-Intent":       "us",
		"X-Budget-Profile":         "standard",
		"X-Budget-Units":           "1",
	}, map[string]any{
		"model": "llama-3.3-70b-versatile",
		"messages": []map[string]any{
			{"role": "user", "content": "Regular token test"},
		},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if receivedAuth != "Bearer gsk_regular_api_key_xyz" {
		t.Fatalf("regular Bearer token should pass through unchanged, got %q", receivedAuth)
	}
	if redeemer.called {
		t.Fatal("SPIKE redeemer should NOT be called for regular Bearer tokens")
	}
}

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
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
		"provider":           "groq",
		"model":              "llama-3.3-70b-versatile",
		"residency_intent":   "us",
		"risk_mode":          "high",
		"compliance_profile": "hipaa",
		"mediation_mode":     "mediated",
		"prompt_has_phi":     true,
		"prompt_has_pii":     true,
		"step_up_approved":   false,
		"prompt":             `package mcp_policy default allow = true`,
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

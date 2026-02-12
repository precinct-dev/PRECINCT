package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
	if rec.Header().Get("X-UASGS-Reason-Code") != string(ReasonModelAllow) {
		t.Fatalf("expected reason %s, got %s", ReasonModelAllow, rec.Header().Get("X-UASGS-Reason-Code"))
	}
	if rec.Header().Get("X-UASGS-Provider-Used") != "groq" {
		t.Fatalf("expected provider groq, got %s", rec.Header().Get("X-UASGS-Provider-Used"))
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

	rec := postOpenAICompat(t, handler, map[string]string{
		"X-Model-Provider":    "openai",
		"X-Provider-Endpoint": "https://evil.example.com/v1/chat/completions",
		"X-Residency-Intent":  "us",
		"X-Budget-Profile":    "standard",
		"X-Budget-Units":      "1",
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

	rec := postOpenAICompat(t, handler, map[string]string{
		"X-Model-Provider":                 "openai",
		"X-Provider-Endpoint-OpenAI":       primary.URL,
		"X-Provider-Endpoint-Azure-OpenAI": fallback.URL,
		"X-Residency-Intent":               "us",
	}, map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]any{
			{"role": "user", "content": "hello"},
		},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-UASGS-Reason-Code") != string(ReasonModelFallbackApplied) {
		t.Fatalf("expected reason %s, got %s", ReasonModelFallbackApplied, rec.Header().Get("X-UASGS-Reason-Code"))
	}
	if rec.Header().Get("X-UASGS-Provider-Used") != "azure_openai" {
		t.Fatalf("expected fallback provider azure_openai, got %s", rec.Header().Get("X-UASGS-Provider-Used"))
	}
}

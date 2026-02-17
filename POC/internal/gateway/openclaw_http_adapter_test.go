package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func postOpenClawHTTP(
	t *testing.T,
	handler http.Handler,
	path string,
	headers map[string]string,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestOpenClawHTTP_OpenResponsesSuccess(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl_1",
			"choices":[{"index":0,"message":{"role":"assistant","content":"OpenClaw wrapped response"}}],
			"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}
		}`))
	}))
	defer provider.Close()

	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	rec := postOpenClawHTTP(t, handler, "/v1/responses", map[string]string{
		"X-SPIFFE-ID":              "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"X-Model-Provider":         "groq",
		"X-Provider-Endpoint-Groq": provider.URL,
		"X-Residency-Intent":       "us",
		"X-Budget-Profile":         "standard",
		"X-Budget-Units":           "1",
		"X-Compliance-Profile":     "standard",
		"X-UASGS-Test-Correlation": "openclaw-http-responses",
	}, `{
		"model":"llama-3.3-70b-versatile",
		"input":"Summarize this policy decision."
	}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-UASGS-Reason-Code"); got != string(ReasonModelAllow) {
		t.Fatalf("expected reason %s, got %s", ReasonModelAllow, got)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if got, _ := body["object"].(string); got != "response" {
		t.Fatalf("expected object=response, got %q", got)
	}
	if got, _ := body["status"].(string); got != "completed" {
		t.Fatalf("expected status=completed, got %q", got)
	}
}

func TestOpenClawHTTP_ToolsInvokeAllowed(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	rec := postOpenClawHTTP(t, handler, "/tools/invoke", map[string]string{
		"X-SPIFFE-ID": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
	}, `{
		"tool":"read",
		"action":"tool.execute",
		"args":{"path":"/tmp/demo.txt"}
	}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-UASGS-Reason-Code"); got != string(ReasonToolAllow) {
		t.Fatalf("expected reason %s, got %s", ReasonToolAllow, got)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	ok, _ := body["ok"].(bool)
	if !ok {
		t.Fatalf("expected ok=true, got body=%v", body)
	}
}

func TestOpenClawHTTP_UnauthenticatedDenied(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	rec := postOpenClawHTTP(t, handler, "/v1/responses", nil, `{
		"model":"llama-3.3-70b-versatile",
		"input":"test"
	}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without SPIFFE identity, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOpenClawHTTP_DangerousToolDenied(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()

	rec := postOpenClawHTTP(t, handler, "/tools/invoke", map[string]string{
		"X-SPIFFE-ID": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
	}, `{
		"tool":"sessions_spawn",
		"args":{"command":"rm -rf /"}
	}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for dangerous tool, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-UASGS-Reason-Code"); got != string(ReasonToolCLICommandDenied) {
		t.Fatalf("expected reason %s, got %s", ReasonToolCLICommandDenied, got)
	}
}

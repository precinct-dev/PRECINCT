package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestV24AdminAuthRequiredUsesUnifiedEnvelope(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)

	req, err := http.NewRequest(http.MethodPost, baseURL+"/admin/dlp/rulesets/create", bytes.NewBufferString(`{"ruleset_id":"rs-authz"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%v", resp.StatusCode, body)
	}
	if got := stringField(body["code"]); got != "auth_missing_identity" {
		t.Fatalf("expected code auth_missing_identity, got %q body=%v", got, body)
	}
	if got := stringField(body["middleware"]); got != "spiffe_auth" {
		t.Fatalf("expected middleware spiffe_auth, got %q body=%v", got, body)
	}
}

func TestV24PlaneContractFailureIncludesTelemetryFields(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)

	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/context/admit", bytes.NewBufferString("{invalid json"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%v", resp.StatusCode, body)
	}
	if got := stringField(body["code"]); got != "mcp_invalid_request" {
		t.Fatalf("expected code mcp_invalid_request, got %q body=%v", got, body)
	}
	if got := stringField(body["middleware"]); got != "v24_phase3_plane" {
		t.Fatalf("expected middleware v24_phase3_plane, got %q body=%v", got, body)
	}
	if got := intField(body["middleware_step"]); got != 16 {
		t.Fatalf("expected middleware_step 16, got %d body=%v", got, body)
	}
	if stringField(body["decision_id"]) == "" || stringField(body["trace_id"]) == "" {
		t.Fatalf("expected decision_id and trace_id in unified envelope body=%v", body)
	}
}

func intField(v any) int {
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	default:
		return 0
	}
}

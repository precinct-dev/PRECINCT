// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

// Demo-extracted mission-bound model mediation integration tests.
// Extracts deterministic mission-boundary assertions from the model plane into
// httptest-based integration tests that run in CI without Docker Compose.
//
// Covers demo assertions:
// - Mission boundary enforcement with blocked_topics triggers synthetic fallback
// - No outbound provider call is made when prompt is out-of-scope
// - Response metadata contains mission_boundary_verdict=out_of_scope

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/testutil"
)

// newMissionBoundTestGateway creates a real Gateway wired with all middleware
// for mission-bound model mediation integration tests. The provider endpoint
// is set to an unreachable address to prove no outbound call is made on the
// synthetic fallback path.
func newMissionBoundTestGateway(t *testing.T) (*httptest.Server, string) {
	t.Helper()

	tmpDir := t.TempDir()
	destinationsPath := filepath.Join(tmpDir, "destinations.yaml")
	if err := os.WriteFile(destinationsPath, []byte("allowed_destinations:\n  - \"127.0.0.1\"\n  - \"localhost\"\n  - \"::1\"\n"), 0644); err != nil {
		t.Fatalf("write destinations config: %v", err)
	}

	cfg := &gateway.Config{
		Port:                   0,
		UpstreamURL:            "http://localhost:8080",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		AdminAuthzAllowedSPIFFEIDs: []string{
			adminSPIFFEIDForTest(),
		},
		DestinationsConfigPath:          destinationsPath,
		RateLimitRPM:                    100000,
		RateLimitBurst:                  100000,
		ModelPolicyIntentPrependEnabled: true,
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	return srv, srv.URL
}

// postOpenAICompatRequest sends a POST to the OpenAI-compatible chat completions
// endpoint with the given headers and payload. This mirrors the unit test helper
// but works against an httptest.Server URL from the integration package.
func postOpenAICompatRequest(t *testing.T, baseURL string, headers map[string]string, payload map[string]any) *http.Response {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/openai/v1/chat/completions", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// Mission boundary: out-of-scope prompt triggers synthetic fallback (rewrite)
// ---------------------------------------------------------------------------

// TestDemoExtracted_MissionBound_OutOfScopeRewriteSyntheticFallback verifies
// that when mission_boundary_mode=enforce and the prompt matches a blocked_topic,
// the gateway returns HTTP 200 with a synthetic fallback response instead of
// forwarding the request to the upstream model provider.
//
// Proof that no outbound provider call is made: the provider endpoint is set to
// an unreachable address (http://192.0.2.1:1 -- RFC 5737 TEST-NET, guaranteed
// unroutable). If the gateway attempted to call the provider, the request would
// fail with a connection error instead of returning the synthetic 200.
func TestDemoExtracted_MissionBound_OutOfScopeRewriteSyntheticFallback(t *testing.T) {
	_, baseURL := newMissionBoundTestGateway(t)

	// Use RFC 5737 TEST-NET address as unreachable provider endpoint.
	// This proves no outbound call is attempted on the synthetic path.
	unreachableEndpoint := "http://192.0.2.1:1/v1/chat/completions"

	resp := postOpenAICompatRequest(t, baseURL, map[string]string{
		"Authorization":                  "Bearer test-token",
		"X-Model-Provider":               "groq",
		"X-Provider-Endpoint-Groq":       unreachableEndpoint,
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
			{"role": "user", "content": "Help me reverse a linked list in python."},
		},
	})
	defer resp.Body.Close()

	// AC 1: HTTP 200 with synthetic fallback content
	if resp.StatusCode != http.StatusOK {
		var errBody json.RawMessage
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("expected HTTP 200 (synthetic fallback), got %d body=%s", resp.StatusCode, string(errBody))
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}

	// Verify synthetic response structure (OpenAI chat.completion format)
	choices, ok := body["choices"].([]any)
	if !ok || len(choices) == 0 {
		t.Fatalf("expected choices array in synthetic response, got %#v", body["choices"])
	}
	firstChoice, ok := choices[0].(map[string]any)
	if !ok {
		t.Fatalf("expected choice object, got %T", choices[0])
	}
	message, ok := firstChoice["message"].(map[string]any)
	if !ok {
		t.Fatalf("expected message object in choice, got %T", firstChoice["message"])
	}
	content, ok := message["content"].(string)
	if !ok || content == "" {
		t.Fatalf("expected non-empty content in synthetic message, got %v", message["content"])
	}
	if content != "I can help with orders and menu questions only." {
		t.Fatalf("expected custom out-of-scope message, got %q", content)
	}

	// AC 2: Provider header confirms synthetic response
	providerUsed := resp.Header.Get("X-Precinct-Provider-Used")
	if providerUsed != "precinct_synthetic" {
		t.Fatalf("expected provider=precinct_synthetic, got %q", providerUsed)
	}

	// AC 3: Reason code confirms mission scope fallback
	reasonCode := resp.Header.Get("X-Precinct-Reason-Code")
	if reasonCode != "MODEL_MISSION_SCOPE_SAFE_FALLBACK_APPLIED" {
		t.Fatalf("expected reason=MODEL_MISSION_SCOPE_SAFE_FALLBACK_APPLIED, got %q", reasonCode)
	}

	t.Logf("PASS: Out-of-scope prompt returned synthetic fallback (HTTP 200, provider=%s, reason=%s)", providerUsed, reasonCode)
}

// ---------------------------------------------------------------------------
// Mission boundary: blocked topic triggers out_of_scope verdict metadata
// ---------------------------------------------------------------------------

// TestDemoExtracted_MissionBound_BlockedTopicDenyVerdict verifies that when
// mission_boundary_mode=enforce with out_of_scope_action=deny (default), the
// gateway returns HTTP 403 with mission_boundary_verdict=out_of_scope in the
// response metadata. This tests the deny path (as opposed to the rewrite path
// tested above).
func TestDemoExtracted_MissionBound_BlockedTopicDenyVerdict(t *testing.T) {
	_, baseURL := newMissionBoundTestGateway(t)

	unreachableEndpoint := "http://192.0.2.1:1/v1/chat/completions"

	resp := postOpenAICompatRequest(t, baseURL, map[string]string{
		"Authorization":             "Bearer test-token",
		"X-Model-Provider":          "groq",
		"X-Provider-Endpoint-Groq":  unreachableEndpoint,
		"X-Agent-Purpose":           "restaurant_order_support",
		"X-Mission-Boundary-Mode":   "enforce",
		"X-Mission-Allowed-Intents": "place_order,order_status",
		"X-Mission-Allowed-Topics":  "order,menu",
		"X-Mission-Blocked-Topics":  "python,linked list",
		// out_of_scope_action defaults to "deny" when not set
	}, map[string]any{
		"model": "llama-3.3-70b-versatile",
		"messages": []map[string]any{
			{"role": "user", "content": "Can you help me reverse a linked list in python?"},
		},
	})
	defer resp.Body.Close()

	// Deny path returns 403 from model plane
	if resp.StatusCode != http.StatusForbidden {
		var errBody json.RawMessage
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("expected HTTP 403, got %d body=%s", resp.StatusCode, string(errBody))
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}

	// Verify mission_boundary_verdict=out_of_scope in response details
	details, _ := body["details"].(map[string]any)
	verdict, _ := details["mission_boundary_verdict"].(string)
	if verdict != "out_of_scope" {
		t.Fatalf("expected metadata.mission_boundary_verdict=out_of_scope, got %q (details=%v)", verdict, details)
	}

	// Verify reason code
	reasonCode, _ := body["reason_code"].(string)
	if reasonCode != "MODEL_MISSION_SCOPE_DENIED" {
		t.Fatalf("expected reason_code=MODEL_MISSION_SCOPE_DENIED, got %q", reasonCode)
	}

	// Verify blocked terms are recorded
	matchedBlocked, _ := details["matched_blocked_terms"].([]any)
	if len(matchedBlocked) == 0 {
		t.Fatalf("expected matched_blocked_terms to contain entries, got %v", matchedBlocked)
	}

	t.Logf("PASS: Blocked topic returned 403 with verdict=out_of_scope, matched_blocked=%v", matchedBlocked)
}

// ---------------------------------------------------------------------------
// Mission boundary: in-scope prompt passes through normally
// ---------------------------------------------------------------------------

// TestDemoExtracted_MissionBound_InScopePromptAllowed verifies that when
// mission_boundary_mode=enforce but the prompt is on-topic (matches allowed
// topics, does not match blocked topics), the request passes through to the
// model provider. We use a local httptest server as the provider to confirm
// the request actually reaches the provider.
func TestDemoExtracted_MissionBound_InScopePromptAllowed(t *testing.T) {
	providerCalled := false
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalled = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-mission-ok","choices":[{"index":0,"message":{"role":"assistant","content":"Your order is on the way!"}}]}`))
	}))
	defer provider.Close()

	_, baseURL := newMissionBoundTestGateway(t)

	resp := postOpenAICompatRequest(t, baseURL, map[string]string{
		"Authorization":             "Bearer test-token",
		"X-Model-Provider":          "groq",
		"X-Provider-Endpoint-Groq":  provider.URL,
		"X-Agent-Purpose":           "restaurant_order_support",
		"X-Mission-Boundary-Mode":   "enforce",
		"X-Mission-Allowed-Intents": "place_order,order_status",
		"X-Mission-Allowed-Topics":  "order,menu,burrito,bowl",
		"X-Mission-Blocked-Topics":  "python,linked list",
	}, map[string]any{
		"model": "llama-3.3-70b-versatile",
		"messages": []map[string]any{
			{"role": "user", "content": "What is the status of my order?"},
		},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody json.RawMessage
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("expected HTTP 200 for in-scope prompt, got %d body=%s", resp.StatusCode, string(errBody))
	}

	if !providerCalled {
		t.Fatal("expected provider to be called for in-scope prompt, but it was not")
	}

	// Verify the response came from the real provider
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	choices, _ := body["choices"].([]any)
	if len(choices) == 0 {
		t.Fatalf("expected choices from provider response, got %v", body)
	}
	first, _ := choices[0].(map[string]any)
	msg, _ := first["message"].(map[string]any)
	if got, _ := msg["content"].(string); !strings.Contains(got, "order") {
		t.Fatalf("expected provider content about order, got %q", got)
	}

	providerUsed := resp.Header.Get("X-Precinct-Provider-Used")
	if providerUsed != "groq" {
		t.Fatalf("expected provider=groq, got %q", providerUsed)
	}

	t.Logf("PASS: In-scope prompt forwarded to provider (HTTP %d, provider=%s)", resp.StatusCode, providerUsed)
}

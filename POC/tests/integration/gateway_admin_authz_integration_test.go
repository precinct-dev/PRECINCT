//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

func TestGatewayAdminAuthzIntegration_LegacyAndV24AdminPaths(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "legacy-circuit-breakers",
			method: http.MethodGet,
			path:   "/admin/circuit-breakers",
		},
		{
			name:   "v24-ruleops",
			method: http.MethodGet,
			path:   "/admin/dlp/rulesets",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, body := doAdminRequest(t, baseURL, tc.method, tc.path, "")
			if status != http.StatusUnauthorized {
				t.Fatalf("expected 401 without identity, got %d body=%v", status, body)
			}
			if got, _ := body["code"].(string); got != middleware.ErrAuthMissingIdentity {
				t.Fatalf("expected code=%q, got %q body=%v", middleware.ErrAuthMissingIdentity, got, body)
			}

			status, body = doAdminRequest(t, baseURL, tc.method, tc.path, "spiffe://poc.local/agents/unauthorized/dev")
			if status != http.StatusForbidden {
				t.Fatalf("expected 403 for unauthorized identity, got %d body=%v", status, body)
			}
			if got, _ := body["code"].(string); got != middleware.ErrAuthzPolicyDenied {
				t.Fatalf("expected code=%q, got %q body=%v", middleware.ErrAuthzPolicyDenied, got, body)
			}

			status, body = doAdminRequest(t, baseURL, tc.method, tc.path, "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
			if status != http.StatusOK {
				t.Fatalf("expected 200 for authorized identity, got %d body=%v", status, body)
			}
		})
	}
}

func doAdminRequest(t *testing.T, baseURL, method, path, spiffeID string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, baseURL+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if spiffeID != "" {
		req.Header.Set("X-SPIFFE-ID", spiffeID)
	}

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

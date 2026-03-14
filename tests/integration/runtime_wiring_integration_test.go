package integration

import "testing"

func TestV24GovernanceEntrypointsReachable(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"

	getChecks := []struct {
		name string
		path string
	}{
		{name: "ruleops summary", path: "/admin/dlp/rulesets"},
		{name: "approvals summary", path: "/admin/approvals"},
		{name: "breakglass status", path: "/admin/breakglass/status"},
		{name: "profiles status", path: "/admin/profiles/status"},
		{name: "loop runs", path: "/admin/loop/runs"},
		{name: "connector report", path: "/v1/connectors/report"},
	}

	for _, tc := range getChecks {
		t.Run(tc.name, func(t *testing.T) {
			code, body := ruleOpsGet(t, baseURL+tc.path)
			if code != 200 {
				t.Fatalf("%s expected 200, got %d body=%v", tc.path, code, body)
			}
		})
	}

	t.Run("approval request operation", func(t *testing.T) {
		code, body := ruleOpsPost(t, baseURL+"/admin/approvals/request", map[string]any{
			"scope": map[string]any{
				"action":          "tool.execute",
				"resource":        "tool/read",
				"actor_spiffe_id": spiffeID,
				"session_id":      "wiring-it-approval-session",
			},
			"requested_by": "integration@test",
			"reason":       "wiring-check",
			"ttl_seconds":  120,
		})
		if code != 200 {
			t.Fatalf("approval request expected 200, got %d body=%v", code, body)
		}
	})

	t.Run("breakglass request operation", func(t *testing.T) {
		code, body := ruleOpsPost(t, baseURL+"/admin/breakglass/request", map[string]any{
			"incident_id": "INC-WIRING-001",
			"scope": map[string]any{
				"action":           "model.call",
				"resource":         "gpt-4o",
				"actor_spiffe_id":  spiffeID,
				"allowed_sessions": []any{"wiring-it-breakglass-session"},
			},
			"requested_by": "integration@test",
			"reason":       "wiring-check",
			"ttl_seconds":  120,
		})
		if code != 200 {
			t.Fatalf("breakglass request expected 200, got %d body=%v", code, body)
		}
	})

	t.Run("ruleops create operation", func(t *testing.T) {
		code, body := ruleOpsPost(t, baseURL+"/admin/dlp/rulesets/create", map[string]any{
			"ruleset_id": "wiring-ruleset",
			"content": map[string]any{
				"version": "1.0",
				"rules": []any{
					map[string]any{
						"id":      "deny-phi",
						"pattern": "(?i)ssn",
						"action":  "deny",
					},
				},
			},
			"created_by": "integration@test",
		})
		if code != 200 {
			t.Fatalf("ruleops create expected 200, got %d body=%v", code, body)
		}
	})
}

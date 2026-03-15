package compliance

import "testing"

func TestMatchesQuery_SupportedPatterns(t *testing.T) {
	entry := map[string]any{
		"spiffe_id":   "spiffe://poc.local/agents/example",
		"action":      "mcp_request",
		"status_code": 403,
		"security": map[string]any{
			"tool_hash_verified": true,
		},
		"result": "total_score=42",
	}

	cases := []struct {
		name  string
		query string
		want  bool
	}{
		{"not_null", ".spiffe_id != null", true},
		{"not_empty", `.spiffe_id != ""`, true},
		{"eq_string", `.action == "mcp_request"`, true},
		{"eq_number", `.status_code == 403`, true},
		{"startswith", `.spiffe_id | startswith("spiffe://")`, true},
		{"contains", `.result | contains("total_score")`, true},
		{"nested_not_null", `.security.tool_hash_verified != null`, true},
		{"compound_and", `.action == "mcp_request" and .status_code == 403`, true},
		{"false_case", `.status_code == 200`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesQuery(entry, tc.query)
			if got != tc.want {
				t.Fatalf("MatchesQuery(%q)=%v, want %v", tc.query, got, tc.want)
			}
		})
	}
}


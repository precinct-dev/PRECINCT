package openclaw

import (
	"testing"
)

func TestGetStringParam(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string]any
		key      string
		expected string
	}{
		{
			name:     "present_string",
			params:   map[string]any{"platform": "whatsapp"},
			key:      "platform",
			expected: "whatsapp",
		},
		{
			name:     "trimmed",
			params:   map[string]any{"platform": "  whatsapp  "},
			key:      "platform",
			expected: "whatsapp",
		},
		{
			name:     "missing_key",
			params:   map[string]any{"other": "value"},
			key:      "platform",
			expected: "",
		},
		{
			name:     "nil_params",
			params:   nil,
			key:      "platform",
			expected: "",
		},
		{
			name:     "non_string_value",
			params:   map[string]any{"platform": 42},
			key:      "platform",
			expected: "",
		},
		{
			name:     "empty_string",
			params:   map[string]any{"platform": "   "},
			key:      "platform",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getStringParam(tc.params, tc.key)
			if got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestWSAllowed_MessageSend(t *testing.T) {
	tests := []struct {
		name    string
		session wsSession
		allowed bool
	}{
		{
			name: "operator_allowed",
			session: wsSession{
				Connected: true,
				Role:      "operator",
				Scopes:    map[string]struct{}{},
			},
			allowed: true,
		},
		{
			name: "node_with_scope",
			session: wsSession{
				Connected: true,
				Role:      "node",
				Scopes:    map[string]struct{}{"tools.messaging.send": {}},
			},
			allowed: true,
		},
		{
			name: "node_without_scope",
			session: wsSession{
				Connected: true,
				Role:      "node",
				Scopes:    map[string]struct{}{},
			},
			allowed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := wsAllowed(tc.session, "message.send")
			if got != tc.allowed {
				t.Fatalf("expected %v, got %v", tc.allowed, got)
			}
		})
	}
}

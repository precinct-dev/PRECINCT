package middleware

import (
	"testing"
	"time"
)

func TestSessionContextGetOrCreateSession(t *testing.T) {
	sc := NewSessionContext(NewInMemoryStore())

	spiffeID := "spiffe://example.org/agent/test"
	sessionID := "session-123"

	// First call should create new session
	session1 := sc.GetOrCreateSession(spiffeID, sessionID)
	if session1.ID != sessionID {
		t.Errorf("Expected session ID %s, got %s", sessionID, session1.ID)
	}
	if session1.SPIFFEID != spiffeID {
		t.Errorf("Expected SPIFFE ID %s, got %s", spiffeID, session1.SPIFFEID)
	}

	// Second call should return same session
	session2 := sc.GetOrCreateSession(spiffeID, sessionID)
	if session1 != session2 {
		t.Error("Expected same session instance")
	}
}

func TestRecordAction(t *testing.T) {
	sc := NewSessionContext(NewInMemoryStore())
	session := sc.GetOrCreateSession("spiffe://example.org/agent/test", "session-123")

	action := ToolAction{
		Timestamp:      time.Now(),
		Tool:           "database_query",
		Resource:       "users_table",
		Classification: "sensitive",
		ExternalTarget: false,
	}

	sc.RecordAction(session, action)

	if len(session.Actions) != 1 {
		t.Errorf("Expected 1 action, got %d", len(session.Actions))
	}
	if session.Actions[0].Tool != "database_query" {
		t.Errorf("Expected tool database_query, got %s", session.Actions[0].Tool)
	}
	if !contains(session.DataClassifications, "sensitive") {
		t.Error("Expected 'sensitive' in data classifications")
	}
}

func TestDetectsExfiltrationPattern(t *testing.T) {
	tests := []struct {
		name     string
		actions  []ToolAction
		expected bool
	}{
		{
			name: "NoExfiltration_InternalToolsOnly",
			actions: []ToolAction{
				{Tool: "database_query", Classification: "internal", ExternalTarget: false},
				{Tool: "file_read", Classification: "internal", ExternalTarget: false},
			},
			expected: false,
		},
		{
			name: "NoExfiltration_ExternalButNoSensitiveData",
			actions: []ToolAction{
				{Tool: "database_query", Classification: "public", ExternalTarget: false},
				{Tool: "email_send", Classification: "public", ExternalTarget: true},
			},
			expected: false,
		},
		{
			name: "Exfiltration_SensitiveDataThenExternal",
			actions: []ToolAction{
				{Tool: "database_query", Classification: "sensitive", ExternalTarget: false},
				{Tool: "email_send", Classification: "", ExternalTarget: true},
			},
			expected: true,
		},
		{
			name: "Exfiltration_LookbackWindow",
			actions: []ToolAction{
				{Tool: "database_query", Classification: "sensitive", ExternalTarget: false},
				{Tool: "file_read", Classification: "internal", ExternalTarget: false},
				{Tool: "file_read", Classification: "internal", ExternalTarget: false},
				{Tool: "file_read", Classification: "internal", ExternalTarget: false},
				{Tool: "file_read", Classification: "internal", ExternalTarget: false},
				{Tool: "email_send", Classification: "", ExternalTarget: true},
			},
			expected: true,
		},
		{
			name: "NoExfiltration_BeyondLookbackWindow",
			actions: []ToolAction{
				{Tool: "database_query", Classification: "sensitive", ExternalTarget: false},
				{Tool: "file_read", Classification: "internal", ExternalTarget: false},
				{Tool: "file_read", Classification: "internal", ExternalTarget: false},
				{Tool: "file_read", Classification: "internal", ExternalTarget: false},
				{Tool: "file_read", Classification: "internal", ExternalTarget: false},
				{Tool: "file_read", Classification: "internal", ExternalTarget: false},
				{Tool: "file_read", Classification: "internal", ExternalTarget: false},
				{Tool: "email_send", Classification: "", ExternalTarget: true},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := NewSessionContext(NewInMemoryStore())
			session := sc.GetOrCreateSession("spiffe://example.org/agent/test", "session-123")

			// Record all actions
			for _, action := range tt.actions {
				sc.RecordAction(session, action)
			}

			result := sc.DetectsExfiltrationPattern(session)
			if result != tt.expected {
				t.Errorf("Expected exfiltration detection %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestComputeActionRisk(t *testing.T) {
	tests := []struct {
		name          string
		action        ToolAction
		expectedRisk  float64
		riskThreshold float64 // acceptable difference
	}{
		{
			name: "InternalNonSensitive",
			action: ToolAction{
				Classification: "internal",
				ExternalTarget: false,
			},
			expectedRisk:  0.1,
			riskThreshold: 0.01,
		},
		{
			name: "SensitiveInternal",
			action: ToolAction{
				Classification: "sensitive",
				ExternalTarget: false,
			},
			expectedRisk:  0.3,
			riskThreshold: 0.01,
		},
		{
			name: "SensitiveExternal",
			action: ToolAction{
				Classification: "sensitive",
				ExternalTarget: true,
			},
			expectedRisk:  0.5, // 0.3 + 0.2
			riskThreshold: 0.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := computeActionRisk(tt.action)
			if risk < tt.expectedRisk-tt.riskThreshold || risk > tt.expectedRisk+tt.riskThreshold {
				t.Errorf("Expected risk ~%f, got %f", tt.expectedRisk, risk)
			}
		})
	}
}

func TestClassifyResource(t *testing.T) {
	tests := []struct {
		resource string
		expected string
	}{
		{"", "public"},
		{"users_table", "internal"},
		{"user_passwords", "sensitive"},
		{"api_key_store", "sensitive"},
		{"config.json", "internal"},
	}

	for _, tt := range tests {
		t.Run(tt.resource, func(t *testing.T) {
			result := classifyResource(tt.resource)
			if result != tt.expected {
				t.Errorf("Expected classification %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestIsExternalTarget(t *testing.T) {
	tests := []struct {
		name           string
		tool           string
		params         map[string]interface{}
		expectedExt    bool
		expectedDomain string
	}{
		{
			name:           "EmailSend",
			tool:           "email_send",
			params:         map[string]interface{}{"destination": "user@example.com"},
			expectedExt:    true,
			expectedDomain: "user@example.com",
		},
		{
			name:           "HTTPRequest",
			tool:           "http_request",
			params:         map[string]interface{}{"url": "https://api.example.com"},
			expectedExt:    true,
			expectedDomain: "https://api.example.com",
		},
		{
			name:        "InternalTool",
			tool:        "database_query",
			params:      map[string]interface{}{},
			expectedExt: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isExt, domain := isExternalTarget(tt.tool, tt.params)
			if isExt != tt.expectedExt {
				t.Errorf("Expected external %v, got %v", tt.expectedExt, isExt)
			}
			if domain != tt.expectedDomain {
				t.Errorf("Expected domain %s, got %s", tt.expectedDomain, domain)
			}
		})
	}
}

func TestRiskScoreAccumulation(t *testing.T) {
	sc := NewSessionContext(NewInMemoryStore())
	session := sc.GetOrCreateSession("spiffe://example.org/agent/test", "session-123")

	// Record multiple actions
	actions := []ToolAction{
		{Classification: "internal", ExternalTarget: false},  // 0.1
		{Classification: "sensitive", ExternalTarget: false}, // 0.3
		{Classification: "internal", ExternalTarget: true},   // 0.3 (0.1 + 0.2)
	}

	expectedRisk := 0.7
	for _, action := range actions {
		sc.RecordAction(session, action)
	}

	if session.RiskScore < expectedRisk-0.01 || session.RiskScore > expectedRisk+0.01 {
		t.Errorf("Expected risk score ~%f, got %f", expectedRisk, session.RiskScore)
	}
}

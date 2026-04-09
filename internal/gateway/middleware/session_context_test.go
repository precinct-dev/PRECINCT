// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
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

// ---------------------------------------------------------------------------
// OC-3nnm: Session-to-SPIFFE identity binding tests
// ---------------------------------------------------------------------------

func TestBindSessionToIdentity_Deterministic(t *testing.T) {
	spiffeID := "spiffe://example.org/agent/alpha"
	sessionID := "550e8400-e29b-41d4-a716-446655440000"

	// Same inputs must produce the same output
	bound1 := BindSessionToIdentity(spiffeID, sessionID)
	bound2 := BindSessionToIdentity(spiffeID, sessionID)

	if bound1 != bound2 {
		t.Errorf("BindSessionToIdentity is not deterministic: %s != %s", bound1, bound2)
	}

	// Output should be a 64-char hex string (SHA-256 = 32 bytes = 64 hex chars)
	if len(bound1) != 64 {
		t.Errorf("Expected 64-char hex string, got %d chars: %s", len(bound1), bound1)
	}
}

func TestBindSessionToIdentity_DifferentSPIFFEIDsProduceDifferentResults(t *testing.T) {
	sessionID := "550e8400-e29b-41d4-a716-446655440000"
	spiffeA := "spiffe://example.org/agent/alpha"
	spiffeB := "spiffe://example.org/agent/beta"

	boundA := BindSessionToIdentity(spiffeA, sessionID)
	boundB := BindSessionToIdentity(spiffeB, sessionID)

	if boundA == boundB {
		t.Errorf("Different SPIFFE IDs with same session ID should produce different bound IDs, both got: %s", boundA)
	}
}

func TestBindSessionToIdentity_DifferentSessionIDsProduceDifferentResults(t *testing.T) {
	spiffeID := "spiffe://example.org/agent/alpha"
	sessionA := "550e8400-e29b-41d4-a716-446655440000"
	sessionB := "660e8400-e29b-41d4-a716-446655440000"

	boundA := BindSessionToIdentity(spiffeID, sessionA)
	boundB := BindSessionToIdentity(spiffeID, sessionB)

	if boundA == boundB {
		t.Errorf("Different session IDs with same SPIFFE ID should produce different bound IDs, both got: %s", boundA)
	}
}

func TestSessionIDBoundToSPIFFEIdentity(t *testing.T) {
	// Two different SPIFFE IDs using the same session ID must get isolated sessions
	// with completely separate state.
	store := NewInMemoryStore()
	sc := NewSessionContext(store)

	spiffeA := "spiffe://example.org/agent/alpha"
	spiffeB := "spiffe://example.org/agent/beta"
	callerSessionID := "shared-session-id"

	// Bind session IDs as the middleware would
	boundA := BindSessionToIdentity(spiffeA, callerSessionID)
	boundB := BindSessionToIdentity(spiffeB, callerSessionID)

	// Create sessions for both agents using their bound session IDs
	sessionA := sc.GetOrCreateSession(spiffeA, boundA)
	sessionB := sc.GetOrCreateSession(spiffeB, boundB)

	// Record different actions for each agent
	sc.RecordAction(sessionA, ToolAction{
		Timestamp:      time.Now(),
		Tool:           "database_query",
		Resource:       "secret_passwords",
		Classification: "sensitive",
		ExternalTarget: false,
	})

	sc.RecordAction(sessionB, ToolAction{
		Timestamp:      time.Now(),
		Tool:           "file_read",
		Resource:       "config.json",
		Classification: "internal",
		ExternalTarget: false,
	})

	// Verify sessions are completely isolated
	if len(sessionA.Actions) != 1 {
		t.Fatalf("Agent A should have 1 action, got %d", len(sessionA.Actions))
	}
	if len(sessionB.Actions) != 1 {
		t.Fatalf("Agent B should have 1 action, got %d", len(sessionB.Actions))
	}
	if sessionA.Actions[0].Tool != "database_query" {
		t.Errorf("Agent A action should be database_query, got %s", sessionA.Actions[0].Tool)
	}
	if sessionB.Actions[0].Tool != "file_read" {
		t.Errorf("Agent B action should be file_read, got %s", sessionB.Actions[0].Tool)
	}

	// Verify sessions have different IDs despite same caller session ID
	if sessionA.ID == sessionB.ID {
		t.Errorf("Bound session IDs should differ: A=%s, B=%s", sessionA.ID, sessionB.ID)
	}

	// Verify risk scores are independent
	if sessionA.RiskScore == sessionB.RiskScore {
		t.Errorf("Risk scores should differ: A=%f, B=%f", sessionA.RiskScore, sessionB.RiskScore)
	}
}

func TestCrossAgentSessionAccessRejected(t *testing.T) {
	// Agent A creates a session and records sensitive data access.
	// Agent B tries to use the same session ID -- it must NOT see agent A's data.
	store := NewInMemoryStore()
	sc := NewSessionContext(store)

	spiffeA := "spiffe://example.org/agent/alpha"
	spiffeB := "spiffe://example.org/agent/beta"
	callerSessionID := "hijack-target-session"

	// Agent A establishes session and records sensitive actions
	boundA := BindSessionToIdentity(spiffeA, callerSessionID)
	sessionA := sc.GetOrCreateSession(spiffeA, boundA)
	sc.RecordAction(sessionA, ToolAction{
		Timestamp:      time.Now(),
		Tool:           "database_query",
		Resource:       "user_passwords",
		Classification: "sensitive",
		ExternalTarget: false,
	})
	sc.RecordAction(sessionA, ToolAction{
		Timestamp:      time.Now(),
		Tool:           "file_read",
		Resource:       "api_keys",
		Classification: "sensitive",
		ExternalTarget: false,
	})

	// Agent B attempts to access the same session ID (hijack attempt)
	boundB := BindSessionToIdentity(spiffeB, callerSessionID)
	sessionB := sc.GetOrCreateSession(spiffeB, boundB)

	// Agent B's session must be empty -- no access to A's data
	if len(sessionB.Actions) != 0 {
		t.Errorf("Agent B should have 0 actions (fresh session), got %d", len(sessionB.Actions))
	}
	if sessionB.RiskScore != 0 {
		t.Errorf("Agent B risk score should be 0, got %f", sessionB.RiskScore)
	}
	if len(sessionB.DataClassifications) != 0 {
		t.Errorf("Agent B should have no data classifications, got %v", sessionB.DataClassifications)
	}

	// Agent A's session must still be intact
	if len(sessionA.Actions) != 2 {
		t.Errorf("Agent A should still have 2 actions, got %d", len(sessionA.Actions))
	}

	// Agent B records an external send -- exfiltration check must NOT trigger
	// because B has no sensitive data in its own session
	sc.RecordAction(sessionB, ToolAction{
		Timestamp:         time.Now(),
		Tool:              "email_send",
		ExternalTarget:    true,
		DestinationDomain: "evil.com",
	})

	if sc.DetectsExfiltrationPattern(sessionB) {
		t.Error("Exfiltration should NOT be detected for agent B -- it never accessed sensitive data")
	}
}

func TestSessionContextMiddleware_BindsSessionToSPIFFE(t *testing.T) {
	// Integration test: verify the middleware applies HMAC binding end-to-end.
	store := NewInMemoryStore()
	sc := NewSessionContext(store)

	callerSessionID := uuid.New().String()
	spiffeA := "spiffe://example.org/agent/alpha"
	spiffeB := "spiffe://example.org/agent/beta"

	var capturedSessionA *AgentSession
	var capturedSessionB *AgentSession

	// Handler that captures the session from context
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := GetSessionContextData(r.Context())
		spiffe := GetSPIFFEID(r.Context())
		switch spiffe {
		case spiffeA:
			capturedSessionA = session
		case spiffeB:
			capturedSessionB = session
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := SessionContextMiddleware(innerHandler, sc)

	// Request from Agent A with session ID
	reqA := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(`{}`))
	ctxA := WithSessionID(reqA.Context(), callerSessionID)
	ctxA = WithSPIFFEID(ctxA, spiffeA)
	ctxA = WithRequestBody(ctxA, []byte(`{}`))
	reqA = reqA.WithContext(ctxA)
	recA := httptest.NewRecorder()
	handler.ServeHTTP(recA, reqA)

	if recA.Code != http.StatusOK {
		t.Fatalf("Agent A request failed: %d", recA.Code)
	}
	if capturedSessionA == nil {
		t.Fatal("Agent A session not captured")
	}

	// Request from Agent B with SAME session ID
	reqB := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(`{}`))
	ctxB := WithSessionID(reqB.Context(), callerSessionID)
	ctxB = WithSPIFFEID(ctxB, spiffeB)
	ctxB = WithRequestBody(ctxB, []byte(`{}`))
	reqB = reqB.WithContext(ctxB)
	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, reqB)

	if recB.Code != http.StatusOK {
		t.Fatalf("Agent B request failed: %d", recB.Code)
	}
	if capturedSessionB == nil {
		t.Fatal("Agent B session not captured")
	}

	// Sessions must be completely different objects with different IDs
	if capturedSessionA.ID == capturedSessionB.ID {
		t.Errorf("Middleware should bind sessions to different IDs: A=%s, B=%s",
			capturedSessionA.ID, capturedSessionB.ID)
	}
	if capturedSessionA.SPIFFEID != spiffeA {
		t.Errorf("Agent A session SPIFFE ID mismatch: got %s", capturedSessionA.SPIFFEID)
	}
	if capturedSessionB.SPIFFEID != spiffeB {
		t.Errorf("Agent B session SPIFFE ID mismatch: got %s", capturedSessionB.SPIFFEID)
	}
}

func TestBodyCapture_RejectsInvalidSessionIDFormat(t *testing.T) {
	var capturedSessionID string

	handler := BodyCapture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSessionID = GetSessionID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// Send a crafted non-UUID session ID
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{}`))
	req.Header.Set("X-Session-ID", "not-a-uuid-crafted-value")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	// The crafted session ID should have been replaced with a valid UUID
	if capturedSessionID == "not-a-uuid-crafted-value" {
		t.Error("BodyCapture should reject non-UUID session IDs")
	}
	if _, err := uuid.Parse(capturedSessionID); err != nil {
		t.Errorf("Replacement session ID should be a valid UUID, got %q: %v", capturedSessionID, err)
	}
}

func TestBodyCapture_AcceptsValidUUIDSessionID(t *testing.T) {
	validUUID := "550e8400-e29b-41d4-a716-446655440000"
	var capturedSessionID string

	handler := BodyCapture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSessionID = GetSessionID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{}`))
	req.Header.Set("X-Session-ID", validUUID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}
	if capturedSessionID != validUUID {
		t.Errorf("Expected valid UUID to be preserved, got %q", capturedSessionID)
	}
}

func TestBodyCapture_RejectsViaAlternateHeader(t *testing.T) {
	var capturedSessionID string

	handler := BodyCapture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSessionID = GetSessionID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// Send crafted ID via Mcp-Session-Id header
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{}`))
	req.Header.Set("Mcp-Session-Id", "../../../etc/passwd")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}
	if capturedSessionID == "../../../etc/passwd" {
		t.Error("BodyCapture should reject path-traversal session IDs via Mcp-Session-Id")
	}
	if _, err := uuid.Parse(capturedSessionID); err != nil {
		t.Errorf("Replacement session ID should be a valid UUID: %v", err)
	}
}

// Ensure the existing TestBodyCapture_PreservesIncomingSessionID in middleware_test.go
// still works by validating the preserved ID is also a valid UUID. This test uses
// a valid UUID to confirm preservation.
func TestBodyCapture_PreservesValidMcpSessionId(t *testing.T) {
	validUUID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	var capturedSessionID string

	handler := BodyCapture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSessionID = GetSessionID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{}`))
	req.Header.Set("Mcp-Session-Id", validUUID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}
	if capturedSessionID != validUUID {
		t.Errorf("Expected valid UUID to be preserved via Mcp-Session-Id, got %q", capturedSessionID)
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

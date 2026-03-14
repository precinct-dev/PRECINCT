package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// principalTestPolicy is a focused OPA policy that includes tool grants (wildcard),
// step-up (none), path/destination (pass-through), session risk (pass-through),
// and the principal-level rules from OC-3ch6.
const principalTestPolicy = `package mcp

import rego.v1

tool_grants := data.tool_grants
tool_registry := data.tool_registry

default allow := {
    "allow": false,
    "reason": "default_deny"
}

allow := {
    "allow": true,
    "reason": "allowed"
} if {
    matching_grant_exists
    tool_authorized_for_spiffe(input.tool)
    path_allowed(input.tool, input.params)
    destination_allowed(input.tool, input.params)
    step_up_satisfied(input.tool, input.step_up_token)
    session_risk_acceptable
    principal_level_acceptable
}

matching_grant_exists if {
    some grant in tool_grants
    spiffe_matches(input.spiffe_id, grant.spiffe_pattern)
}

tool_authorized_for_spiffe(tool) if {
    some grant in tool_grants
    spiffe_matches(input.spiffe_id, grant.spiffe_pattern)
    tool_authorized(tool, grant.allowed_tools)
}

spiffe_matches(spiffe_id, pattern) if {
    spiffe_id == pattern
}

spiffe_matches(spiffe_id, pattern) if {
    pattern_regex := replace(pattern, "*", "[^/]+")
    regex.match(pattern_regex, spiffe_id)
}

tool_authorized(tool, allowed_tools) if {
    "*" in allowed_tools
}

tool_authorized(tool, allowed_tools) if {
    tool in allowed_tools
}

tool_authorized("", allowed_tools) if {
    true
}

path_allowed(tool, params) if {
    not tool in ["read", "grep"]
}

path_allowed(tool, params) if {
    tool in ["read", "grep"]
}

destination_allowed(tool, params) if {
    true
}

step_up_satisfied(tool, step_up_token) if {
    not tool_in_registry(tool)
}

step_up_satisfied("", step_up_token) if {
    true
}

tool_in_registry(tool) if {
    some registry_tool in tool_registry.tools
    registry_tool.name == tool
}

session_risk_acceptable if {
    input.session.risk_score < 0.7
}

session_risk_acceptable if {
    not input.session
}

# Principal-level rules (OC-3ch6)
default principal_level_acceptable := true

principal_level_acceptable := false if {
    input.principal != null
    input.principal.level > 2
    is_destructive_action
}

principal_level_acceptable := false if {
    input.principal != null
    input.principal.level > 1
    is_data_export_action
}

principal_level_acceptable := false if {
    input.principal != null
    input.principal.level > 3
    is_messaging_action
}

principal_level_acceptable := false if {
    input.principal != null
    input.principal.level == 5
    input.path != "/health"
}

is_destructive_action if {
    action := lower(input.action)
    keywords := ["delete", "rm", "remove", "drop", "reset", "wipe", "shutdown", "terminate", "revoke", "purge", "destroy"]
    keyword := keywords[_]
    contains(action, keyword)
}

is_data_export_action if {
    action := lower(input.action)
    keywords := ["export", "dump", "backup", "extract", "exfil"]
    keyword := keywords[_]
    contains(action, keyword)
}

is_messaging_action if {
    action := lower(input.action)
    keywords := ["message", "notify", "broadcast", "send_agent", "agent_invoke"]
    keyword := keywords[_]
    contains(action, keyword)
}

# Denial reasons
allow := {
    "allow": false,
    "reason": "no_matching_grant"
} if {
    not matching_grant_exists
}

allow := {
    "allow": false,
    "reason": "principal_level_insufficient"
} if {
    matching_grant_exists
    tool_authorized_for_spiffe(input.tool)
    path_allowed(input.tool, input.params)
    destination_allowed(input.tool, input.params)
    step_up_satisfied(input.tool, input.step_up_token)
    session_risk_acceptable
    not principal_level_acceptable
}
`

// principalTestData provides wildcard grants so all SPIFFE IDs pass authz checks.
const principalTestData = `tool_grants:
  - spiffe_pattern: "spiffe://poc.local/*"
    allowed_tools:
      - "*"
  - spiffe_pattern: "spiffe://poc.local/*/*"
    allowed_tools:
      - "*"
tool_registry:
  tools: []
`

// setupPrincipalTestEngine creates an OPA engine with principal-level test policy.
func setupPrincipalTestEngine(t *testing.T) *OPAEngine {
	t.Helper()
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "mcp_policy.rego"), []byte(principalTestPolicy), 0644); err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "data.yaml"), []byte(principalTestData), 0644); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}

	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

// TestPrincipalLevel_DestructiveOperations tests AC #2: destructive operations
// require principal_level <= 2.
func TestPrincipalLevel_DestructiveOperations(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	tests := []struct {
		name       string
		level      int
		role       string
		action     string
		wantAllow  bool
		wantReason string
	}{
		{
			name:       "Owner_Level1_Delete_Allowed",
			level:      1,
			role:       "owner",
			action:     "delete",
			wantAllow:  true,
			wantReason: "allowed",
		},
		{
			name:       "DelegatedAdmin_Level2_Delete_Allowed",
			level:      2,
			role:       "delegated_admin",
			action:     "delete",
			wantAllow:  true,
			wantReason: "allowed",
		},
		{
			name:       "Agent_Level3_Delete_Denied",
			level:      3,
			role:       "agent",
			action:     "delete",
			wantAllow:  false,
			wantReason: "principal_level_insufficient",
		},
		{
			name:       "External_Level4_Delete_Denied",
			level:      4,
			role:       "external_user",
			action:     "delete",
			wantAllow:  false,
			wantReason: "principal_level_insufficient",
		},
		{
			name:       "Agent_Level3_Shutdown_Denied",
			level:      3,
			role:       "agent",
			action:     "shutdown",
			wantAllow:  false,
			wantReason: "principal_level_insufficient",
		},
		{
			name:       "Agent_Level3_Reset_Denied",
			level:      3,
			role:       "agent",
			action:     "reset",
			wantAllow:  false,
			wantReason: "principal_level_insufficient",
		},
		{
			name:       "DelegatedAdmin_Level2_Terminate_Allowed",
			level:      2,
			role:       "delegated_admin",
			action:     "terminate",
			wantAllow:  true,
			wantReason: "allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := OPAInput{
				SPIFFEID: "spiffe://poc.local/agents/test",
				Tool:     "some_tool",
				Action:   tt.action,
				Method:   "POST",
				Path:     "/mcp",
				Params:   map[string]interface{}{},
				Session:  SessionInput{RiskScore: 0.0, PreviousActions: []ToolAction{}},
				Principal: &PrincipalInput{
					Level:        tt.level,
					Role:         tt.role,
					Capabilities: []string{"read", "write"},
				},
			}
			allowed, reason, err := engine.Evaluate(input)
			if err != nil {
				t.Fatalf("Evaluate error: %v", err)
			}
			if allowed != tt.wantAllow {
				t.Errorf("expected allow=%v, got %v (reason: %s)", tt.wantAllow, allowed, reason)
			}
			if reason != tt.wantReason {
				t.Errorf("expected reason=%q, got %q", tt.wantReason, reason)
			}
		})
	}
}

// TestPrincipalLevel_DataExportOperations tests AC #3: data export operations
// require principal_level <= 1.
func TestPrincipalLevel_DataExportOperations(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	tests := []struct {
		name       string
		level      int
		role       string
		action     string
		wantAllow  bool
		wantReason string
	}{
		{
			name:       "Owner_Level1_Export_Allowed",
			level:      1,
			role:       "owner",
			action:     "export",
			wantAllow:  true,
			wantReason: "allowed",
		},
		{
			name:       "DelegatedAdmin_Level2_Export_Denied",
			level:      2,
			role:       "delegated_admin",
			action:     "export",
			wantAllow:  false,
			wantReason: "principal_level_insufficient",
		},
		{
			name:       "Agent_Level3_Backup_Denied",
			level:      3,
			role:       "agent",
			action:     "backup",
			wantAllow:  false,
			wantReason: "principal_level_insufficient",
		},
		{
			name:       "Owner_Level1_Dump_Allowed",
			level:      1,
			role:       "owner",
			action:     "dump",
			wantAllow:  true,
			wantReason: "allowed",
		},
		{
			name:       "External_Level4_Extract_Denied",
			level:      4,
			role:       "external_user",
			action:     "extract",
			wantAllow:  false,
			wantReason: "principal_level_insufficient",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := OPAInput{
				SPIFFEID: "spiffe://poc.local/agents/test",
				Tool:     "some_tool",
				Action:   tt.action,
				Method:   "POST",
				Path:     "/mcp",
				Params:   map[string]interface{}{},
				Session:  SessionInput{RiskScore: 0.0, PreviousActions: []ToolAction{}},
				Principal: &PrincipalInput{
					Level:        tt.level,
					Role:         tt.role,
					Capabilities: []string{"read"},
				},
			}
			allowed, reason, err := engine.Evaluate(input)
			if err != nil {
				t.Fatalf("Evaluate error: %v", err)
			}
			if allowed != tt.wantAllow {
				t.Errorf("expected allow=%v, got %v (reason: %s)", tt.wantAllow, allowed, reason)
			}
			if reason != tt.wantReason {
				t.Errorf("expected reason=%q, got %q", tt.wantReason, reason)
			}
		})
	}
}

// TestPrincipalLevel_MessagingOperations tests AC #4: inter-agent messaging
// requires principal_level <= 3.
func TestPrincipalLevel_MessagingOperations(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	tests := []struct {
		name       string
		level      int
		role       string
		action     string
		wantAllow  bool
		wantReason string
	}{
		{
			name:       "Agent_Level3_Message_Allowed",
			level:      3,
			role:       "agent",
			action:     "message",
			wantAllow:  true,
			wantReason: "allowed",
		},
		{
			name:       "External_Level4_Message_Denied",
			level:      4,
			role:       "external_user",
			action:     "message",
			wantAllow:  false,
			wantReason: "principal_level_insufficient",
		},
		{
			name:       "Agent_Level3_Broadcast_Allowed",
			level:      3,
			role:       "agent",
			action:     "broadcast",
			wantAllow:  true,
			wantReason: "allowed",
		},
		{
			name:       "External_Level4_SendAgent_Denied",
			level:      4,
			role:       "external_user",
			action:     "send_agent",
			wantAllow:  false,
			wantReason: "principal_level_insufficient",
		},
		{
			name:       "Owner_Level1_Notify_Allowed",
			level:      1,
			role:       "owner",
			action:     "notify",
			wantAllow:  true,
			wantReason: "allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := OPAInput{
				SPIFFEID: "spiffe://poc.local/agents/test",
				Tool:     "some_tool",
				Action:   tt.action,
				Method:   "POST",
				Path:     "/mcp",
				Params:   map[string]interface{}{},
				Session:  SessionInput{RiskScore: 0.0, PreviousActions: []ToolAction{}},
				Principal: &PrincipalInput{
					Level:        tt.level,
					Role:         tt.role,
					Capabilities: []string{"read", "write", "execute"},
				},
			}
			allowed, reason, err := engine.Evaluate(input)
			if err != nil {
				t.Fatalf("Evaluate error: %v", err)
			}
			if allowed != tt.wantAllow {
				t.Errorf("expected allow=%v, got %v (reason: %s)", tt.wantAllow, allowed, reason)
			}
			if reason != tt.wantReason {
				t.Errorf("expected reason=%q, got %q", tt.wantReason, reason)
			}
		})
	}
}

// TestPrincipalLevel_AnonymousAccess tests AC #5: anonymous (level 5)
// denied except /health.
func TestPrincipalLevel_AnonymousAccess(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	tests := []struct {
		name       string
		path       string
		action     string
		wantAllow  bool
		wantReason string
	}{
		{
			name:       "Anonymous_MCP_Denied",
			path:       "/mcp",
			action:     "execute",
			wantAllow:  false,
			wantReason: "principal_level_insufficient",
		},
		{
			name:       "Anonymous_Health_Allowed",
			path:       "/health",
			action:     "execute",
			wantAllow:  true,
			wantReason: "allowed",
		},
		{
			name:       "Anonymous_Arbitrary_Path_Denied",
			path:       "/api/v1/tools",
			action:     "execute",
			wantAllow:  false,
			wantReason: "principal_level_insufficient",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := OPAInput{
				SPIFFEID: "spiffe://poc.local/agents/test",
				Tool:     "some_tool",
				Action:   tt.action,
				Method:   "GET",
				Path:     tt.path,
				Params:   map[string]interface{}{},
				Session:  SessionInput{RiskScore: 0.0, PreviousActions: []ToolAction{}},
				Principal: &PrincipalInput{
					Level:        5,
					Role:         "anonymous",
					Capabilities: []string{},
				},
			}
			allowed, reason, err := engine.Evaluate(input)
			if err != nil {
				t.Fatalf("Evaluate error: %v", err)
			}
			if allowed != tt.wantAllow {
				t.Errorf("expected allow=%v, got %v (reason: %s)", tt.wantAllow, allowed, reason)
			}
			if reason != tt.wantReason {
				t.Errorf("expected reason=%q, got %q", tt.wantReason, reason)
			}
		})
	}
}

// TestPrincipalLevel_NoPrincipal tests backward compatibility when no principal
// is present in the input.
func TestPrincipalLevel_NoPrincipal(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	input := OPAInput{
		SPIFFEID: "spiffe://poc.local/agents/test",
		Tool:     "some_tool",
		Action:   "delete",
		Method:   "POST",
		Path:     "/mcp",
		Params:   map[string]interface{}{},
		Session:  SessionInput{RiskScore: 0.0, PreviousActions: []ToolAction{}},
		// No Principal field -- backward compatible
	}
	allowed, reason, err := engine.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !allowed {
		t.Errorf("expected allow=true with no principal (backward compatible), got deny (reason: %s)", reason)
	}
}

// TestPrincipalInput_JSONSerialization verifies the PrincipalInput struct
// serializes correctly for OPA evaluation.
func TestPrincipalInput_JSONSerialization(t *testing.T) {
	input := OPAInput{
		SPIFFEID: "spiffe://poc.local/owner/alice",
		Tool:     "bash",
		Action:   "delete",
		Method:   "POST",
		Path:     "/mcp",
		Params:   map[string]interface{}{},
		Session:  SessionInput{RiskScore: 0.1},
		Principal: &PrincipalInput{
			Level:        1,
			Role:         "owner",
			Capabilities: []string{"admin", "read", "write"},
		},
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	principal, ok := decoded["principal"].(map[string]interface{})
	if !ok {
		t.Fatal("expected principal field in JSON")
	}
	if level, ok := principal["level"].(float64); !ok || int(level) != 1 {
		t.Errorf("expected principal.level=1, got %v", principal["level"])
	}
	if role, ok := principal["role"].(string); !ok || role != "owner" {
		t.Errorf("expected principal.role=owner, got %v", principal["role"])
	}
}

// TestPrincipalInput_OmitEmpty verifies the Principal field is omitted from JSON
// when nil (backward compatibility).
func TestPrincipalInput_OmitEmpty(t *testing.T) {
	input := OPAInput{
		SPIFFEID: "spiffe://poc.local/agents/test",
		Tool:     "bash",
		Action:   "execute",
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	if strings.Contains(string(data), `"principal"`) {
		t.Errorf("expected principal to be omitted when nil, got: %s", string(data))
	}
}

// TestPrincipalLevel_ErrorCode verifies the ErrPrincipalLevelInsufficient constant.
func TestPrincipalLevel_ErrorCode(t *testing.T) {
	if ErrPrincipalLevelInsufficient != "principal_level_insufficient" {
		t.Errorf("expected ErrPrincipalLevelInsufficient=%q, got %q",
			"principal_level_insufficient", ErrPrincipalLevelInsufficient)
	}
}

// TestPrincipalLevel_Integration_ExternalDelete is an integration test that
// exercises the full middleware chain: context population -> OPA evaluation
// with principal-aware rules. External SPIFFE ID + delete action = denied.
func TestPrincipalLevel_Integration_ExternalDelete(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	// Simulate what the OPAPolicy middleware does: build input from context
	spiffeID := "spiffe://poc.local/external/bob"
	role := ResolvePrincipalRole(spiffeID, "poc.local", "mtls_svid")

	input := OPAInput{
		SPIFFEID: spiffeID,
		Tool:     "some_tool",
		Action:   "delete",
		Method:   "POST",
		Path:     "/mcp",
		Params:   map[string]interface{}{},
		Session:  SessionInput{RiskScore: 0.0, PreviousActions: []ToolAction{}},
	}

	// Populate principal from resolved role (as the middleware does)
	if role.Role != "" {
		input.Principal = &PrincipalInput{
			Level:        role.Level,
			Role:         role.Role,
			Capabilities: role.Capabilities,
		}
	}

	allowed, reason, err := engine.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if allowed {
		t.Error("expected external/bob (level 4) to be denied for delete action")
	}
	if reason != "principal_level_insufficient" {
		t.Errorf("expected reason=principal_level_insufficient, got %q", reason)
	}
}

// TestPrincipalLevel_Integration_OwnerDelete is an integration test:
// Owner SPIFFE ID + delete action = allowed through OPA.
func TestPrincipalLevel_Integration_OwnerDelete(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	spiffeID := "spiffe://poc.local/owner/alice"
	role := ResolvePrincipalRole(spiffeID, "poc.local", "mtls_svid")

	input := OPAInput{
		SPIFFEID: spiffeID,
		Tool:     "some_tool",
		Action:   "delete",
		Method:   "POST",
		Path:     "/mcp",
		Params:   map[string]interface{}{},
		Session:  SessionInput{RiskScore: 0.0, PreviousActions: []ToolAction{}},
	}

	if role.Role != "" {
		input.Principal = &PrincipalInput{
			Level:        role.Level,
			Role:         role.Role,
			Capabilities: role.Capabilities,
		}
	}

	allowed, reason, err := engine.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !allowed {
		t.Errorf("expected owner/alice (level 1) to be allowed for delete, got deny (reason: %s)", reason)
	}
}

// TestPrincipalLevel_Integration_AnonymousMiddleware tests that anonymous principal
// (level 5) is denied for non-health paths through the OPAPolicy middleware chain.
func TestPrincipalLevel_Integration_AnonymousMiddleware(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	handlerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := OPAPolicy(inner, engine)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"some_tool","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.Background()
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test")
	ctx = WithPrincipalRole(ctx, PrincipalRole{
		Level:        5,
		Role:         "anonymous",
		Capabilities: []string{},
	})
	ctx = WithRequestBody(ctx, []byte(body))
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for anonymous on /mcp, got %d", rr.Code)
	}
	if handlerCalled {
		t.Error("handler should not have been called for anonymous user on /mcp")
	}

	// Verify the error code is principal_level_insufficient
	var errResp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err == nil {
		if code, ok := errResp["code"].(string); ok {
			if code != ErrPrincipalLevelInsufficient {
				t.Errorf("expected error code %q, got %q", ErrPrincipalLevelInsufficient, code)
			}
		}
	}
}

// TestPrincipalLevel_Integration_OwnerMiddleware tests that owner principal
// (level 1) is allowed through the OPAPolicy middleware chain.
func TestPrincipalLevel_Integration_OwnerMiddleware(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	handlerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := OPAPolicy(inner, engine)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"some_tool","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.Background()
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/owner/alice")
	ctx = WithPrincipalRole(ctx, PrincipalRole{
		Level:        1,
		Role:         "owner",
		Capabilities: []string{"admin", "read", "write", "execute", "delegate"},
	})
	ctx = WithRequestBody(ctx, []byte(body))
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for owner on /mcp, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if !handlerCalled {
		t.Error("handler should have been called for owner user")
	}
}

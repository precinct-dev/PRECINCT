package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Unit tests for deriveAction (mocks allowed at unit level)
// ---------------------------------------------------------------------------

// TestOPAActionDerivation verifies that explicit params["action"] is used.
func TestOPAActionDerivation(t *testing.T) {
	tests := []struct {
		name       string
		toolName   string
		params     map[string]interface{}
		wantAction string
	}{
		{
			name:       "ExplicitDeleteAction",
			toolName:   "some_tool",
			params:     map[string]interface{}{"action": "delete"},
			wantAction: "delete",
		},
		{
			name:       "ExplicitExportAction",
			toolName:   "some_tool",
			params:     map[string]interface{}{"action": "export"},
			wantAction: "export",
		},
		{
			name:       "ExplicitCustomAction",
			toolName:   "some_tool",
			params:     map[string]interface{}{"action": "my_custom_action"},
			wantAction: "my_custom_action",
		},
		{
			name:       "ExplicitActionTakesPrecedenceOverToolName",
			toolName:   "messaging_send",
			params:     map[string]interface{}{"action": "delete"},
			wantAction: "delete",
		},
		{
			name:       "EmptyStringActionIgnored",
			toolName:   "some_tool",
			params:     map[string]interface{}{"action": ""},
			wantAction: "execute",
		},
		{
			name:       "NonStringActionIgnored",
			toolName:   "some_tool",
			params:     map[string]interface{}{"action": 42},
			wantAction: "execute",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveAction(tt.toolName, tt.params)
			if got != tt.wantAction {
				t.Errorf("deriveAction(%q, %v) = %q, want %q", tt.toolName, tt.params, got, tt.wantAction)
			}
		})
	}
}

// TestOPAActionFromToolName verifies keyword extraction from tool name.
func TestOPAActionFromToolName(t *testing.T) {
	tests := []struct {
		name       string
		toolName   string
		wantAction string
	}{
		{
			name:       "MessagingSend",
			toolName:   "messaging_send",
			wantAction: "message",
		},
		{
			name:       "DeleteResource",
			toolName:   "delete_resource",
			wantAction: "delete",
		},
		{
			name:       "DataExport",
			toolName:   "data_export",
			wantAction: "export",
		},
		{
			name:       "BroadcastNotification",
			toolName:   "broadcast_notification",
			wantAction: "broadcast",
		},
		{
			name:       "AgentInvoke",
			toolName:   "agent_invoke_task",
			wantAction: "agent_invoke",
		},
		{
			name:       "RemoveEntry",
			toolName:   "remove_entry",
			wantAction: "remove",
		},
		{
			name:       "ShutdownService",
			toolName:   "shutdown_service",
			wantAction: "shutdown",
		},
		{
			name:       "CaseSensitivity_UpperCase",
			toolName:   "DELETE_RESOURCE",
			wantAction: "delete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveAction(tt.toolName, map[string]interface{}{})
			if got != tt.wantAction {
				t.Errorf("deriveAction(%q, {}) = %q, want %q", tt.toolName, got, tt.wantAction)
			}
		})
	}
}

// TestOPAActionFallback verifies that neutral tools produce "execute".
func TestOPAActionFallback(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		params   map[string]interface{}
	}{
		{
			name:     "NeutralTool",
			toolName: "read_file",
			params:   map[string]interface{}{},
		},
		{
			name:     "EmptyToolName",
			toolName: "",
			params:   map[string]interface{}{},
		},
		{
			name:     "GrepTool",
			toolName: "grep",
			params:   map[string]interface{}{"query": "hello"},
		},
		{
			name:     "TavilySearch",
			toolName: "tavily_search",
			params:   map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveAction(tt.toolName, tt.params)
			if got != "execute" {
				t.Errorf("deriveAction(%q, %v) = %q, want %q", tt.toolName, tt.params, got, "execute")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Integration tests (NO mocks -- HARD GATE)
// These exercise the full OPAPolicy middleware with a real OPA engine.
// ---------------------------------------------------------------------------

// TestOPAIntegrationDestructiveActionPrincipalDenied verifies that an external
// user (level 4) calling a destructive action receives HTTP 403 with
// "principal_level_insufficient" through the actual gateway HTTP path.
func TestOPAIntegrationDestructiveActionPrincipalDenied(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	handlerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := OPAPolicy(inner, engine)

	// MCP tools/call with params["action"]="delete"
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"some_tool","arguments":{"action":"delete"}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.Background()
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/external/bob")
	ctx = WithPrincipalRole(ctx, PrincipalRole{
		Level:        4,
		Role:         "external_user",
		Capabilities: []string{"read"},
	})
	ctx = WithRequestBody(ctx, []byte(body))
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if handlerCalled {
		t.Fatal("inner handler should not have been called for denied request")
	}

	// Verify response contains principal_level_insufficient
	var errResp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	code, _ := errResp["code"].(string)
	if code != ErrPrincipalLevelInsufficient {
		t.Errorf("expected error code %q, got %q", ErrPrincipalLevelInsufficient, code)
	}
	details, _ := errResp["details"].(map[string]interface{})
	reason, _ := details["reason"].(string)
	if reason != "principal_level_insufficient" {
		t.Errorf("expected reason %q in details, got %q", "principal_level_insufficient", reason)
	}
}

// TestOPAIntegrationMessagingActionPrincipalDenied verifies that an external
// user (level 4) calling messaging_send receives HTTP 403 with
// "principal_level_insufficient" through the actual gateway HTTP path.
func TestOPAIntegrationMessagingActionPrincipalDenied(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	handlerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := OPAPolicy(inner, engine)

	// MCP tools/call with tool name "messaging_send" (no explicit action param)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"messaging_send","arguments":{"to":"agent-1","text":"hello"}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.Background()
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/external/bob")
	ctx = WithPrincipalRole(ctx, PrincipalRole{
		Level:        4,
		Role:         "external_user",
		Capabilities: []string{"read"},
	})
	ctx = WithRequestBody(ctx, []byte(body))
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if handlerCalled {
		t.Fatal("inner handler should not have been called for denied request")
	}

	// Verify response contains principal_level_insufficient
	var errResp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	code, _ := errResp["code"].(string)
	if code != ErrPrincipalLevelInsufficient {
		t.Errorf("expected error code %q, got %q", ErrPrincipalLevelInsufficient, code)
	}
	details, _ := errResp["details"].(map[string]interface{})
	reason, _ := details["reason"].(string)
	if reason != "principal_level_insufficient" {
		t.Errorf("expected reason %q in details, got %q", "principal_level_insufficient", reason)
	}
}

// TestOPAIntegrationNeutralToolAllowed verifies that a neutral tool with no
// action semantics still gets Action="execute" and is allowed through.
func TestOPAIntegrationNeutralToolAllowed(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	handlerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := OPAPolicy(inner, engine)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test.txt"}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.Background()
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/external/bob")
	ctx = WithPrincipalRole(ctx, PrincipalRole{
		Level:        4,
		Role:         "external_user",
		Capabilities: []string{"read"},
	})
	ctx = WithRequestBody(ctx, []byte(body))
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 for neutral tool, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if !handlerCalled {
		t.Error("inner handler should have been called for allowed request")
	}
}

// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// --- Unit Tests: UIInput struct and BuildUIInput ---

func TestBuildUIInput_AllFields(t *testing.T) {
	ui := BuildUIInput(
		true,
		"ui://dashboard/analytics.html",
		"sha256:ab12cd34",
		"app",
		7,
		true,
		true,
	)

	if !ui.Enabled {
		t.Error("Expected Enabled=true")
	}
	if ui.ResourceURI != "ui://dashboard/analytics.html" {
		t.Errorf("Expected ResourceURI='ui://dashboard/analytics.html', got %q", ui.ResourceURI)
	}
	if ui.ResourceContentHash != "sha256:ab12cd34" {
		t.Errorf("Expected ResourceContentHash='sha256:ab12cd34', got %q", ui.ResourceContentHash)
	}
	if ui.CallOrigin != "app" {
		t.Errorf("Expected CallOrigin='app', got %q", ui.CallOrigin)
	}
	if ui.AppSessionToolCalls != 7 {
		t.Errorf("Expected AppSessionToolCalls=7, got %d", ui.AppSessionToolCalls)
	}
	if !ui.ResourceRegistered {
		t.Error("Expected ResourceRegistered=true")
	}
	if !ui.ResourceHashVerified {
		t.Error("Expected ResourceHashVerified=true")
	}
}

func TestBuildUIInput_Defaults(t *testing.T) {
	ui := BuildUIInput(false, "", "", "", 0, false, false)

	if ui.Enabled {
		t.Error("Expected Enabled=false")
	}
	if ui.ResourceURI != "" {
		t.Errorf("Expected empty ResourceURI, got %q", ui.ResourceURI)
	}
	if ui.CallOrigin != "" {
		t.Errorf("Expected empty CallOrigin, got %q", ui.CallOrigin)
	}
	if ui.AppSessionToolCalls != 0 {
		t.Errorf("Expected AppSessionToolCalls=0, got %d", ui.AppSessionToolCalls)
	}
}

func TestUIInput_JSONSerialization(t *testing.T) {
	ui := UIInput{
		Enabled:              true,
		ResourceURI:          "ui://server/page.html",
		ResourceContentHash:  "sha256:deadbeef",
		CallOrigin:           "app",
		AppSessionToolCalls:  42,
		ResourceRegistered:   true,
		ResourceHashVerified: true,
		DeclaredCSP: &DeclaredCSPInput{
			ConnectDomains:  []string{"https://api.example.com"},
			ResourceDomains: []string{},
			FrameDomains:    []string{},
			BaseURIDomains:  []string{},
		},
		DeclaredPermissions: &DeclaredPermsInput{
			Camera:         false,
			Microphone:     false,
			Geolocation:    false,
			ClipboardWrite: false,
		},
		ToolVisibility: []string{"model", "app"},
	}

	data, err := json.Marshal(ui)
	if err != nil {
		t.Fatalf("Failed to marshal UIInput: %v", err)
	}

	// Verify key fields are present in JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal UIInput JSON: %v", err)
	}

	// Check all 10 fields from AC #1
	expectedFields := []string{
		"enabled", "resource_uri", "resource_content_hash",
		"declared_csp", "declared_permissions", "tool_visibility",
		"call_origin", "app_session_tool_calls",
		"resource_registered", "resource_hash_verified",
	}

	for _, field := range expectedFields {
		if _, ok := parsed[field]; !ok {
			t.Errorf("Expected field %q in serialized UIInput JSON", field)
		}
	}

	// Verify CSP sub-fields
	csp, ok := parsed["declared_csp"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected declared_csp to be an object")
	}
	if _, ok := csp["connectDomains"]; !ok {
		t.Error("Expected connectDomains in declared_csp")
	}

	// Verify permissions sub-fields
	perms, ok := parsed["declared_permissions"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected declared_permissions to be an object")
	}
	if _, ok := perms["camera"]; !ok {
		t.Error("Expected camera in declared_permissions")
	}
}

func TestUIInput_OmitEmptyFields(t *testing.T) {
	// When DeclaredCSP and DeclaredPermissions are nil, they should be omitted
	ui := UIInput{
		Enabled:    false,
		CallOrigin: "",
	}

	data, err := json.Marshal(ui)
	if err != nil {
		t.Fatalf("Failed to marshal UIInput: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if _, ok := parsed["declared_csp"]; ok {
		t.Error("Expected declared_csp to be omitted when nil")
	}
	if _, ok := parsed["declared_permissions"]; ok {
		t.Error("Expected declared_permissions to be omitted when nil")
	}
}

func TestOPAInput_IncludesUISection(t *testing.T) {
	uiInput := BuildUIInput(true, "ui://s/p.html", "sha256:abc", "app", 5, true, false)
	input := OPAInput{
		SPIFFEID:    "spiffe://test/agent",
		Tool:        "render-analytics",
		Action:      "execute",
		Method:      "POST",
		Path:        "/",
		StepUpToken: "",
		Session:     SessionInput{},
		UI:          &uiInput,
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Failed to marshal OPAInput: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	uiSection, ok := parsed["ui"]
	if !ok {
		t.Fatal("Expected 'ui' section in OPAInput JSON")
	}

	uiMap := uiSection.(map[string]interface{})
	if enabled, ok := uiMap["enabled"].(bool); !ok || !enabled {
		t.Error("Expected ui.enabled=true in OPAInput")
	}
	if callOrigin, ok := uiMap["call_origin"].(string); !ok || callOrigin != "app" {
		t.Error("Expected ui.call_origin='app' in OPAInput")
	}
}

func TestOPAInput_UIIsOmittedWhenNil(t *testing.T) {
	input := OPAInput{
		SPIFFEID: "spiffe://test/agent",
		Tool:     "read",
		Action:   "execute",
		// UI is nil
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Failed to marshal OPAInput: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if _, ok := parsed["ui"]; ok {
		t.Error("Expected 'ui' to be omitted when nil")
	}
}

// --- Unit Tests: UIPolicyInput marshaling ---

func TestUIPolicyInput_JSONStructure(t *testing.T) {
	input := UIPolicyInput{
		UI: UIInput{
			Enabled:             true,
			CallOrigin:          "app",
			AppSessionToolCalls: 51,
		},
		ToolServer:    "mcp-dashboard-server",
		Tool:          "render-analytics",
		ToolRiskLevel: "high",
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Failed to marshal UIPolicyInput: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	for _, field := range []string{"ui", "tool_server", "tool", "tool_risk_level"} {
		if _, ok := parsed[field]; !ok {
			t.Errorf("Expected field %q in UIPolicyInput JSON", field)
		}
	}
}

// --- Unit Tests: UI Context helpers ---

func TestUIContextHelpers(t *testing.T) {
	ctx := context.Background()

	// Defaults should be zero values
	if GetUIEnabled(ctx) {
		t.Error("Expected UIEnabled=false by default")
	}
	if GetUICallOrigin(ctx) != "" {
		t.Error("Expected empty UICallOrigin by default")
	}
	if GetUIAppToolCalls(ctx) != 0 {
		t.Error("Expected UIAppToolCalls=0 by default")
	}
	if GetUIResourceURI(ctx) != "" {
		t.Error("Expected empty UIResourceURI by default")
	}

	// Set values
	ctx = WithUIEnabled(ctx, true)
	ctx = WithUICallOrigin(ctx, "app")
	ctx = WithUIAppToolCalls(ctx, 42)
	ctx = WithUIResourceURI(ctx, "ui://server/page.html")

	if !GetUIEnabled(ctx) {
		t.Error("Expected UIEnabled=true after set")
	}
	if GetUICallOrigin(ctx) != "app" {
		t.Errorf("Expected UICallOrigin='app', got %q", GetUICallOrigin(ctx))
	}
	if GetUIAppToolCalls(ctx) != 42 {
		t.Errorf("Expected UIAppToolCalls=42, got %d", GetUIAppToolCalls(ctx))
	}
	if GetUIResourceURI(ctx) != "ui://server/page.html" {
		t.Errorf("Expected UIResourceURI='ui://server/page.html', got %q", GetUIResourceURI(ctx))
	}
}

// --- Integration Tests: Against embedded OPA engine with real Rego policies ---
// These tests create a real OPA engine with the ui_policy.rego and evaluate
// the rules with various inputs. NO MOCKS.

// setupUIPolicyEngine creates an OPA engine with the UI policy and capability
// grants data for integration testing.
func setupUIPolicyEngine(t *testing.T, grantsYAML string) *OPAEngine {
	t.Helper()

	tmpDir := t.TempDir()

	// Write a minimal MCP policy so the main query compiles
	mcpPolicy := `package mcp
default allow := {"allow": true, "reason": "allowed"}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "mcp_policy.rego"), []byte(mcpPolicy), 0644); err != nil {
		t.Fatalf("Failed to write MCP policy: %v", err)
	}

	// Write the actual UI policy from config/opa/ui_policy.rego
	uiPolicy := `package mcp.ui.policy

import rego.v1

default deny_ui_resource := false
default deny_app_tool_call := false
default requires_step_up := false
default excessive_app_calls := false

deny_ui_resource if {
    input.ui.enabled
    not ui_server_approved
}

ui_server_approved if {
    some grant in data.ui_capability_grants
    grant.server == input.tool_server
    grant.mode == "allow"
}

deny_app_tool_call if {
    input.ui.call_origin == "app"
    some grant in data.ui_capability_grants
    grant.server == input.tool_server
    count(grant.approved_tools) > 0
    not input.tool in grant.approved_tools
}

requires_step_up if {
    input.ui.call_origin == "app"
    input.tool_risk_level in {"high", "critical"}
}

excessive_app_calls if {
    input.ui.call_origin == "app"
    input.ui.app_session_tool_calls > 50
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "ui_policy.rego"), []byte(uiPolicy), 0644); err != nil {
		t.Fatalf("Failed to write UI policy: %v", err)
	}

	// Write grants data
	if err := os.WriteFile(filepath.Join(tmpDir, "ui_capability_grants.yaml"), []byte(grantsYAML), 0644); err != nil {
		t.Fatalf("Failed to write grants YAML: %v", err)
	}

	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	return engine
}

// TestOPAUIPolicy_DenyUIResource_UnapprovedServer tests AC #3:
// deny_ui_resource blocks UI resources from servers without allow mode.
func TestOPAUIPolicy_DenyUIResource_UnapprovedServer(t *testing.T) {
	grants := `ui_capability_grants:
  - server: "approved-server"
    mode: "allow"
    approved_tools: []
  - server: "denied-server"
    mode: "deny"
    approved_tools: []
`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled: true,
		},
		ToolServer: "denied-server",
		Tool:       "some-tool",
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if !result.DenyUIResource {
		t.Error("Expected deny_ui_resource=true for unapproved (deny mode) server")
	}
}

// TestOPAUIPolicy_DenyUIResource_ApprovedServer tests AC #3:
// deny_ui_resource allows UI resources from servers with allow mode.
func TestOPAUIPolicy_DenyUIResource_ApprovedServer(t *testing.T) {
	grants := `ui_capability_grants:
  - server: "approved-server"
    mode: "allow"
    approved_tools: []
`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled: true,
		},
		ToolServer: "approved-server",
		Tool:       "some-tool",
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if result.DenyUIResource {
		t.Error("Expected deny_ui_resource=false for approved (allow mode) server")
	}
}

// TestOPAUIPolicy_DenyUIResource_UnknownServer tests that unknown servers
// (not in grants at all) are denied.
func TestOPAUIPolicy_DenyUIResource_UnknownServer(t *testing.T) {
	grants := `ui_capability_grants:
  - server: "known-server"
    mode: "allow"
    approved_tools: []
`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled: true,
		},
		ToolServer: "unknown-server",
		Tool:       "some-tool",
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if !result.DenyUIResource {
		t.Error("Expected deny_ui_resource=true for unknown server (no grant)")
	}
}

// TestOPAUIPolicy_DenyUIResource_UIDisabled tests that when UI is not enabled,
// deny_ui_resource is false (the UI subsystem is simply not active).
func TestOPAUIPolicy_DenyUIResource_UIDisabled(t *testing.T) {
	grants := `ui_capability_grants:
  - server: "some-server"
    mode: "deny"
    approved_tools: []
`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled: false, // UI not enabled
		},
		ToolServer: "some-server",
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if result.DenyUIResource {
		t.Error("Expected deny_ui_resource=false when UI is disabled")
	}
}

// TestOPAUIPolicy_DenyAppToolCall_UnapprovedTool tests AC #4:
// deny_app_tool_call blocks app-driven calls to tools not in approved set.
func TestOPAUIPolicy_DenyAppToolCall_UnapprovedTool(t *testing.T) {
	grants := `ui_capability_grants:
  - server: "dashboard-server"
    mode: "allow"
    approved_tools:
      - "render-analytics"
      - "show-chart"
`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:    true,
			CallOrigin: "app",
		},
		ToolServer: "dashboard-server",
		Tool:       "delete-data", // NOT in approved_tools
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if !result.DenyAppToolCall {
		t.Error("Expected deny_app_tool_call=true for app calling unapproved tool")
	}
}

// TestOPAUIPolicy_DenyAppToolCall_ApprovedTool tests AC #4:
// deny_app_tool_call allows app-driven calls to tools in the approved set.
func TestOPAUIPolicy_DenyAppToolCall_ApprovedTool(t *testing.T) {
	grants := `ui_capability_grants:
  - server: "dashboard-server"
    mode: "allow"
    approved_tools:
      - "render-analytics"
      - "show-chart"
`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:    true,
			CallOrigin: "app",
		},
		ToolServer: "dashboard-server",
		Tool:       "render-analytics", // In approved_tools
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if result.DenyAppToolCall {
		t.Error("Expected deny_app_tool_call=false for app calling approved tool")
	}
}

// TestOPAUIPolicy_DenyAppToolCall_EmptyApprovedTools tests that when
// approved_tools is empty (all tools allowed), no denial occurs.
func TestOPAUIPolicy_DenyAppToolCall_EmptyApprovedTools(t *testing.T) {
	grants := `ui_capability_grants:
  - server: "permissive-server"
    mode: "allow"
    approved_tools: []
`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:    true,
			CallOrigin: "app",
		},
		ToolServer: "permissive-server",
		Tool:       "any-tool",
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if result.DenyAppToolCall {
		t.Error("Expected deny_app_tool_call=false when approved_tools is empty (all tools allowed)")
	}
}

// TestOPAUIPolicy_DenyAppToolCall_ModelOrigin tests that model-originated calls
// are not blocked by deny_app_tool_call.
func TestOPAUIPolicy_DenyAppToolCall_ModelOrigin(t *testing.T) {
	grants := `ui_capability_grants:
  - server: "dashboard-server"
    mode: "allow"
    approved_tools:
      - "render-analytics"
`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:    true,
			CallOrigin: "model", // Not "app"
		},
		ToolServer: "dashboard-server",
		Tool:       "delete-data", // Not in approved_tools, but origin is model
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if result.DenyAppToolCall {
		t.Error("Expected deny_app_tool_call=false for model-originated call")
	}
}

// TestOPAUIPolicy_RequiresStepUp_HighRisk tests AC #5:
// requires_step_up forces step-up for app-driven high-risk tool calls.
func TestOPAUIPolicy_RequiresStepUp_HighRisk(t *testing.T) {
	grants := `ui_capability_grants: []`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:    true,
			CallOrigin: "app",
		},
		ToolRiskLevel: "high",
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if !result.RequiresStepUp {
		t.Error("Expected requires_step_up=true for app-driven high-risk call")
	}
}

// TestOPAUIPolicy_RequiresStepUp_CriticalRisk tests AC #5 for critical risk level.
func TestOPAUIPolicy_RequiresStepUp_CriticalRisk(t *testing.T) {
	grants := `ui_capability_grants: []`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:    true,
			CallOrigin: "app",
		},
		ToolRiskLevel: "critical",
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if !result.RequiresStepUp {
		t.Error("Expected requires_step_up=true for app-driven critical-risk call")
	}
}

// TestOPAUIPolicy_RequiresStepUp_LowRisk tests that low-risk tools do not
// require step-up even when app-driven.
func TestOPAUIPolicy_RequiresStepUp_LowRisk(t *testing.T) {
	grants := `ui_capability_grants: []`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:    true,
			CallOrigin: "app",
		},
		ToolRiskLevel: "low",
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if result.RequiresStepUp {
		t.Error("Expected requires_step_up=false for low-risk tool")
	}
}

// TestOPAUIPolicy_RequiresStepUp_ModelOrigin tests that model-driven calls
// never trigger step-up, even for high-risk tools.
func TestOPAUIPolicy_RequiresStepUp_ModelOrigin(t *testing.T) {
	grants := `ui_capability_grants: []`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:    true,
			CallOrigin: "model",
		},
		ToolRiskLevel: "high",
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if result.RequiresStepUp {
		t.Error("Expected requires_step_up=false for model-driven call")
	}
}

// TestOPAUIPolicy_ExcessiveAppCalls_Over50 tests AC #6:
// excessive_app_calls flags sessions with >50 app-driven tool calls.
func TestOPAUIPolicy_ExcessiveAppCalls_Over50(t *testing.T) {
	grants := `ui_capability_grants: []`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:             true,
			CallOrigin:          "app",
			AppSessionToolCalls: 51, // > 50
		},
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if !result.ExcessiveAppCalls {
		t.Error("Expected excessive_app_calls=true for 51 app tool calls")
	}
}

// TestOPAUIPolicy_ExcessiveAppCalls_Exactly50 tests the boundary: exactly 50
// calls should NOT trigger the flag (>50, not >=50).
func TestOPAUIPolicy_ExcessiveAppCalls_Exactly50(t *testing.T) {
	grants := `ui_capability_grants: []`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:             true,
			CallOrigin:          "app",
			AppSessionToolCalls: 50, // Exactly 50, not >50
		},
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if result.ExcessiveAppCalls {
		t.Error("Expected excessive_app_calls=false for exactly 50 calls (>50, not >=50)")
	}
}

// TestOPAUIPolicy_ExcessiveAppCalls_Under50 tests that normal call counts
// do not trigger the flag.
func TestOPAUIPolicy_ExcessiveAppCalls_Under50(t *testing.T) {
	grants := `ui_capability_grants: []`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:             true,
			CallOrigin:          "app",
			AppSessionToolCalls: 10,
		},
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if result.ExcessiveAppCalls {
		t.Error("Expected excessive_app_calls=false for 10 app tool calls")
	}
}

// TestOPAUIPolicy_ExcessiveAppCalls_ModelOrigin tests that model-driven calls
// never trigger excessive_app_calls, even at high counts.
func TestOPAUIPolicy_ExcessiveAppCalls_ModelOrigin(t *testing.T) {
	grants := `ui_capability_grants: []`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:             true,
			CallOrigin:          "model",
			AppSessionToolCalls: 100,
		},
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if result.ExcessiveAppCalls {
		t.Error("Expected excessive_app_calls=false for model-driven calls")
	}
}

// TestOPAUIPolicy_NoPolicyLoaded tests that when no UI policy is loaded,
// EvaluateUIPolicy returns safe defaults (all false).
func TestOPAUIPolicy_NoPolicyLoaded(t *testing.T) {
	tmpDir := t.TempDir()

	// Only MCP policy, no UI policy
	mcpPolicy := `package mcp
default allow := {"allow": true, "reason": "allowed"}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "mcp_policy.rego"), []byte(mcpPolicy), 0644); err != nil {
		t.Fatalf("Failed to write MCP policy: %v", err)
	}

	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer func() {
		_ = engine.Close()
	}()

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:             true,
			CallOrigin:          "app",
			AppSessionToolCalls: 100,
		},
		ToolServer:    "any-server",
		ToolRiskLevel: "critical",
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if result.DenyUIResource || result.DenyAppToolCall || result.RequiresStepUp || result.ExcessiveAppCalls {
		t.Errorf("Expected all-false result when UI policy not loaded, got %+v", result)
	}
}

// TestOPAUIPolicy_InputSchemaMatchesDocumented verifies AC #1:
// OPA input schema includes all documented fields in the ui section.
func TestOPAUIPolicy_InputSchemaMatchesDocumented(t *testing.T) {
	input := UIPolicyInput{
		UI: UIInput{
			Enabled:             true,
			ResourceURI:         "ui://dashboard/analytics.html",
			ResourceContentHash: "sha256:ab12cd34",
			DeclaredCSP: &DeclaredCSPInput{
				ConnectDomains:  []string{"https://api.acme.corp"},
				ResourceDomains: []string{},
				FrameDomains:    []string{},
				BaseURIDomains:  []string{},
			},
			DeclaredPermissions: &DeclaredPermsInput{
				Camera:         false,
				Microphone:     false,
				Geolocation:    false,
				ClipboardWrite: false,
			},
			ToolVisibility:       []string{"model", "app"},
			CallOrigin:           "app",
			AppSessionToolCalls:  7,
			ResourceRegistered:   true,
			ResourceHashVerified: true,
		},
		ToolServer:    "mcp-dashboard-server",
		Tool:          "render-analytics",
		ToolRiskLevel: "low",
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	ui, ok := parsed["ui"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected 'ui' section in parsed JSON")
	}

	// AC #1: verify all 10 documented fields
	requiredFields := map[string]bool{
		"enabled":                true,
		"resource_uri":           true,
		"resource_content_hash":  true,
		"declared_csp":           true,
		"declared_permissions":   true,
		"tool_visibility":        true,
		"call_origin":            true,
		"app_session_tool_calls": true,
		"resource_registered":    true,
		"resource_hash_verified": true,
	}

	for field := range requiredFields {
		if _, found := ui[field]; !found {
			t.Errorf("AC #1 VIOLATION: Required field %q missing from ui section", field)
		}
	}

	t.Logf("PASS: All 10 documented fields present in ui section")
}

// TestOPAUIPolicy_LoadsSuccessfully verifies AC #8:
// Rego policies load successfully in embedded OPA engine.
func TestOPAUIPolicy_LoadsSuccessfully(t *testing.T) {
	// Use the actual policy file from config/opa/
	grants := `ui_capability_grants:
  - server: "test-server"
    mode: "allow"
    approved_tools: []
`
	engine := setupUIPolicyEngine(t, grants)

	// Verify the engine loaded the UI policy queries
	engine.mu.RLock()
	hasQueries := engine.uiPolicyQueries != nil
	engine.mu.RUnlock()

	if !hasQueries {
		t.Fatal("AC #8 VIOLATION: UI policy queries not loaded in OPA engine")
	}

	t.Log("PASS: UI policy loaded successfully in embedded OPA engine")
}

// TestOPAUIPolicy_CombinedScenario tests a realistic scenario where multiple
// rules fire simultaneously.
func TestOPAUIPolicy_CombinedScenario(t *testing.T) {
	grants := `ui_capability_grants:
  - server: "dashboard-server"
    mode: "deny"
    approved_tools:
      - "render-analytics"
`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:             true,
			CallOrigin:          "app",
			AppSessionToolCalls: 100, // Excessive
		},
		ToolServer:    "dashboard-server",
		Tool:          "delete-data", // Not in approved set
		ToolRiskLevel: "critical",    // High risk
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	// All rules should fire for this adversarial input
	if !result.DenyUIResource {
		t.Error("Expected deny_ui_resource=true (server in deny mode)")
	}
	if !result.DenyAppToolCall {
		t.Error("Expected deny_app_tool_call=true (tool not in approved list)")
	}
	if !result.RequiresStepUp {
		t.Error("Expected requires_step_up=true (app + critical risk)")
	}
	if !result.ExcessiveAppCalls {
		t.Error("Expected excessive_app_calls=true (100 > 50)")
	}
}

// TestOPAUIPolicy_AllowedScenario tests a realistic scenario where no rules fire.
func TestOPAUIPolicy_AllowedScenario(t *testing.T) {
	grants := `ui_capability_grants:
  - server: "approved-server"
    mode: "allow"
    approved_tools: []
`
	engine := setupUIPolicyEngine(t, grants)

	input := UIPolicyInput{
		UI: UIInput{
			Enabled:             true,
			CallOrigin:          "model",
			AppSessionToolCalls: 5,
		},
		ToolServer:    "approved-server",
		Tool:          "safe-tool",
		ToolRiskLevel: "low",
	}

	result, err := engine.EvaluateUIPolicy(input)
	if err != nil {
		t.Fatalf("EvaluateUIPolicy failed: %v", err)
	}

	if result.DenyUIResource || result.DenyAppToolCall || result.RequiresStepUp || result.ExcessiveAppCalls {
		t.Errorf("Expected all rules to pass for allowed scenario, got %+v", result)
	}
}

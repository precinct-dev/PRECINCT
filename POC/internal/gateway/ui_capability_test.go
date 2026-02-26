package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/testutil"
)

func mustWriteTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustUnmarshalJSON(t *testing.T, data []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}
}

// --- Grant Loading Tests ---

func TestLoadUICapabilityGrants_ValidFile(t *testing.T) {
	yamlContent := `
ui_capability_grants:
  - server: "mcp-dashboard-server"
    tenant: "acme-corp"
    mode: "allow"
    approved_tools:
      - "render-analytics"
      - "show-chart"
    max_resource_size_bytes: 2097152
    allowed_csp_connect_domains:
      - "https://api.acme.corp"
    allowed_permissions: []
    approved_at: "2026-02-01T00:00:00Z"
    approved_by: "security-review@acme.corp"
  - server: "mcp-reporting-server"
    tenant: "acme-corp"
    mode: "audit-only"
    approved_tools: []
    max_resource_size_bytes: 1048576
    allowed_csp_connect_domains: []
    allowed_permissions: []
    approved_at: "2026-02-01T00:00:00Z"
    approved_by: "security-review@acme.corp"
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	grants, err := LoadUICapabilityGrants(tmpFile)
	if err != nil {
		t.Fatalf("Failed to load grants: %v", err)
	}

	if len(grants) != 2 {
		t.Fatalf("Expected 2 grants, got %d", len(grants))
	}

	// Verify first grant
	if grants[0].Server != "mcp-dashboard-server" {
		t.Errorf("Expected server=mcp-dashboard-server, got %s", grants[0].Server)
	}
	if grants[0].Tenant != "acme-corp" {
		t.Errorf("Expected tenant=acme-corp, got %s", grants[0].Tenant)
	}
	if grants[0].Mode != "allow" {
		t.Errorf("Expected mode=allow, got %s", grants[0].Mode)
	}
	if len(grants[0].ApprovedTools) != 2 {
		t.Errorf("Expected 2 approved tools, got %d", len(grants[0].ApprovedTools))
	}
	if grants[0].MaxResourceSizeBytes != 2097152 {
		t.Errorf("Expected MaxResourceSizeBytes=2097152, got %d", grants[0].MaxResourceSizeBytes)
	}
	if len(grants[0].AllowedCSPConnectDomains) != 1 {
		t.Errorf("Expected 1 allowed CSP connect domain, got %d", len(grants[0].AllowedCSPConnectDomains))
	}

	// Verify second grant
	if grants[1].Mode != "audit-only" {
		t.Errorf("Expected mode=audit-only for second grant, got %s", grants[1].Mode)
	}
}

func TestLoadUICapabilityGrants_FileNotFound(t *testing.T) {
	_, err := LoadUICapabilityGrants("/nonexistent/path/grants.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestLoadUICapabilityGrants_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "bad.yaml")
	if err := os.WriteFile(tmpFile, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	_, err := LoadUICapabilityGrants(tmpFile)
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}
}

func TestLoadUICapabilityGrants_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "empty.yaml")
	if err := os.WriteFile(tmpFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	grants, err := LoadUICapabilityGrants(tmpFile)
	if err != nil {
		t.Fatalf("Expected no error for empty file, got: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("Expected 0 grants from empty file, got %d", len(grants))
	}
}

func TestLoadUICapabilityGrants_FromRealOPAFile(t *testing.T) {
	// Test loading the actual ui_capability_grants.yaml from config/opa/
	grants, err := LoadUICapabilityGrants(testutil.UICapabilityGrantsPath())
	if err != nil {
		t.Fatalf("Failed to load real grants file: %v", err)
	}

	if len(grants) < 1 {
		t.Error("Expected at least one grant in the real grants file")
	}
}

// --- NewUICapabilityGating Tests ---

func TestNewUICapabilityGating_WithValidFile(t *testing.T) {
	yamlContent := `
ui_capability_grants:
  - server: "test-server"
    tenant: "test-tenant"
    mode: "allow"
    approved_tools: ["tool-a"]
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	gating := NewUICapabilityGating(uiConfig, tmpFile)
	if gating == nil {
		t.Fatal("Expected non-nil gating")
	}

	grant := gating.LookupGrant("test-server", "test-tenant")
	if grant == nil {
		t.Fatal("Expected to find grant for test-server|test-tenant")
	}
	if grant.Mode != "allow" {
		t.Errorf("Expected mode=allow, got %s", grant.Mode)
	}
}

func TestNewUICapabilityGating_WithNoFile(t *testing.T) {
	uiConfig := UIConfigDefaults()
	gating := NewUICapabilityGating(uiConfig, "")
	if gating == nil {
		t.Fatal("Expected non-nil gating even with no file")
	}
	if len(gating.grants) != 0 {
		t.Errorf("Expected 0 grants with no file, got %d", len(gating.grants))
	}
}

func TestNewUICapabilityGating_WithMissingFile(t *testing.T) {
	uiConfig := UIConfigDefaults()
	// Should not panic; logs warning and operates with no grants
	gating := NewUICapabilityGating(uiConfig, "/nonexistent/file.yaml")
	if gating == nil {
		t.Fatal("Expected non-nil gating even with missing file")
	}
	if len(gating.grants) != 0 {
		t.Errorf("Expected 0 grants with missing file, got %d", len(gating.grants))
	}
}

// --- ResolveMode Tests ---

func TestResolveMode_GlobalKillSwitchOff(t *testing.T) {
	// AC#5: Global kill switch (ui.enabled=false) strips ALL _meta.ui
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = false // kill switch off

	yamlContent := `
ui_capability_grants:
  - server: "test-server"
    tenant: "test-tenant"
    mode: "allow"
    approved_tools: []
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)

	// Even though grant says "allow", kill switch overrides to deny
	mode := gating.ResolveMode("test-server", "test-tenant")
	if mode != UICapabilityModeDeny {
		t.Errorf("Expected deny mode when kill switch is off, got %s", mode)
	}
}

func TestResolveMode_ExplicitGrant(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	yamlContent := `
ui_capability_grants:
  - server: "allow-server"
    tenant: "tenant-a"
    mode: "allow"
    approved_tools: []
  - server: "audit-server"
    tenant: "tenant-a"
    mode: "audit-only"
    approved_tools: []
  - server: "deny-server"
    tenant: "tenant-a"
    mode: "deny"
    approved_tools: []
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)

	// AC#1: Three enforcement modes work
	if m := gating.ResolveMode("allow-server", "tenant-a"); m != UICapabilityModeAllow {
		t.Errorf("Expected allow, got %s", m)
	}
	if m := gating.ResolveMode("audit-server", "tenant-a"); m != UICapabilityModeAuditOnly {
		t.Errorf("Expected audit-only, got %s", m)
	}
	if m := gating.ResolveMode("deny-server", "tenant-a"); m != UICapabilityModeDeny {
		t.Errorf("Expected deny, got %s", m)
	}
}

func TestResolveMode_NoGrantFallsBackToDefaultMode(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true
	uiConfig.DefaultMode = "audit-only"

	gating := NewUICapabilityGating(uiConfig, "")

	// No grant -> falls back to default_mode
	mode := gating.ResolveMode("unknown-server", "unknown-tenant")
	if mode != UICapabilityModeAuditOnly {
		t.Errorf("Expected audit-only from default mode, got %s", mode)
	}
}

func TestResolveMode_DefaultModeDeny(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true
	uiConfig.DefaultMode = "deny"

	gating := NewUICapabilityGating(uiConfig, "")

	mode := gating.ResolveMode("any-server", "any-tenant")
	if mode != UICapabilityModeDeny {
		t.Errorf("Expected deny from default mode, got %s", mode)
	}
}

func TestResolveMode_InvalidModeDefaultsToDeny(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	yamlContent := `
ui_capability_grants:
  - server: "bad-mode-server"
    tenant: "tenant-a"
    mode: "invalid-mode"
    approved_tools: []
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)

	// Invalid mode should fail closed to deny
	mode := gating.ResolveMode("bad-mode-server", "tenant-a")
	if mode != UICapabilityModeDeny {
		t.Errorf("Expected deny for invalid mode, got %s", mode)
	}
}

// --- IsToolApproved Tests ---

func TestIsToolApproved_EmptyListApprovesAll(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	yamlContent := `
ui_capability_grants:
  - server: "server-a"
    tenant: "tenant-a"
    mode: "allow"
    approved_tools: []
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)

	// Empty approved_tools list means all tools are approved
	if !gating.IsToolApproved("server-a", "tenant-a", "any-tool") {
		t.Error("Expected all tools approved when approved_tools is empty")
	}
}

func TestIsToolApproved_NonEmptyListFilters(t *testing.T) {
	// AC#3: allow mode permits _meta.ui for approved tools only
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	yamlContent := `
ui_capability_grants:
  - server: "server-a"
    tenant: "tenant-a"
    mode: "allow"
    approved_tools:
      - "render-analytics"
      - "show-chart"
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)

	if !gating.IsToolApproved("server-a", "tenant-a", "render-analytics") {
		t.Error("Expected render-analytics to be approved")
	}
	if !gating.IsToolApproved("server-a", "tenant-a", "show-chart") {
		t.Error("Expected show-chart to be approved")
	}
	if gating.IsToolApproved("server-a", "tenant-a", "unapproved-tool") {
		t.Error("Expected unapproved-tool to NOT be approved")
	}
}

func TestIsToolApproved_NoGrantReturnsFalse(t *testing.T) {
	uiConfig := UIConfigDefaults()
	gating := NewUICapabilityGating(uiConfig, "")

	if gating.IsToolApproved("no-such-server", "no-such-tenant", "any-tool") {
		t.Error("Expected false when no grant exists")
	}
}

// --- ApplyUICapabilityGating Tests ---

// Helper to build a tools/list JSON-RPC response body
func buildToolsListResponse(tools []map[string]interface{}) []byte {
	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]interface{}{
			"tools": tools,
		},
	}
	b, _ := json.Marshal(response)
	return b
}

func TestApplyUICapabilityGating_DenyModeStripsMetaUI(t *testing.T) {
	// AC#2: deny mode strips _meta.ui from tool listings
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true
	uiConfig.DefaultMode = "deny" // no grant, falls back to deny

	gating := NewUICapabilityGating(uiConfig, "")

	tools := []map[string]interface{}{
		{
			"name":        "render-analytics",
			"description": "Render analytics",
			"_meta": map[string]interface{}{
				"ui": map[string]interface{}{
					"resourceUri": "ui://dashboard-server/analytics.html",
				},
			},
		},
		{
			"name":        "plain-tool",
			"description": "A regular tool",
		},
	}
	body := buildToolsListResponse(tools)

	processed, events, err := gating.ApplyUICapabilityGating(body, "some-server", "some-tenant")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify _meta.ui was stripped
	var result map[string]interface{}
	mustUnmarshalJSON(t, processed, &result)
	resultMap := result["result"].(map[string]interface{})
	toolList := resultMap["tools"].([]interface{})

	for _, toolItem := range toolList {
		tool := toolItem.(map[string]interface{})
		toolName := tool["name"].(string)

		if toolName == "render-analytics" {
			// _meta should be removed (it only had "ui")
			if _, has := tool["_meta"]; has {
				t.Error("Expected _meta to be removed from render-analytics in deny mode")
			}
		}
	}

	// Verify audit event emitted
	if len(events) == 0 {
		t.Error("Expected at least one audit event")
	}

	found := false
	for _, e := range events {
		if e.EventType == "ui.capability.stripped" && e.Reason == "server_not_approved" {
			found = true
		}
	}
	if !found {
		t.Error("Expected ui.capability.stripped event with reason=server_not_approved")
	}
}

func TestApplyUICapabilityGating_DenyModePreservesOtherMeta(t *testing.T) {
	// When _meta has both "ui" and other fields, only "ui" should be removed
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true
	uiConfig.DefaultMode = "deny"

	gating := NewUICapabilityGating(uiConfig, "")

	tools := []map[string]interface{}{
		{
			"name": "render-analytics",
			"_meta": map[string]interface{}{
				"ui":      map[string]interface{}{"resourceUri": "ui://test"},
				"version": "1.0",
			},
		},
	}
	body := buildToolsListResponse(tools)

	processed, _, err := gating.ApplyUICapabilityGating(body, "srv", "tnt")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var result map[string]interface{}
	mustUnmarshalJSON(t, processed, &result)
	toolList := result["result"].(map[string]interface{})["tools"].([]interface{})
	tool := toolList[0].(map[string]interface{})

	meta, has := tool["_meta"]
	if !has {
		t.Fatal("Expected _meta to still exist (has version field)")
	}
	metaMap := meta.(map[string]interface{})
	if _, hasUI := metaMap["ui"]; hasUI {
		t.Error("Expected _meta.ui to be removed")
	}
	if metaMap["version"] != "1.0" {
		t.Error("Expected _meta.version to be preserved")
	}
}

func TestApplyUICapabilityGating_AuditOnlyModeKeepsMetaUI(t *testing.T) {
	// AC#4: audit-only mode passes _meta.ui through but emits audit event
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	yamlContent := `
ui_capability_grants:
  - server: "audit-server"
    tenant: "tenant-a"
    mode: "audit-only"
    approved_tools: []
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)

	tools := []map[string]interface{}{
		{
			"name": "render-analytics",
			"_meta": map[string]interface{}{
				"ui": map[string]interface{}{
					"resourceUri": "ui://audit-server/analytics.html",
				},
			},
		},
	}
	body := buildToolsListResponse(tools)

	processed, events, err := gating.ApplyUICapabilityGating(body, "audit-server", "tenant-a")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify _meta.ui is preserved
	var result map[string]interface{}
	mustUnmarshalJSON(t, processed, &result)
	toolList := result["result"].(map[string]interface{})["tools"].([]interface{})
	tool := toolList[0].(map[string]interface{})

	meta, has := tool["_meta"]
	if !has {
		t.Error("Expected _meta to be preserved in audit-only mode")
	}
	metaMap := meta.(map[string]interface{})
	if _, hasUI := metaMap["ui"]; !hasUI {
		t.Error("Expected _meta.ui to be preserved in audit-only mode")
	}

	// Verify audit event emitted
	if len(events) == 0 {
		t.Error("Expected audit event in audit-only mode")
	}
	found := false
	for _, e := range events {
		if e.EventType == "ui.capability.audit_passthrough" {
			found = true
		}
	}
	if !found {
		t.Error("Expected ui.capability.audit_passthrough event")
	}
}

func TestApplyUICapabilityGating_AllowModeWithApprovedTools(t *testing.T) {
	// AC#3: allow mode permits _meta.ui for approved tools only
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	yamlContent := `
ui_capability_grants:
  - server: "dashboard-server"
    tenant: "acme"
    mode: "allow"
    approved_tools:
      - "render-analytics"
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)

	tools := []map[string]interface{}{
		{
			"name": "render-analytics", // approved
			"_meta": map[string]interface{}{
				"ui": map[string]interface{}{
					"resourceUri": "ui://dashboard-server/analytics.html",
				},
			},
		},
		{
			"name": "unapproved-tool", // NOT approved
			"_meta": map[string]interface{}{
				"ui": map[string]interface{}{
					"resourceUri": "ui://dashboard-server/unauthorized.html",
				},
			},
		},
	}
	body := buildToolsListResponse(tools)

	processed, events, err := gating.ApplyUICapabilityGating(body, "dashboard-server", "acme")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var result map[string]interface{}
	mustUnmarshalJSON(t, processed, &result)
	toolList := result["result"].(map[string]interface{})["tools"].([]interface{})

	for _, toolItem := range toolList {
		tool := toolItem.(map[string]interface{})
		toolName := tool["name"].(string)

		switch toolName {
		case "render-analytics":
			// Approved - _meta.ui should be preserved
			meta, has := tool["_meta"]
			if !has {
				t.Error("Expected _meta preserved for approved tool render-analytics")
				continue
			}
			metaMap := meta.(map[string]interface{})
			if _, hasUI := metaMap["ui"]; !hasUI {
				t.Error("Expected _meta.ui preserved for approved tool render-analytics")
			}
		case "unapproved-tool":
			// NOT approved - _meta.ui should be stripped
			if _, has := tool["_meta"]; has {
				t.Error("Expected _meta to be removed for unapproved tool")
			}
		}
	}

	// Verify stripped event for unapproved tool
	foundStripped := false
	for _, e := range events {
		if e.EventType == "ui.capability.stripped" && e.ToolName == "unapproved-tool" && e.Reason == "tool_not_in_approved_list" {
			foundStripped = true
		}
	}
	if !foundStripped {
		t.Error("Expected ui.capability.stripped event for unapproved tool")
	}
}

func TestApplyUICapabilityGating_AllowModeEmptyApprovedToolsAllowsAll(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	yamlContent := `
ui_capability_grants:
  - server: "dashboard-server"
    tenant: "acme"
    mode: "allow"
    approved_tools: []
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)

	tools := []map[string]interface{}{
		{
			"name": "any-tool",
			"_meta": map[string]interface{}{
				"ui": map[string]interface{}{
					"resourceUri": "ui://dashboard-server/any.html",
				},
			},
		},
	}
	body := buildToolsListResponse(tools)

	processed, events, err := gating.ApplyUICapabilityGating(body, "dashboard-server", "acme")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// _meta.ui should be preserved for all tools
	var result map[string]interface{}
	mustUnmarshalJSON(t, processed, &result)
	toolList := result["result"].(map[string]interface{})["tools"].([]interface{})
	tool := toolList[0].(map[string]interface{})

	meta, has := tool["_meta"]
	if !has {
		t.Error("Expected _meta preserved when approved_tools is empty (allows all)")
	} else {
		metaMap := meta.(map[string]interface{})
		if _, hasUI := metaMap["ui"]; !hasUI {
			t.Error("Expected _meta.ui preserved when approved_tools is empty (allows all)")
		}
	}

	// No stripped events expected
	for _, e := range events {
		if e.EventType == "ui.capability.stripped" {
			t.Errorf("Did not expect any stripped events, got: %v", e)
		}
	}
}

func TestApplyUICapabilityGating_GlobalKillSwitchOverridesGrant(t *testing.T) {
	// AC#5: Global kill switch strips ALL _meta.ui regardless of grants
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = false // KILL SWITCH OFF

	yamlContent := `
ui_capability_grants:
  - server: "dashboard-server"
    tenant: "acme"
    mode: "allow"
    approved_tools: []
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)

	tools := []map[string]interface{}{
		{
			"name": "render-analytics",
			"_meta": map[string]interface{}{
				"ui": map[string]interface{}{
					"resourceUri": "ui://dashboard-server/analytics.html",
				},
			},
		},
	}
	body := buildToolsListResponse(tools)

	processed, events, err := gating.ApplyUICapabilityGating(body, "dashboard-server", "acme")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// _meta.ui should be stripped despite grant saying "allow"
	var result map[string]interface{}
	mustUnmarshalJSON(t, processed, &result)
	toolList := result["result"].(map[string]interface{})["tools"].([]interface{})
	tool := toolList[0].(map[string]interface{})

	if _, has := tool["_meta"]; has {
		t.Error("Expected _meta stripped when global kill switch is off, but _meta still present")
	}

	// Should emit stripped event
	if len(events) == 0 {
		t.Error("Expected stripped event when kill switch is off")
	}
}

func TestApplyUICapabilityGating_NoToolsField(t *testing.T) {
	uiConfig := UIConfigDefaults()
	gating := NewUICapabilityGating(uiConfig, "")

	// Response with no tools field
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"other":"data"}}`)
	processed, events, err := gating.ApplyUICapabilityGating(body, "s", "t")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("Expected no events for response without tools, got %d", len(events))
	}
	_ = processed
}

func TestApplyUICapabilityGating_NoResultField(t *testing.T) {
	uiConfig := UIConfigDefaults()
	gating := NewUICapabilityGating(uiConfig, "")

	body := []byte(`{"jsonrpc":"2.0","id":1}`)
	processed, events, err := gating.ApplyUICapabilityGating(body, "s", "t")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("Expected no events, got %d", len(events))
	}
	_ = processed
}

func TestApplyUICapabilityGating_InvalidJSON(t *testing.T) {
	uiConfig := UIConfigDefaults()
	gating := NewUICapabilityGating(uiConfig, "")

	body := []byte(`{invalid json}`)
	_, _, err := gating.ApplyUICapabilityGating(body, "s", "t")
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestApplyUICapabilityGating_ToolsWithNoMetaUI(t *testing.T) {
	// AC#7: Graceful downgrade - tools without _meta.ui appear as standard tools
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true
	uiConfig.DefaultMode = "deny"

	gating := NewUICapabilityGating(uiConfig, "")

	tools := []map[string]interface{}{
		{
			"name":        "standard-tool",
			"description": "No UI metadata",
		},
	}
	body := buildToolsListResponse(tools)

	processed, events, err := gating.ApplyUICapabilityGating(body, "s", "t")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Standard tools should be unmodified
	var result map[string]interface{}
	mustUnmarshalJSON(t, processed, &result)
	toolList := result["result"].(map[string]interface{})["tools"].([]interface{})
	tool := toolList[0].(map[string]interface{})

	if tool["name"] != "standard-tool" {
		t.Error("Standard tool should be unmodified")
	}

	// No events expected for tools without _meta.ui
	if len(events) != 0 {
		t.Errorf("Expected no events for tools without _meta.ui, got %d", len(events))
	}
}

func TestApplyUICapabilityGating_MultipleToolsMixedModes(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	yamlContent := `
ui_capability_grants:
  - server: "mixed-server"
    tenant: "tenant-a"
    mode: "allow"
    approved_tools:
      - "approved-ui-tool"
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)

	tools := []map[string]interface{}{
		{
			"name": "approved-ui-tool",
			"_meta": map[string]interface{}{
				"ui": map[string]interface{}{"resourceUri": "ui://mixed-server/a.html"},
			},
		},
		{
			"name": "unapproved-ui-tool",
			"_meta": map[string]interface{}{
				"ui": map[string]interface{}{"resourceUri": "ui://mixed-server/b.html"},
			},
		},
		{
			"name":        "standard-tool",
			"description": "No UI",
		},
	}
	body := buildToolsListResponse(tools)

	processed, events, err := gating.ApplyUICapabilityGating(body, "mixed-server", "tenant-a")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var result map[string]interface{}
	mustUnmarshalJSON(t, processed, &result)
	toolList := result["result"].(map[string]interface{})["tools"].([]interface{})

	for _, toolItem := range toolList {
		tool := toolItem.(map[string]interface{})
		name := tool["name"].(string)

		switch name {
		case "approved-ui-tool":
			if _, has := tool["_meta"]; !has {
				t.Error("approved-ui-tool should have _meta preserved")
			}
		case "unapproved-ui-tool":
			if _, has := tool["_meta"]; has {
				t.Error("unapproved-ui-tool should have _meta stripped")
			}
		case "standard-tool":
			if _, has := tool["_meta"]; has {
				t.Error("standard-tool should not have _meta (never had it)")
			}
		}
	}

	// Should have exactly one stripped event
	strippedCount := 0
	for _, e := range events {
		if e.EventType == "ui.capability.stripped" {
			strippedCount++
		}
	}
	if strippedCount != 1 {
		t.Errorf("Expected exactly 1 stripped event, got %d", strippedCount)
	}
}

// --- CheckUIResourceReadAllowed Tests ---

func TestCheckUIResourceReadAllowed_DenyMode(t *testing.T) {
	// AC#2: deny mode blocks ui:// reads with HTTP 403
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true
	uiConfig.DefaultMode = "deny"

	gating := NewUICapabilityGating(uiConfig, "")

	allowed, event := gating.CheckUIResourceReadAllowed("server", "tenant", "ui://server/resource.html")
	if allowed {
		t.Error("Expected ui:// read to be blocked in deny mode")
	}
	if event == nil {
		t.Fatal("Expected event for blocked read")
	}
	if event.EventType != "ui.resource.blocked" {
		t.Errorf("Expected event_type=ui.resource.blocked, got %s", event.EventType)
	}
}

func TestCheckUIResourceReadAllowed_AllowMode(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	yamlContent := `
ui_capability_grants:
  - server: "allowed-server"
    tenant: "tenant-a"
    mode: "allow"
    approved_tools: []
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)

	allowed, event := gating.CheckUIResourceReadAllowed("allowed-server", "tenant-a", "ui://allowed-server/resource.html")
	if !allowed {
		t.Error("Expected ui:// read to be allowed in allow mode")
	}
	if event != nil {
		t.Error("Expected no event for allowed read in allow mode")
	}
}

func TestCheckUIResourceReadAllowed_AuditOnlyMode(t *testing.T) {
	// AC#4: audit-only mode allows but emits audit event
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	yamlContent := `
ui_capability_grants:
  - server: "audit-server"
    tenant: "tenant-a"
    mode: "audit-only"
    approved_tools: []
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)

	allowed, event := gating.CheckUIResourceReadAllowed("audit-server", "tenant-a", "ui://audit-server/resource.html")
	if !allowed {
		t.Error("Expected ui:// read to be allowed in audit-only mode")
	}
	if event == nil {
		t.Fatal("Expected audit event for audit-only mode")
	}
	if event.EventType != "ui.capability.audit_passthrough" {
		t.Errorf("Expected event_type=ui.capability.audit_passthrough, got %s", event.EventType)
	}
}

func TestCheckUIResourceReadAllowed_GlobalKillSwitchBlocks(t *testing.T) {
	// AC#5: Global kill switch blocks all ui:// reads
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = false

	yamlContent := `
ui_capability_grants:
  - server: "allowed-server"
    tenant: "tenant-a"
    mode: "allow"
    approved_tools: []
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)

	allowed, event := gating.CheckUIResourceReadAllowed("allowed-server", "tenant-a", "ui://allowed-server/resource.html")
	if allowed {
		t.Error("Expected ui:// read to be blocked when kill switch is off")
	}
	if event == nil {
		t.Fatal("Expected event when kill switch blocks")
	}
}

// --- IsUIResourceURI Tests ---

func TestIsUIResourceURI(t *testing.T) {
	testCases := []struct {
		uri      string
		expected bool
	}{
		{"ui://server/resource.html", true},
		{"ui://dashboard-server/analytics.html", true},
		{"ui://", true},
		{"http://example.com", false},
		{"https://example.com", false},
		{"file:///etc/passwd", false},
		{"", false},
		{"UI://server/resource.html", false}, // Case-sensitive
	}

	for _, tc := range testCases {
		t.Run(tc.uri, func(t *testing.T) {
			result := IsUIResourceURI(tc.uri)
			if result != tc.expected {
				t.Errorf("IsUIResourceURI(%q) = %v, want %v", tc.uri, result, tc.expected)
			}
		})
	}
}

// --- parseCapabilityMode Tests ---

func TestParseCapabilityMode(t *testing.T) {
	testCases := []struct {
		input    string
		expected UICapabilityMode
	}{
		{"deny", UICapabilityModeDeny},
		{"allow", UICapabilityModeAllow},
		{"audit-only", UICapabilityModeAuditOnly},
		{"", UICapabilityModeDeny},
		{"invalid", UICapabilityModeDeny},
		{"DENY", UICapabilityModeDeny}, // Case-sensitive, invalid falls to deny
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := parseCapabilityMode(tc.input)
			if result != tc.expected {
				t.Errorf("parseCapabilityMode(%q) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

// --- LookupGrant Tests ---

func TestLookupGrant_Found(t *testing.T) {
	uiConfig := UIConfigDefaults()

	yamlContent := `
ui_capability_grants:
  - server: "srv"
    tenant: "tnt"
    mode: "allow"
    approved_tools: ["tool1"]
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "grants.yaml")
	mustWriteTestFile(t, tmpFile, yamlContent)

	gating := NewUICapabilityGating(uiConfig, tmpFile)
	grant := gating.LookupGrant("srv", "tnt")
	if grant == nil {
		t.Fatal("Expected to find grant")
	}
	if grant.Server != "srv" || grant.Tenant != "tnt" {
		t.Error("Grant fields do not match")
	}
}

func TestLookupGrant_NotFound(t *testing.T) {
	uiConfig := UIConfigDefaults()
	gating := NewUICapabilityGating(uiConfig, "")
	grant := gating.LookupGrant("no-such", "no-such")
	if grant != nil {
		t.Error("Expected nil for non-existent grant")
	}
}

// --- UICapabilityGatingEvent Tests ---

func TestUICapabilityGatingEvent_JSONSerialization(t *testing.T) {
	event := UICapabilityGatingEvent{
		EventType: "ui.capability.stripped",
		Server:    "test-server",
		Tenant:    "test-tenant",
		ToolName:  "test-tool",
		Mode:      "deny",
		Reason:    "server_not_approved",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal event: %v", err)
	}

	jsonStr := string(data)
	if !strings.Contains(jsonStr, "ui.capability.stripped") {
		t.Error("Expected event_type in JSON")
	}
	if !strings.Contains(jsonStr, "test-server") {
		t.Error("Expected server in JSON")
	}
}

// --- Integration: Config includes UICapabilityGrantsPath ---

func TestConfigHasUICapabilityGrantsPath(t *testing.T) {
	cfg := ConfigFromEnv()
	if cfg.UICapabilityGrantsPath == "" {
		t.Error("Expected UICapabilityGrantsPath to have a default value")
	}
	if !strings.Contains(cfg.UICapabilityGrantsPath, "ui_capability_grants") {
		t.Errorf("Expected UICapabilityGrantsPath to contain 'ui_capability_grants', got %s", cfg.UICapabilityGrantsPath)
	}
}

func TestConfigUICapabilityGrantsPathEnvOverride(t *testing.T) {
	t.Setenv("UI_CAPABILITY_GRANTS_PATH", "/custom/path/grants.yaml")
	cfg := ConfigFromEnv()
	if cfg.UICapabilityGrantsPath != "/custom/path/grants.yaml" {
		t.Errorf("Expected UICapabilityGrantsPath=/custom/path/grants.yaml, got %s", cfg.UICapabilityGrantsPath)
	}
}

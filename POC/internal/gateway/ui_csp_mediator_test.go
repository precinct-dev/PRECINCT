package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/testutil"
)

// --- MediateCSP Unit Tests ---

func TestMediateCSP_ConnectDomainsIntersection(t *testing.T) {
	// AC#1: CSP connectDomains intersected with grant's allowed_csp_connect_domains
	config := UIConfigDefaults()
	grant := &UICapabilityGrant{
		AllowedCSPConnectDomains: []string{
			"https://api.acme.corp",
			"https://data.acme.corp",
		},
	}

	input := UICSPInput{
		ConnectDomains: []string{
			"https://api.acme.corp",    // allowed
			"https://evil.example.com", // NOT allowed
			"https://data.acme.corp",   // allowed
		},
	}

	result := MediateCSP(input, grant, config, "srv", "tnt", "tool1")

	// Only allowed domains should remain
	if len(result.ConnectDomains) != 2 {
		t.Fatalf("Expected 2 connectDomains after intersection, got %d: %v",
			len(result.ConnectDomains), result.ConnectDomains)
	}
	if result.ConnectDomains[0] != "https://api.acme.corp" {
		t.Errorf("Expected first domain=https://api.acme.corp, got %s", result.ConnectDomains[0])
	}
	if result.ConnectDomains[1] != "https://data.acme.corp" {
		t.Errorf("Expected second domain=https://data.acme.corp, got %s", result.ConnectDomains[1])
	}

	// Verify stripped event for disallowed domain
	foundStripped := false
	for _, e := range result.Events {
		if e.EventType == "ui.csp.domain_stripped" &&
			e.Domain == "https://evil.example.com" &&
			e.Field == "connectDomains" &&
			e.Reason == "not_in_grant_allowlist" {
			foundStripped = true
		}
	}
	if !foundStripped {
		t.Error("Expected ui.csp.domain_stripped event for https://evil.example.com")
	}
}

func TestMediateCSP_FrameDomainsAlwaysEmpty(t *testing.T) {
	// AC#2: CSP frameDomains always empty (hard constraint)
	config := UIConfigDefaults()
	grant := &UICapabilityGrant{}

	input := UICSPInput{
		FrameDomains: []string{
			"https://embed.example.com",
			"https://iframe.example.com",
		},
	}

	result := MediateCSP(input, grant, config, "srv", "tnt", "tool1")

	if len(result.FrameDomains) != 0 {
		t.Errorf("Expected frameDomains to be empty, got %v", result.FrameDomains)
	}

	// Verify stripped events for each frame domain
	frameStrippedCount := 0
	for _, e := range result.Events {
		if e.EventType == "ui.csp.domain_stripped" &&
			e.Field == "frameDomains" &&
			e.Reason == "hard_constraint_frame_domains_denied" {
			frameStrippedCount++
		}
	}
	if frameStrippedCount != 2 {
		t.Errorf("Expected 2 frame domain stripped events, got %d", frameStrippedCount)
	}
}

func TestMediateCSP_BaseURIDomainsAlwaysEmpty(t *testing.T) {
	// AC#3: CSP baseUriDomains always empty (hard constraint)
	config := UIConfigDefaults()
	grant := &UICapabilityGrant{}

	input := UICSPInput{
		BaseURIDomains: []string{
			"https://base.example.com",
		},
	}

	result := MediateCSP(input, grant, config, "srv", "tnt", "tool1")

	if len(result.BaseURIDomains) != 0 {
		t.Errorf("Expected baseUriDomains to be empty, got %v", result.BaseURIDomains)
	}

	// Verify stripped event
	foundStripped := false
	for _, e := range result.Events {
		if e.EventType == "ui.csp.domain_stripped" &&
			e.Field == "baseUriDomains" &&
			e.Reason == "hard_constraint_base_uri_denied" {
			foundStripped = true
		}
	}
	if !foundStripped {
		t.Error("Expected ui.csp.domain_stripped event for baseUriDomains")
	}
}

func TestMediateCSP_ResourceDomainsIntersection(t *testing.T) {
	// AC#4: CSP resourceDomains intersected with allowed list
	config := UIConfigDefaults()
	grant := &UICapabilityGrant{
		AllowedCSPResourceDomains: []string{
			"https://cdn.acme.corp",
			"https://static.acme.corp",
		},
	}

	input := UICSPInput{
		ResourceDomains: []string{
			"https://cdn.acme.corp",     // allowed
			"https://malicious.cdn.com", // NOT allowed
			"https://static.acme.corp",  // allowed
		},
	}

	result := MediateCSP(input, grant, config, "srv", "tnt", "tool1")

	if len(result.ResourceDomains) != 2 {
		t.Fatalf("Expected 2 resourceDomains after intersection, got %d", len(result.ResourceDomains))
	}
	if result.ResourceDomains[0] != "https://cdn.acme.corp" {
		t.Errorf("Expected first=https://cdn.acme.corp, got %s", result.ResourceDomains[0])
	}
	if result.ResourceDomains[1] != "https://static.acme.corp" {
		t.Errorf("Expected second=https://static.acme.corp, got %s", result.ResourceDomains[1])
	}
}

func TestMediateCSP_MaxConnectDomainsEnforced(t *testing.T) {
	// AC#6: Hard constraints override grants - max_connect_domains=5
	config := UIConfigDefaults()
	config.CSPHardConstraints.MaxConnectDomains = 5

	// Grant allows all 10 domains
	grant := &UICapabilityGrant{
		AllowedCSPConnectDomains: []string{
			"https://d1.example.com",
			"https://d2.example.com",
			"https://d3.example.com",
			"https://d4.example.com",
			"https://d5.example.com",
			"https://d6.example.com",
			"https://d7.example.com",
			"https://d8.example.com",
			"https://d9.example.com",
			"https://d10.example.com",
		},
	}

	// Server declares 10 domains (all in allowlist)
	input := UICSPInput{
		ConnectDomains: []string{
			"https://d1.example.com",
			"https://d2.example.com",
			"https://d3.example.com",
			"https://d4.example.com",
			"https://d5.example.com",
			"https://d6.example.com",
			"https://d7.example.com",
			"https://d8.example.com",
			"https://d9.example.com",
			"https://d10.example.com",
		},
	}

	result := MediateCSP(input, grant, config, "srv", "tnt", "tool1")

	// Only 5 should survive (max_connect_domains=5)
	if len(result.ConnectDomains) != 5 {
		t.Fatalf("Expected 5 connectDomains after max enforcement, got %d", len(result.ConnectDomains))
	}

	// Verify truncation events for domains 6-10
	truncatedCount := 0
	for _, e := range result.Events {
		if e.EventType == "ui.csp.domain_stripped" &&
			e.Field == "connectDomains" &&
			e.Reason == "max_domains_exceeded" {
			truncatedCount++
		}
	}
	if truncatedCount != 5 {
		t.Errorf("Expected 5 max_domains_exceeded events, got %d", truncatedCount)
	}
}

func TestMediateCSP_MaxResourceDomainsEnforced(t *testing.T) {
	config := UIConfigDefaults()
	config.CSPHardConstraints.MaxResourceDomains = 3

	domains := []string{
		"https://r1.example.com",
		"https://r2.example.com",
		"https://r3.example.com",
		"https://r4.example.com",
		"https://r5.example.com",
	}

	grant := &UICapabilityGrant{
		AllowedCSPResourceDomains: domains,
	}

	input := UICSPInput{
		ResourceDomains: domains,
	}

	result := MediateCSP(input, grant, config, "srv", "tnt", "tool1")

	if len(result.ResourceDomains) != 3 {
		t.Fatalf("Expected 3 resourceDomains after max enforcement, got %d", len(result.ResourceDomains))
	}
}

func TestMediateCSP_NilGrant(t *testing.T) {
	// No grant means no domains allowed
	config := UIConfigDefaults()

	input := UICSPInput{
		ConnectDomains:  []string{"https://api.example.com"},
		ResourceDomains: []string{"https://cdn.example.com"},
		FrameDomains:    []string{"https://embed.example.com"},
		BaseURIDomains:  []string{"https://base.example.com"},
	}

	result := MediateCSP(input, nil, config, "srv", "tnt", "tool1")

	if len(result.ConnectDomains) != 0 {
		t.Errorf("Expected empty connectDomains with nil grant, got %v", result.ConnectDomains)
	}
	if len(result.ResourceDomains) != 0 {
		t.Errorf("Expected empty resourceDomains with nil grant, got %v", result.ResourceDomains)
	}
	if len(result.FrameDomains) != 0 {
		t.Errorf("Expected empty frameDomains, got %v", result.FrameDomains)
	}
	if len(result.BaseURIDomains) != 0 {
		t.Errorf("Expected empty baseUriDomains, got %v", result.BaseURIDomains)
	}

	// Should have events for all stripped domains
	if len(result.Events) < 4 {
		t.Errorf("Expected at least 4 stripped events, got %d", len(result.Events))
	}
}

func TestMediateCSP_EmptyInput(t *testing.T) {
	config := UIConfigDefaults()
	grant := &UICapabilityGrant{
		AllowedCSPConnectDomains: []string{"https://api.example.com"},
	}

	input := UICSPInput{} // All empty

	result := MediateCSP(input, grant, config, "srv", "tnt", "tool1")

	if len(result.ConnectDomains) != 0 {
		t.Errorf("Expected empty connectDomains, got %v", result.ConnectDomains)
	}
	if len(result.ResourceDomains) != 0 {
		t.Errorf("Expected empty resourceDomains, got %v", result.ResourceDomains)
	}
	if len(result.FrameDomains) != 0 {
		t.Errorf("Expected empty frameDomains, got %v", result.FrameDomains)
	}
	if len(result.BaseURIDomains) != 0 {
		t.Errorf("Expected empty baseUriDomains, got %v", result.BaseURIDomains)
	}
	if len(result.Events) != 0 {
		t.Errorf("Expected no events for empty input, got %d", len(result.Events))
	}
}

func TestMediateCSP_GlobMatching(t *testing.T) {
	// Glob matching should work for wildcard patterns in allowlist
	config := UIConfigDefaults()
	grant := &UICapabilityGrant{
		AllowedCSPConnectDomains: []string{
			"*.acme.corp", // Wildcard pattern
		},
	}

	input := UICSPInput{
		ConnectDomains: []string{
			"api.acme.corp",    // matches *.acme.corp
			"data.acme.corp",   // matches *.acme.corp
			"evil.example.com", // does NOT match
		},
	}

	result := MediateCSP(input, grant, config, "srv", "tnt", "tool1")

	if len(result.ConnectDomains) != 2 {
		t.Fatalf("Expected 2 connectDomains with glob matching, got %d: %v",
			len(result.ConnectDomains), result.ConnectDomains)
	}
}

func TestMediateCSP_EmptyDomainsSkipped(t *testing.T) {
	config := UIConfigDefaults()
	grant := &UICapabilityGrant{}

	input := UICSPInput{
		FrameDomains:   []string{"", ""}, // Empty strings should not generate events
		BaseURIDomains: []string{"", ""},
	}

	result := MediateCSP(input, grant, config, "srv", "tnt", "tool1")

	if len(result.Events) != 0 {
		t.Errorf("Expected no events for empty domain strings, got %d", len(result.Events))
	}
}

func TestMediateCSP_AuditEventsContainServerTenantTool(t *testing.T) {
	// AC#7: Stripped domains logged as ui.csp.domain_stripped events
	config := UIConfigDefaults()
	grant := &UICapabilityGrant{}

	input := UICSPInput{
		ConnectDomains: []string{"https://stripped.example.com"},
	}

	result := MediateCSP(input, grant, config, "my-server", "my-tenant", "my-tool")

	if len(result.Events) == 0 {
		t.Fatal("Expected at least one event")
	}

	e := result.Events[0]
	if e.Server != "my-server" {
		t.Errorf("Expected server=my-server, got %s", e.Server)
	}
	if e.Tenant != "my-tenant" {
		t.Errorf("Expected tenant=my-tenant, got %s", e.Tenant)
	}
	if e.ToolName != "my-tool" {
		t.Errorf("Expected toolName=my-tool, got %s", e.ToolName)
	}
	if e.EventType != "ui.csp.domain_stripped" {
		t.Errorf("Expected eventType=ui.csp.domain_stripped, got %s", e.EventType)
	}
}

// --- MediatePermissions Unit Tests ---

func TestMediatePermissions_AllDeniedByHardConstraints(t *testing.T) {
	// AC#6: Hard constraints override grants
	config := UIConfigDefaults() // All permissions denied by default

	grant := &UICapabilityGrant{
		AllowedPermissions: []string{
			"camera", "microphone", "geolocation", "clipboardWrite",
		},
	}

	input := UIPermissionsInput{
		Camera:         true,
		Microphone:     true,
		Geolocation:    true,
		ClipboardWrite: true,
	}

	result := MediatePermissions(input, grant, config, "srv", "tnt", "tool1")

	// All should be denied because hard constraints say no
	if result.Camera {
		t.Error("Expected camera denied by hard constraint")
	}
	if result.Microphone {
		t.Error("Expected microphone denied by hard constraint")
	}
	if result.Geolocation {
		t.Error("Expected geolocation denied by hard constraint")
	}
	if result.ClipboardWrite {
		t.Error("Expected clipboardWrite denied by hard constraint")
	}

	// Should have 4 denial events
	if len(result.Events) != 4 {
		t.Errorf("Expected 4 denial events, got %d", len(result.Events))
	}

	for _, e := range result.Events {
		if e.EventType != "ui.permission.denied" {
			t.Errorf("Expected ui.permission.denied, got %s", e.EventType)
		}
		if e.Reason != "hard_constraint_camera_denied" &&
			e.Reason != "hard_constraint_microphone_denied" &&
			e.Reason != "hard_constraint_geolocation_denied" &&
			e.Reason != "hard_constraint_clipboard_write_denied" {
			t.Errorf("Unexpected denial reason: %s", e.Reason)
		}
	}
}

func TestMediatePermissions_DeniedByGrant(t *testing.T) {
	// AC#5: Permissions denied unless in grant's allowed_permissions
	config := UIConfigDefaults()
	// Enable all hard constraints so grant controls the outcome
	config.PermissionsHardConstraints.CameraAllowed = true
	config.PermissionsHardConstraints.MicrophoneAllowed = true
	config.PermissionsHardConstraints.GeolocationAllowed = true
	config.PermissionsHardConstraints.ClipboardWriteAllowed = true

	// Grant only allows camera
	grant := &UICapabilityGrant{
		AllowedPermissions: []string{"camera"},
	}

	input := UIPermissionsInput{
		Camera:         true,
		Microphone:     true,
		Geolocation:    true,
		ClipboardWrite: true,
	}

	result := MediatePermissions(input, grant, config, "srv", "tnt", "tool1")

	if !result.Camera {
		t.Error("Expected camera allowed (in grant + hard constraint allows)")
	}
	if result.Microphone {
		t.Error("Expected microphone denied (not in grant)")
	}
	if result.Geolocation {
		t.Error("Expected geolocation denied (not in grant)")
	}
	if result.ClipboardWrite {
		t.Error("Expected clipboardWrite denied (not in grant)")
	}

	// Should have 3 denial events (mic, geo, clipboard)
	if len(result.Events) != 3 {
		t.Errorf("Expected 3 denial events, got %d", len(result.Events))
	}

	for _, e := range result.Events {
		if e.Reason != "not_in_grant_allowed_permissions" {
			t.Errorf("Expected reason=not_in_grant_allowed_permissions, got %s", e.Reason)
		}
	}
}

func TestMediatePermissions_CameraNoGrant(t *testing.T) {
	// AC#5 specific case: camera=true with no grant -> denied
	config := UIConfigDefaults()
	config.PermissionsHardConstraints.CameraAllowed = true // Hard constraint allows

	input := UIPermissionsInput{
		Camera: true,
	}

	// No grant (nil)
	result := MediatePermissions(input, nil, config, "srv", "tnt", "tool1")

	if result.Camera {
		t.Error("Expected camera denied with nil grant")
	}

	// AC#8: Denied permissions logged
	if len(result.Events) != 1 {
		t.Fatalf("Expected 1 denial event, got %d", len(result.Events))
	}
	if result.Events[0].EventType != "ui.permission.denied" {
		t.Errorf("Expected ui.permission.denied, got %s", result.Events[0].EventType)
	}
	if result.Events[0].Field != "camera" {
		t.Errorf("Expected field=camera, got %s", result.Events[0].Field)
	}
}

func TestMediatePermissions_AllAllowed(t *testing.T) {
	config := UIConfigDefaults()
	config.PermissionsHardConstraints.CameraAllowed = true
	config.PermissionsHardConstraints.MicrophoneAllowed = true
	config.PermissionsHardConstraints.GeolocationAllowed = true
	config.PermissionsHardConstraints.ClipboardWriteAllowed = true

	grant := &UICapabilityGrant{
		AllowedPermissions: []string{
			"camera", "microphone", "geolocation", "clipboardWrite",
		},
	}

	input := UIPermissionsInput{
		Camera:         true,
		Microphone:     true,
		Geolocation:    true,
		ClipboardWrite: true,
	}

	result := MediatePermissions(input, grant, config, "srv", "tnt", "tool1")

	if !result.Camera {
		t.Error("Expected camera allowed")
	}
	if !result.Microphone {
		t.Error("Expected microphone allowed")
	}
	if !result.Geolocation {
		t.Error("Expected geolocation allowed")
	}
	if !result.ClipboardWrite {
		t.Error("Expected clipboardWrite allowed")
	}

	// No denial events
	if len(result.Events) != 0 {
		t.Errorf("Expected 0 denial events, got %d", len(result.Events))
	}
}

func TestMediatePermissions_FalseInputNoEvents(t *testing.T) {
	// Permissions not requested should not generate events
	config := UIConfigDefaults()
	grant := &UICapabilityGrant{}

	input := UIPermissionsInput{
		Camera:         false,
		Microphone:     false,
		Geolocation:    false,
		ClipboardWrite: false,
	}

	result := MediatePermissions(input, grant, config, "srv", "tnt", "tool1")

	if len(result.Events) != 0 {
		t.Errorf("Expected 0 events for false inputs, got %d", len(result.Events))
	}
}

func TestMediatePermissions_AuditEventsForDenied(t *testing.T) {
	// AC#8: Denied permissions logged as ui.permission.denied events
	config := UIConfigDefaults()

	input := UIPermissionsInput{
		Camera: true,
	}

	result := MediatePermissions(input, nil, config, "my-server", "my-tenant", "my-tool")

	if len(result.Events) == 0 {
		t.Fatal("Expected denial events")
	}

	e := result.Events[0]
	if e.EventType != "ui.permission.denied" {
		t.Errorf("Expected ui.permission.denied, got %s", e.EventType)
	}
	if e.Server != "my-server" {
		t.Errorf("Expected server=my-server, got %s", e.Server)
	}
	if e.Tenant != "my-tenant" {
		t.Errorf("Expected tenant=my-tenant, got %s", e.Tenant)
	}
	if e.ToolName != "my-tool" {
		t.Errorf("Expected toolName=my-tool, got %s", e.ToolName)
	}
}

// --- domainMatchesAllowlist Unit Tests ---

func TestDomainMatchesAllowlist_ExactMatch(t *testing.T) {
	if !domainMatchesAllowlist("https://api.acme.corp", []string{"https://api.acme.corp"}) {
		t.Error("Expected exact match to succeed")
	}
}

func TestDomainMatchesAllowlist_GlobMatch(t *testing.T) {
	if !domainMatchesAllowlist("api.acme.corp", []string{"*.acme.corp"}) {
		t.Error("Expected glob match to succeed")
	}
}

func TestDomainMatchesAllowlist_NoMatch(t *testing.T) {
	if domainMatchesAllowlist("evil.example.com", []string{"*.acme.corp"}) {
		t.Error("Expected no match for different domain")
	}
}

func TestDomainMatchesAllowlist_EmptyAllowlist(t *testing.T) {
	if domainMatchesAllowlist("anything.com", []string{}) {
		t.Error("Expected no match with empty allowlist")
	}
}

func TestDomainMatchesAllowlist_NilAllowlist(t *testing.T) {
	if domainMatchesAllowlist("anything.com", nil) {
		t.Error("Expected no match with nil allowlist")
	}
}

func TestDomainMatchesAllowlist_MultiplePatterns(t *testing.T) {
	allowlist := []string{
		"https://api.acme.corp",
		"*.cdn.acme.corp",
		"static.example.com",
	}

	tests := []struct {
		domain   string
		expected bool
	}{
		{"https://api.acme.corp", true},
		{"images.cdn.acme.corp", true},
		{"static.example.com", true},
		{"evil.example.com", false},
		{"api.acme.corp.evil.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			result := domainMatchesAllowlist(tc.domain, allowlist)
			if result != tc.expected {
				t.Errorf("domainMatchesAllowlist(%q) = %v, want %v", tc.domain, result, tc.expected)
			}
		})
	}
}

// --- Integration Tests (no mocks, real grant files) ---

func TestMediateCSP_Integration_WithRealGrantFile(t *testing.T) {
	// Integration test: load real grants, mediate CSP with mixed domains
	grants, err := LoadUICapabilityGrants(testutil.UICapabilityGrantsPath())
	if err != nil {
		t.Fatalf("Failed to load real grants: %v", err)
	}

	if len(grants) < 1 {
		t.Fatal("Expected at least one grant in real file")
	}

	// Find the dashboard server grant which has allowed_csp_connect_domains
	var dashboardGrant *UICapabilityGrant
	for i := range grants {
		if grants[i].Server == "mcp-dashboard-server" {
			dashboardGrant = &grants[i]
			break
		}
	}
	if dashboardGrant == nil {
		t.Fatal("Expected to find mcp-dashboard-server grant in real file")
	}

	config := UIConfigDefaults()

	input := UICSPInput{
		ConnectDomains: []string{
			"https://api.acme.corp",    // Should be allowed (in grant)
			"https://evil.example.com", // Should be stripped (not in grant)
		},
		FrameDomains:   []string{"https://embed.evil.com"}, // Always stripped
		BaseURIDomains: []string{"https://base.evil.com"},  // Always stripped
	}

	result := MediateCSP(input, dashboardGrant, config, "mcp-dashboard-server", "acme-corp", "render-analytics")

	// connectDomains: only https://api.acme.corp should survive
	if len(result.ConnectDomains) != 1 {
		t.Fatalf("Expected 1 connectDomain, got %d: %v", len(result.ConnectDomains), result.ConnectDomains)
	}
	if result.ConnectDomains[0] != "https://api.acme.corp" {
		t.Errorf("Expected https://api.acme.corp, got %s", result.ConnectDomains[0])
	}

	// frameDomains: always empty
	if len(result.FrameDomains) != 0 {
		t.Errorf("Expected empty frameDomains, got %v", result.FrameDomains)
	}

	// baseUriDomains: always empty
	if len(result.BaseURIDomains) != 0 {
		t.Errorf("Expected empty baseUriDomains, got %v", result.BaseURIDomains)
	}

	// Verify audit events
	strippedEvents := 0
	for _, e := range result.Events {
		if e.EventType == "ui.csp.domain_stripped" {
			strippedEvents++
		}
	}
	if strippedEvents < 3 {
		// At least: evil.example.com from connect, embed.evil.com from frame, base.evil.com from baseURI
		t.Errorf("Expected at least 3 stripped events, got %d", strippedEvents)
	}
}

func TestMediatePermissions_Integration_WithRealGrantFile(t *testing.T) {
	// Integration test: load real grants, mediate permissions
	grants, err := LoadUICapabilityGrants(testutil.UICapabilityGrantsPath())
	if err != nil {
		t.Fatalf("Failed to load real grants: %v", err)
	}

	// Dashboard grant has empty allowed_permissions
	var dashboardGrant *UICapabilityGrant
	for i := range grants {
		if grants[i].Server == "mcp-dashboard-server" {
			dashboardGrant = &grants[i]
			break
		}
	}
	if dashboardGrant == nil {
		t.Fatal("Expected to find mcp-dashboard-server grant")
	}

	config := UIConfigDefaults() // All permissions denied by hard constraint

	input := UIPermissionsInput{
		Camera:         true,
		Microphone:     true,
		Geolocation:    true,
		ClipboardWrite: true,
	}

	result := MediatePermissions(input, dashboardGrant, config, "mcp-dashboard-server", "acme-corp", "render-analytics")

	// All should be denied (hard constraints all false by default)
	if result.Camera || result.Microphone || result.Geolocation || result.ClipboardWrite {
		t.Error("Expected all permissions denied by hard constraints")
	}

	// Should have 4 denial events
	if len(result.Events) != 4 {
		t.Errorf("Expected 4 denial events, got %d", len(result.Events))
	}
}

func TestMediateCSP_Integration_TenConnectDomainsWithMaxFive(t *testing.T) {
	// Integration test: 10 connectDomains with max 5 -> only 5 pass
	tmpDir := t.TempDir()
	grantsYAML := `
ui_capability_grants:
  - server: "big-csp-server"
    tenant: "acme-corp"
    mode: "allow"
    approved_tools: []
    max_resource_size_bytes: 2097152
    allowed_csp_connect_domains:
      - "https://d1.example.com"
      - "https://d2.example.com"
      - "https://d3.example.com"
      - "https://d4.example.com"
      - "https://d5.example.com"
      - "https://d6.example.com"
      - "https://d7.example.com"
      - "https://d8.example.com"
      - "https://d9.example.com"
      - "https://d10.example.com"
    allowed_permissions: []
    approved_at: "2026-02-01T00:00:00Z"
    approved_by: "security-review@acme.corp"
`
	grantsFile := filepath.Join(tmpDir, "grants.yaml")
	if err := os.WriteFile(grantsFile, []byte(grantsYAML), 0644); err != nil {
		t.Fatalf("Failed to write grants file: %v", err)
	}

	grants, err := LoadUICapabilityGrants(grantsFile)
	if err != nil {
		t.Fatalf("Failed to load grants: %v", err)
	}

	config := UIConfigDefaults() // max_connect_domains=5

	input := UICSPInput{
		ConnectDomains: []string{
			"https://d1.example.com",
			"https://d2.example.com",
			"https://d3.example.com",
			"https://d4.example.com",
			"https://d5.example.com",
			"https://d6.example.com",
			"https://d7.example.com",
			"https://d8.example.com",
			"https://d9.example.com",
			"https://d10.example.com",
		},
	}

	result := MediateCSP(input, &grants[0], config, "big-csp-server", "acme-corp", "tool1")

	if len(result.ConnectDomains) != 5 {
		t.Fatalf("Expected 5 connectDomains after max enforcement, got %d", len(result.ConnectDomains))
	}

	// Verify the first 5 survived
	for i := 0; i < 5; i++ {
		expected := input.ConnectDomains[i]
		if result.ConnectDomains[i] != expected {
			t.Errorf("Domain %d: expected %s, got %s", i, expected, result.ConnectDomains[i])
		}
	}

	// Verify 5 max_domains_exceeded events
	truncatedCount := 0
	for _, e := range result.Events {
		if e.Reason == "max_domains_exceeded" {
			truncatedCount++
		}
	}
	if truncatedCount != 5 {
		t.Errorf("Expected 5 max_domains_exceeded events, got %d", truncatedCount)
	}
}

func TestMediatePermissions_Integration_CameraTrueNoGrant(t *testing.T) {
	// Integration test: camera=true with no grant -> denied
	config := UIConfigDefaults()
	// Even if we allow camera in hard constraints...
	config.PermissionsHardConstraints.CameraAllowed = true

	input := UIPermissionsInput{
		Camera: true,
	}

	// No grant (nil)
	result := MediatePermissions(input, nil, config, "unknown-server", "acme-corp", "tool1")

	if result.Camera {
		t.Error("Expected camera denied with no grant")
	}

	if len(result.Events) != 1 {
		t.Fatalf("Expected 1 denial event, got %d", len(result.Events))
	}
	if result.Events[0].EventType != "ui.permission.denied" {
		t.Errorf("Expected ui.permission.denied, got %s", result.Events[0].EventType)
	}
	if result.Events[0].Field != "camera" {
		t.Errorf("Expected field=camera, got %s", result.Events[0].Field)
	}
}

func TestMediateCSP_Integration_FrameDomainsAlwaysStripped(t *testing.T) {
	// Integration test: frameDomains always stripped regardless of grant
	tmpDir := t.TempDir()
	grantsYAML := `
ui_capability_grants:
  - server: "frame-server"
    tenant: "acme-corp"
    mode: "allow"
    approved_tools: []
    max_resource_size_bytes: 2097152
    allowed_csp_connect_domains:
      - "https://api.acme.corp"
    allowed_permissions:
      - "camera"
    approved_at: "2026-02-01T00:00:00Z"
    approved_by: "security-review@acme.corp"
`
	grantsFile := filepath.Join(tmpDir, "grants.yaml")
	if err := os.WriteFile(grantsFile, []byte(grantsYAML), 0644); err != nil {
		t.Fatalf("Failed to write grants file: %v", err)
	}

	grants, err := LoadUICapabilityGrants(grantsFile)
	if err != nil {
		t.Fatalf("Failed to load grants: %v", err)
	}

	config := UIConfigDefaults()

	input := UICSPInput{
		FrameDomains: []string{
			"https://embed1.example.com",
			"https://embed2.example.com",
			"https://embed3.example.com",
		},
	}

	result := MediateCSP(input, &grants[0], config, "frame-server", "acme-corp", "tool1")

	if len(result.FrameDomains) != 0 {
		t.Errorf("Expected frameDomains always empty, got %v", result.FrameDomains)
	}

	// Verify 3 stripped events
	frameStrippedCount := 0
	for _, e := range result.Events {
		if e.Field == "frameDomains" && e.EventType == "ui.csp.domain_stripped" {
			frameStrippedCount++
		}
	}
	if frameStrippedCount != 3 {
		t.Errorf("Expected 3 frame domain stripped events, got %d", frameStrippedCount)
	}
}

func TestMediateCSP_Integration_MixedAllowedDisallowed(t *testing.T) {
	// Integration test: mix of allowed/disallowed connectDomains -> only allowed pass
	tmpDir := t.TempDir()
	grantsYAML := `
ui_capability_grants:
  - server: "mixed-server"
    tenant: "acme-corp"
    mode: "allow"
    approved_tools: []
    max_resource_size_bytes: 2097152
    allowed_csp_connect_domains:
      - "https://api.acme.corp"
      - "https://data.acme.corp"
      - "https://auth.acme.corp"
    allowed_permissions: []
    approved_at: "2026-02-01T00:00:00Z"
    approved_by: "security-review@acme.corp"
`
	grantsFile := filepath.Join(tmpDir, "grants.yaml")
	if err := os.WriteFile(grantsFile, []byte(grantsYAML), 0644); err != nil {
		t.Fatalf("Failed to write grants file: %v", err)
	}

	grants, err := LoadUICapabilityGrants(grantsFile)
	if err != nil {
		t.Fatalf("Failed to load grants: %v", err)
	}

	config := UIConfigDefaults()

	input := UICSPInput{
		ConnectDomains: []string{
			"https://api.acme.corp",   // allowed
			"https://evil.hacker.com", // NOT allowed
			"https://data.acme.corp",  // allowed
			"https://malware.bad.com", // NOT allowed
			"https://auth.acme.corp",  // allowed
		},
	}

	result := MediateCSP(input, &grants[0], config, "mixed-server", "acme-corp", "tool1")

	if len(result.ConnectDomains) != 3 {
		t.Fatalf("Expected 3 allowed connectDomains, got %d: %v",
			len(result.ConnectDomains), result.ConnectDomains)
	}

	// Verify exactly the right domains survived
	expected := map[string]bool{
		"https://api.acme.corp":  true,
		"https://data.acme.corp": true,
		"https://auth.acme.corp": true,
	}
	for _, d := range result.ConnectDomains {
		if !expected[d] {
			t.Errorf("Unexpected domain in result: %s", d)
		}
	}

	// Verify 2 stripped events
	strippedCount := 0
	for _, e := range result.Events {
		if e.EventType == "ui.csp.domain_stripped" && e.Field == "connectDomains" {
			strippedCount++
		}
	}
	if strippedCount != 2 {
		t.Errorf("Expected 2 stripped events, got %d", strippedCount)
	}
}

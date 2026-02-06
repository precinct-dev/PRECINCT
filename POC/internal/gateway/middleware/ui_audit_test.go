package middleware

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// --- Event Type Constants Tests ---

func TestAllUIEventTypes_Returns10Types(t *testing.T) {
	types := AllUIEventTypes()
	if len(types) != 10 {
		t.Fatalf("Expected 10 UI event types, got %d", len(types))
	}

	// Verify all expected types are present
	expected := map[string]bool{
		"ui.capability.stripped":                  false,
		"ui.capability.audit_passthrough":         false,
		"ui.resource.read":                        false,
		"ui.resource.blocked":                     false,
		"ui.resource.hash_mismatch":               false,
		"ui.csp.domain_stripped":                  false,
		"ui.permission.denied":                    false,
		"tool.invocation.app_driven":              false,
		"tool.invocation.app_driven.blocked":      false,
		"tool.invocation.app_driven.rate_limited": false,
	}

	for _, et := range types {
		if _, ok := expected[et]; !ok {
			t.Errorf("Unexpected event type: %s", et)
		}
		expected[et] = true
	}

	for et, found := range expected {
		if !found {
			t.Errorf("Missing event type: %s", et)
		}
	}
}

// --- Severity Assignment Tests (AC#4) ---

func TestUIEventSeverity_InfoEvents(t *testing.T) {
	infoEvents := []string{
		UIEventCapabilityStripped,
		UIEventResourceRead,
		UIEventToolInvocationAppDriven,
	}
	for _, et := range infoEvents {
		if sev := UIEventSeverity(et); sev != SeverityInfo {
			t.Errorf("Expected severity=info for %s, got %s", et, sev)
		}
	}
}

func TestUIEventSeverity_WarningEvents(t *testing.T) {
	warningEvents := []string{
		UIEventCapabilityAuditPassthrough,
		UIEventCSPDomainStripped,
		UIEventPermissionDenied,
		UIEventToolInvocationAppDrivenRateLimited,
	}
	for _, et := range warningEvents {
		if sev := UIEventSeverity(et); sev != SeverityWarning {
			t.Errorf("Expected severity=warning for %s, got %s", et, sev)
		}
	}
}

func TestUIEventSeverity_HighEvents(t *testing.T) {
	highEvents := []string{
		UIEventResourceBlocked,
		UIEventToolInvocationAppDrivenBlocked,
	}
	for _, et := range highEvents {
		if sev := UIEventSeverity(et); sev != SeverityHigh {
			t.Errorf("Expected severity=high for %s, got %s", et, sev)
		}
	}
}

func TestUIEventSeverity_CriticalEvents(t *testing.T) {
	if sev := UIEventSeverity(UIEventResourceHashMismatch); sev != SeverityCritical {
		t.Errorf("Expected severity=critical for %s, got %s", UIEventResourceHashMismatch, sev)
	}
}

func TestUIEventSeverity_UnknownDefaultsToInfo(t *testing.T) {
	if sev := UIEventSeverity("unknown.event"); sev != SeverityInfo {
		t.Errorf("Expected severity=info for unknown event type, got %s", sev)
	}
}

// --- UIAuditData JSON Marshaling Tests (AC#2) ---

func TestUIAuditData_JSONMarshal_AllFields(t *testing.T) {
	hashVerified := true
	ui := &UIAuditData{
		ResourceURI:         "ui://dashboard-server/analytics.html",
		ResourceContentHash: "sha256:ab12cd34",
		ResourceSizeBytes:   145000,
		ContentType:         "text/html;profile=mcp-app",
		HashVerified:        &hashVerified,
		ScanResult: &UIAuditScanResult{
			DangerousPatternsFound: 0,
			CSPViolationsFound:     0,
		},
		CSPMediation: &UIAuditCSPMediation{
			DomainsStripped: []string{"https://cdn.untrusted.com"},
			DomainsAllowed:  []string{"https://api.acme.corp"},
		},
		PermissionsMediation: &UIAuditPermissions{
			PermissionsDenied:  []string{"camera", "microphone"},
			PermissionsAllowed: []string{},
		},
		CapabilityGrantMode: "allow",
	}

	data, err := json.Marshal(ui)
	if err != nil {
		t.Fatalf("Failed to marshal UIAuditData: %v", err)
	}

	// Unmarshal back to verify round-trip
	var result UIAuditData
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal UIAuditData: %v", err)
	}

	if result.ResourceURI != "ui://dashboard-server/analytics.html" {
		t.Errorf("ResourceURI mismatch: %s", result.ResourceURI)
	}
	if result.ResourceContentHash != "sha256:ab12cd34" {
		t.Errorf("ResourceContentHash mismatch: %s", result.ResourceContentHash)
	}
	if result.ResourceSizeBytes != 145000 {
		t.Errorf("ResourceSizeBytes mismatch: %d", result.ResourceSizeBytes)
	}
	if result.ContentType != "text/html;profile=mcp-app" {
		t.Errorf("ContentType mismatch: %s", result.ContentType)
	}
	if result.HashVerified == nil || *result.HashVerified != true {
		t.Error("HashVerified should be true")
	}
	if result.ScanResult == nil {
		t.Fatal("ScanResult should not be nil")
	}
	if result.ScanResult.DangerousPatternsFound != 0 {
		t.Errorf("DangerousPatternsFound mismatch: %d", result.ScanResult.DangerousPatternsFound)
	}
	if result.CSPMediation == nil {
		t.Fatal("CSPMediation should not be nil")
	}
	if len(result.CSPMediation.DomainsStripped) != 1 || result.CSPMediation.DomainsStripped[0] != "https://cdn.untrusted.com" {
		t.Errorf("DomainsStripped mismatch: %v", result.CSPMediation.DomainsStripped)
	}
	if result.PermissionsMediation == nil {
		t.Fatal("PermissionsMediation should not be nil")
	}
	if len(result.PermissionsMediation.PermissionsDenied) != 2 {
		t.Errorf("Expected 2 denied permissions, got %d", len(result.PermissionsMediation.PermissionsDenied))
	}
	if result.CapabilityGrantMode != "allow" {
		t.Errorf("CapabilityGrantMode mismatch: %s", result.CapabilityGrantMode)
	}
}

func TestUIAuditData_JSONMarshal_OptionalFieldsOmitted(t *testing.T) {
	// When only ResourceURI is set, other fields should be omitted
	ui := &UIAuditData{
		ResourceURI: "ui://server/page.html",
	}

	data, err := json.Marshal(ui)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Verify optional fields are not present
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)

	if _, ok := raw["scan_result"]; ok {
		t.Error("scan_result should be omitted when nil")
	}
	if _, ok := raw["csp_mediation"]; ok {
		t.Error("csp_mediation should be omitted when nil")
	}
	if _, ok := raw["hash_verified"]; ok {
		t.Error("hash_verified should be omitted when nil")
	}
}

// --- AppDrivenData JSON Marshaling Tests (AC#3) ---

func TestAppDrivenData_JSONMarshal(t *testing.T) {
	ad := &AppDrivenData{
		UIContext: &AppDrivenUIContext{
			ResourceURI:     "ui://dashboard-server/analytics.html",
			ContentHash:     "sha256:ab12cd34",
			OriginatingTool: "render-analytics",
			SessionID:       "sess-abc123",
		},
		Correlation: &AppDrivenCorrelation{
			UISessionStart:          "2026-02-04T14:30:00Z",
			ToolCallsInUISession:    5,
			UserInteractionInferred: true,
		},
	}

	data, err := json.Marshal(ad)
	if err != nil {
		t.Fatalf("Failed to marshal AppDrivenData: %v", err)
	}

	var result AppDrivenData
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if result.UIContext == nil {
		t.Fatal("UIContext should not be nil")
	}
	if result.UIContext.ResourceURI != "ui://dashboard-server/analytics.html" {
		t.Errorf("ResourceURI mismatch: %s", result.UIContext.ResourceURI)
	}
	if result.UIContext.OriginatingTool != "render-analytics" {
		t.Errorf("OriginatingTool mismatch: %s", result.UIContext.OriginatingTool)
	}

	if result.Correlation == nil {
		t.Fatal("Correlation should not be nil")
	}
	if result.Correlation.ToolCallsInUISession != 5 {
		t.Errorf("ToolCallsInUISession mismatch: %d", result.Correlation.ToolCallsInUISession)
	}
	if !result.Correlation.UserInteractionInferred {
		t.Error("UserInteractionInferred should be true")
	}
}

// --- AuditEvent with UI field JSON Marshaling Tests ---

func TestAuditEvent_WithUIField_JSONMarshal(t *testing.T) {
	hashVerified := true
	event := AuditEvent{
		Timestamp: "2026-02-04T14:30:15.123456Z",
		EventType: UIEventResourceRead,
		Severity:  SeverityInfo,
		SessionID: "sess-abc123",
		TraceID:   "4bf92f3577b34da6a3ce929d0e0e4736",
		SPIFFEID:  "spiffe://acme.corp/agents/mcp-client/dashboard-viewer/prod",
		Action:    UIEventResourceRead,
		Result:    SeverityInfo,
		UI: &UIAuditData{
			ResourceURI:         "ui://dashboard-server/analytics.html",
			ResourceContentHash: "sha256:ab12cd34",
			ResourceSizeBytes:   145000,
			ContentType:         "text/html;profile=mcp-app",
			HashVerified:        &hashVerified,
			ScanResult: &UIAuditScanResult{
				DangerousPatternsFound: 0,
				CSPViolationsFound:     0,
			},
			CSPMediation: &UIAuditCSPMediation{
				DomainsStripped: []string{"https://cdn.untrusted.com"},
				DomainsAllowed:  []string{"https://api.acme.corp"},
			},
			PermissionsMediation: &UIAuditPermissions{
				PermissionsDenied:  []string{"camera", "microphone"},
				PermissionsAllowed: []string{},
			},
			CapabilityGrantMode: "allow",
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal AuditEvent with UI: %v", err)
	}

	// Verify the JSON structure matches the documented schema
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)

	if raw["event_type"] != "ui.resource.read" {
		t.Errorf("event_type mismatch: %v", raw["event_type"])
	}
	if raw["severity"] != "info" {
		t.Errorf("severity mismatch: %v", raw["severity"])
	}
	if raw["trace_id"] != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trace_id mismatch: %v", raw["trace_id"])
	}

	// Verify UI section exists
	uiSection, ok := raw["ui"]
	if !ok {
		t.Fatal("Expected 'ui' section in JSON output")
	}
	uiMap := uiSection.(map[string]interface{})
	if uiMap["resource_uri"] != "ui://dashboard-server/analytics.html" {
		t.Errorf("ui.resource_uri mismatch: %v", uiMap["resource_uri"])
	}
}

func TestAuditEvent_WithAppDrivenField_JSONMarshal(t *testing.T) {
	event := AuditEvent{
		EventType: UIEventToolInvocationAppDriven,
		Severity:  SeverityInfo,
		SessionID: "sess-abc123",
		TraceID:   "trace-123",
		Action:    UIEventToolInvocationAppDriven,
		AppDriven: &AppDrivenData{
			UIContext: &AppDrivenUIContext{
				ResourceURI:     "ui://dashboard-server/analytics.html",
				ContentHash:     "sha256:ab12cd34",
				OriginatingTool: "render-analytics",
				SessionID:       "sess-abc123",
			},
			Correlation: &AppDrivenCorrelation{
				UISessionStart:          "2026-02-04T14:30:00Z",
				ToolCallsInUISession:    3,
				UserInteractionInferred: false,
			},
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var raw map[string]interface{}
	json.Unmarshal(data, &raw)

	if raw["event_type"] != "tool.invocation.app_driven" {
		t.Errorf("event_type mismatch: %v", raw["event_type"])
	}

	// Verify app_driven section exists with ui_context and correlation
	adSection, ok := raw["app_driven"]
	if !ok {
		t.Fatal("Expected 'app_driven' section in JSON output")
	}
	adMap := adSection.(map[string]interface{})

	uiCtx, ok := adMap["ui_context"]
	if !ok {
		t.Fatal("Expected 'ui_context' in app_driven section")
	}
	uiCtxMap := uiCtx.(map[string]interface{})
	if uiCtxMap["originating_tool"] != "render-analytics" {
		t.Errorf("originating_tool mismatch: %v", uiCtxMap["originating_tool"])
	}

	corr, ok := adMap["correlation"]
	if !ok {
		t.Fatal("Expected 'correlation' in app_driven section")
	}
	corrMap := corr.(map[string]interface{})
	if corrMap["tool_calls_in_ui_session"] != float64(3) {
		t.Errorf("tool_calls_in_ui_session mismatch: %v", corrMap["tool_calls_in_ui_session"])
	}
}

func TestAuditEvent_WithoutUI_OmitsUIField(t *testing.T) {
	event := AuditEvent{
		SessionID: "sess-123",
		Action:    "mcp_request",
		Result:    "completed",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var raw map[string]interface{}
	json.Unmarshal(data, &raw)

	if _, ok := raw["ui"]; ok {
		t.Error("UI field should be omitted when nil")
	}
	if _, ok := raw["app_driven"]; ok {
		t.Error("AppDriven field should be omitted when nil")
	}
	if _, ok := raw["event_type"]; ok {
		// event_type should be omitted when empty string
		if raw["event_type"] != "" {
			t.Error("event_type should be empty or omitted for non-UI events")
		}
	}
}

// --- EmitUIEvent Unit Tests (with mock audit sink) ---

func TestEmitUIEvent_SetsCorrectFields(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	os.WriteFile(bundlePath, []byte("package test"), 0644)
	os.WriteFile(registryPath, []byte("tools: []"), 0644)

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	hashVerified := true
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventResourceRead,
		SessionID: "sess-123",
		TraceID:   "trace-456",
		SPIFFEID:  "spiffe://acme.corp/agents/test",
		UI: &UIAuditData{
			ResourceURI:         "ui://server/page.html",
			ResourceContentHash: "sha256:abcdef",
			ResourceSizeBytes:   1024,
			ContentType:         "text/html;profile=mcp-app",
			HashVerified:        &hashVerified,
			CapabilityGrantMode: "allow",
		},
	})

	// Read the written event
	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("Failed to open audit file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatal("No events found in audit file")
	}

	var event AuditEvent
	if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
		t.Fatalf("Failed to unmarshal event: %v", err)
	}

	// Verify all expected fields
	if event.EventType != UIEventResourceRead {
		t.Errorf("EventType: expected %s, got %s", UIEventResourceRead, event.EventType)
	}
	if event.Severity != SeverityInfo {
		t.Errorf("Severity: expected %s, got %s", SeverityInfo, event.Severity)
	}
	if event.SessionID != "sess-123" {
		t.Errorf("SessionID: expected sess-123, got %s", event.SessionID)
	}
	if event.TraceID != "trace-456" {
		t.Errorf("TraceID: expected trace-456, got %s", event.TraceID)
	}
	if event.SPIFFEID != "spiffe://acme.corp/agents/test" {
		t.Errorf("SPIFFEID mismatch: %s", event.SPIFFEID)
	}
	if event.Timestamp == "" {
		t.Error("Timestamp should be set by Auditor.Log")
	}
	if event.PrevHash == "" {
		t.Error("PrevHash should be set by Auditor.Log (hash chain)")
	}
	if event.BundleDigest == "" {
		t.Error("BundleDigest should be set by Auditor.Log")
	}
	if event.RegistryDigest == "" {
		t.Error("RegistryDigest should be set by Auditor.Log")
	}

	// Verify UI section
	if event.UI == nil {
		t.Fatal("UI section should not be nil")
	}
	if event.UI.ResourceURI != "ui://server/page.html" {
		t.Errorf("UI.ResourceURI mismatch: %s", event.UI.ResourceURI)
	}
	if event.UI.ResourceContentHash != "sha256:abcdef" {
		t.Errorf("UI.ResourceContentHash mismatch: %s", event.UI.ResourceContentHash)
	}
	if event.UI.ResourceSizeBytes != 1024 {
		t.Errorf("UI.ResourceSizeBytes mismatch: %d", event.UI.ResourceSizeBytes)
	}
	if event.UI.HashVerified == nil || *event.UI.HashVerified != true {
		t.Error("UI.HashVerified should be true")
	}
}

// --- EmitUIEvent for Each of 10 Event Types ---

func TestEmitUIEvent_AllEventTypes(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	os.WriteFile(bundlePath, []byte("package test"), 0644)
	os.WriteFile(registryPath, []byte("tools: []"), 0644)

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	// Emit one event for each of the 10 types
	for _, eventType := range AllUIEventTypes() {
		params := UIAuditEventParams{
			EventType: eventType,
			SessionID: "sess-all-types",
			TraceID:   "trace-all-types",
			SPIFFEID:  "spiffe://test/agent",
		}

		// Add UI data for UI-prefixed events
		if eventType == UIEventToolInvocationAppDriven ||
			eventType == UIEventToolInvocationAppDrivenBlocked ||
			eventType == UIEventToolInvocationAppDrivenRateLimited {
			params.AppDriven = &AppDrivenData{
				UIContext: &AppDrivenUIContext{
					ResourceURI:     "ui://server/page.html",
					OriginatingTool: "some-tool",
					SessionID:       "sess-all-types",
				},
				Correlation: &AppDrivenCorrelation{
					ToolCallsInUISession: 1,
				},
			}
		} else {
			params.UI = &UIAuditData{
				ResourceURI: "ui://server/page.html",
			}
		}

		auditor.EmitUIEvent(params)
	}

	// Read all events and verify
	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("Failed to open audit file: %v", err)
	}
	defer file.Close()

	expectedTypes := AllUIEventTypes()
	scanner := bufio.NewScanner(file)
	eventIndex := 0
	for scanner.Scan() {
		var event AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("Failed to unmarshal event %d: %v", eventIndex, err)
		}

		if eventIndex >= len(expectedTypes) {
			t.Fatalf("More events than expected (got %d+)", eventIndex+1)
		}

		expectedType := expectedTypes[eventIndex]
		expectedSeverity := UIEventSeverity(expectedType)

		if event.EventType != expectedType {
			t.Errorf("Event %d: expected event_type=%s, got %s", eventIndex, expectedType, event.EventType)
		}
		if event.Severity != expectedSeverity {
			t.Errorf("Event %d (%s): expected severity=%s, got %s", eventIndex, expectedType, expectedSeverity, event.Severity)
		}
		if event.TraceID != "trace-all-types" {
			t.Errorf("Event %d: TraceID mismatch", eventIndex)
		}
		if event.PrevHash == "" {
			t.Errorf("Event %d: PrevHash should be set (hash chain)", eventIndex)
		}

		eventIndex++
	}

	if eventIndex != 10 {
		t.Errorf("Expected 10 events, got %d", eventIndex)
	}
}

// --- Hash Chain Integration Tests (AC#5) ---

func TestEmitUIEvent_HashChainIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	os.WriteFile(bundlePath, []byte("package test"), 0644)
	os.WriteFile(registryPath, []byte("tools: []"), 0644)

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	// Emit a mix of standard and UI events
	auditor.Log(AuditEvent{
		SessionID: "sess-1",
		Action:    "mcp_request",
		Result:    "allowed",
	})

	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventResourceRead,
		SessionID: "sess-1",
		TraceID:   "trace-1",
		UI: &UIAuditData{
			ResourceURI: "ui://server/page.html",
		},
	})

	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventCSPDomainStripped,
		SessionID: "sess-1",
		TraceID:   "trace-1",
		UI: &UIAuditData{
			CSPMediation: &UIAuditCSPMediation{
				DomainsStripped: []string{"https://evil.com"},
				DomainsAllowed:  []string{"https://good.com"},
			},
		},
	})

	auditor.Log(AuditEvent{
		SessionID: "sess-2",
		Action:    "mcp_request",
		Result:    "denied",
	})

	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventToolInvocationAppDriven,
		SessionID: "sess-2",
		TraceID:   "trace-2",
		AppDriven: &AppDrivenData{
			UIContext: &AppDrivenUIContext{
				ResourceURI:     "ui://server/page.html",
				OriginatingTool: "render-analytics",
			},
			Correlation: &AppDrivenCorrelation{
				ToolCallsInUISession: 1,
			},
		},
	})

	auditor.Close()

	// Verify hash chain using the existing verification utility
	result, err := VerifyAuditChain(auditPath)
	if err != nil {
		t.Fatalf("Chain verification error: %v", err)
	}

	if !result.Valid {
		t.Errorf("Hash chain should be valid with mixed events: %s", result.ErrorMessage)
	}
	if result.TotalEvents != 5 {
		t.Errorf("Expected 5 events (2 standard + 3 UI), got %d", result.TotalEvents)
	}
	if len(result.TamperedEvents) != 0 {
		t.Errorf("Expected no tampered events, got %d", len(result.TamperedEvents))
	}
}

func TestEmitUIEvent_FirstEventHasGenesisHash(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	os.WriteFile(bundlePath, []byte("package test"), 0644)
	os.WriteFile(registryPath, []byte("tools: []"), 0644)

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	// First event is a UI event
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventCapabilityStripped,
		SessionID: "first-session",
		TraceID:   "first-trace",
	})

	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("Failed to open audit file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatal("No events found")
	}

	var event AuditEvent
	json.Unmarshal(scanner.Bytes(), &event)

	genesisHash := sha256.Sum256([]byte(""))
	expectedGenesis := hex.EncodeToString(genesisHash[:])

	if event.PrevHash != expectedGenesis {
		t.Errorf("First UI event should have genesis hash: expected %s, got %s", expectedGenesis, event.PrevHash)
	}
}

// --- Trace ID Correlation Tests (AC#6) ---

func TestEmitUIEvent_TraceIDCorrelation(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	os.WriteFile(bundlePath, []byte("package test"), 0644)
	os.WriteFile(registryPath, []byte("tools: []"), 0644)

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	sharedTraceID := "shared-trace-4bf92f3577b34da6a3ce929d0e0e4736"

	// Emit 3 related events with same trace_id
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventResourceRead,
		TraceID:   sharedTraceID,
		UI:        &UIAuditData{ResourceURI: "ui://server/page.html"},
	})
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventCSPDomainStripped,
		TraceID:   sharedTraceID,
		UI: &UIAuditData{
			CSPMediation: &UIAuditCSPMediation{
				DomainsStripped: []string{"https://evil.com"},
				DomainsAllowed:  []string{},
			},
		},
	})
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventToolInvocationAppDriven,
		TraceID:   sharedTraceID,
		AppDriven: &AppDrivenData{
			UIContext: &AppDrivenUIContext{ResourceURI: "ui://server/page.html"},
		},
	})

	// Read and verify all events have the same trace_id
	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("Failed to open audit file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	eventCount := 0
	for scanner.Scan() {
		var event AuditEvent
		json.Unmarshal(scanner.Bytes(), &event)
		if event.TraceID != sharedTraceID {
			t.Errorf("Event %d: trace_id mismatch, expected %s, got %s", eventCount, sharedTraceID, event.TraceID)
		}
		eventCount++
	}

	if eventCount != 3 {
		t.Errorf("Expected 3 correlated events, got %d", eventCount)
	}
}

// --- Integration: UI events routed to same sink (AC#7) ---

func TestEmitUIEvent_RoutedToSameAuditSink(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	os.WriteFile(bundlePath, []byte("package test"), 0644)
	os.WriteFile(registryPath, []byte("tools: []"), 0644)

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	// Mix standard and UI events - all should go to same file
	auditor.Log(AuditEvent{
		SessionID: "standard-1",
		Action:    "mcp_request",
		Result:    "allowed",
	})

	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventResourceRead,
		SessionID: "ui-1",
		UI:        &UIAuditData{ResourceURI: "ui://server/page.html"},
	})

	auditor.Log(AuditEvent{
		SessionID: "standard-2",
		Action:    "tool_execution",
		Result:    "success",
	})

	auditor.Close()

	// Verify all events are in the same file
	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("Failed to open: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	foundStandard := false
	foundUI := false
	for scanner.Scan() {
		lineCount++
		var event AuditEvent
		json.Unmarshal(scanner.Bytes(), &event)
		if event.EventType == UIEventResourceRead {
			foundUI = true
		}
		if event.Action == "mcp_request" {
			foundStandard = true
		}
	}

	if lineCount != 3 {
		t.Errorf("Expected 3 events in same file, got %d", lineCount)
	}
	if !foundStandard {
		t.Error("Standard event not found in audit file")
	}
	if !foundUI {
		t.Error("UI event not found in audit file - not routing to same sink")
	}
}

// --- Integration: Full 10-Event Scenario with Hash Chain (combined AC test) ---

func TestUIAuditEvents_FullScenario_10EventTypes_HashChain(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "full_scenario.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	os.WriteFile(bundlePath, []byte("package test\ndefault allow = true"), 0644)
	os.WriteFile(registryPath, []byte("tools:\n  - name: test\n    hash: abc"), 0644)

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	traceID := "scenario-trace-id"
	hashVerified := true
	hashNotVerified := false

	// Event 1: ui.capability.stripped
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventCapabilityStripped,
		SessionID: "sess-1",
		TraceID:   traceID,
		SPIFFEID:  "spiffe://acme.corp/agents/client1",
		UI: &UIAuditData{
			ResourceURI:         "ui://denied-server/page.html",
			CapabilityGrantMode: "deny",
		},
	})

	// Event 2: ui.capability.audit_passthrough
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventCapabilityAuditPassthrough,
		SessionID: "sess-1",
		TraceID:   traceID,
		SPIFFEID:  "spiffe://acme.corp/agents/client1",
		UI: &UIAuditData{
			CapabilityGrantMode: "audit-only",
		},
	})

	// Event 3: ui.resource.read
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventResourceRead,
		SessionID: "sess-1",
		TraceID:   traceID,
		SPIFFEID:  "spiffe://acme.corp/agents/client1",
		UI: &UIAuditData{
			ResourceURI:         "ui://dashboard-server/analytics.html",
			ResourceContentHash: "sha256:ab12cd34",
			ResourceSizeBytes:   145000,
			ContentType:         "text/html;profile=mcp-app",
			HashVerified:        &hashVerified,
			ScanResult: &UIAuditScanResult{
				DangerousPatternsFound: 0,
				CSPViolationsFound:     0,
			},
			CapabilityGrantMode: "allow",
		},
	})

	// Event 4: ui.resource.blocked
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventResourceBlocked,
		SessionID: "sess-1",
		TraceID:   traceID,
		SPIFFEID:  "spiffe://acme.corp/agents/client1",
		UI: &UIAuditData{
			ResourceURI:       "ui://dashboard-server/malicious.html",
			ResourceSizeBytes: 500000,
			ContentType:       "text/html;profile=mcp-app",
			ScanResult: &UIAuditScanResult{
				DangerousPatternsFound: 3,
				CSPViolationsFound:     1,
			},
		},
	})

	// Event 5: ui.resource.hash_mismatch
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventResourceHashMismatch,
		SessionID: "sess-1",
		TraceID:   traceID,
		SPIFFEID:  "spiffe://acme.corp/agents/client1",
		UI: &UIAuditData{
			ResourceURI:         "ui://dashboard-server/analytics.html",
			ResourceContentHash: "sha256:changed99",
			HashVerified:        &hashNotVerified,
		},
	})

	// Event 6: ui.csp.domain_stripped
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventCSPDomainStripped,
		SessionID: "sess-1",
		TraceID:   traceID,
		SPIFFEID:  "spiffe://acme.corp/agents/client1",
		UI: &UIAuditData{
			CSPMediation: &UIAuditCSPMediation{
				DomainsStripped: []string{"https://cdn.untrusted.com", "https://tracker.ads.com"},
				DomainsAllowed:  []string{"https://api.acme.corp"},
			},
		},
	})

	// Event 7: ui.permission.denied
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventPermissionDenied,
		SessionID: "sess-1",
		TraceID:   traceID,
		SPIFFEID:  "spiffe://acme.corp/agents/client1",
		UI: &UIAuditData{
			PermissionsMediation: &UIAuditPermissions{
				PermissionsDenied:  []string{"camera", "microphone"},
				PermissionsAllowed: []string{},
			},
		},
	})

	// Event 8: tool.invocation.app_driven
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventToolInvocationAppDriven,
		SessionID: "sess-1",
		TraceID:   traceID,
		SPIFFEID:  "spiffe://acme.corp/agents/client1",
		AppDriven: &AppDrivenData{
			UIContext: &AppDrivenUIContext{
				ResourceURI:     "ui://dashboard-server/analytics.html",
				ContentHash:     "sha256:ab12cd34",
				OriginatingTool: "render-analytics",
				SessionID:       "sess-1",
			},
			Correlation: &AppDrivenCorrelation{
				UISessionStart:          "2026-02-04T14:30:00Z",
				ToolCallsInUISession:    1,
				UserInteractionInferred: true,
			},
		},
	})

	// Event 9: tool.invocation.app_driven.blocked
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventToolInvocationAppDrivenBlocked,
		SessionID: "sess-1",
		TraceID:   traceID,
		SPIFFEID:  "spiffe://acme.corp/agents/client1",
		AppDriven: &AppDrivenData{
			UIContext: &AppDrivenUIContext{
				ResourceURI:     "ui://dashboard-server/analytics.html",
				ContentHash:     "sha256:ab12cd34",
				OriginatingTool: "blocked-tool",
				SessionID:       "sess-1",
			},
			Correlation: &AppDrivenCorrelation{
				ToolCallsInUISession: 2,
			},
		},
	})

	// Event 10: tool.invocation.app_driven.rate_limited
	auditor.EmitUIEvent(UIAuditEventParams{
		EventType: UIEventToolInvocationAppDrivenRateLimited,
		SessionID: "sess-1",
		TraceID:   traceID,
		SPIFFEID:  "spiffe://acme.corp/agents/client1",
		AppDriven: &AppDrivenData{
			UIContext: &AppDrivenUIContext{
				ResourceURI:     "ui://dashboard-server/analytics.html",
				OriginatingTool: "rate-limited-tool",
				SessionID:       "sess-1",
			},
			Correlation: &AppDrivenCorrelation{
				ToolCallsInUISession: 3,
			},
		},
	})

	auditor.Close()

	// --- Verification ---

	// 1. Verify all 10 events were written
	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("Failed to open audit file: %v", err)
	}

	scanner := bufio.NewScanner(file)
	events := make([]AuditEvent, 0, 10)
	for scanner.Scan() {
		var event AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("Failed to unmarshal event: %v", err)
		}
		events = append(events, event)
	}
	file.Close()

	if len(events) != 10 {
		t.Fatalf("Expected 10 events, got %d", len(events))
	}

	// 2. Verify event types in order
	expectedEventTypes := AllUIEventTypes()
	for i, event := range events {
		if event.EventType != expectedEventTypes[i] {
			t.Errorf("Event %d: expected type=%s, got %s", i, expectedEventTypes[i], event.EventType)
		}
	}

	// 3. Verify severity assignments (AC#4)
	expectedSeverities := []string{
		SeverityInfo,     // capability.stripped
		SeverityWarning,  // capability.audit_passthrough
		SeverityInfo,     // resource.read
		SeverityHigh,     // resource.blocked
		SeverityCritical, // resource.hash_mismatch
		SeverityWarning,  // csp.domain_stripped
		SeverityWarning,  // permission.denied
		SeverityInfo,     // tool.invocation.app_driven
		SeverityHigh,     // tool.invocation.app_driven.blocked
		SeverityWarning,  // tool.invocation.app_driven.rate_limited
	}
	for i, event := range events {
		if event.Severity != expectedSeverities[i] {
			t.Errorf("Event %d (%s): expected severity=%s, got %s",
				i, event.EventType, expectedSeverities[i], event.Severity)
		}
	}

	// 4. Verify all events have trace_id (AC#6)
	for i, event := range events {
		if event.TraceID != traceID {
			t.Errorf("Event %d: trace_id mismatch", i)
		}
	}

	// 5. Verify hash chain integrity (AC#5)
	chainResult, err := VerifyAuditChain(auditPath)
	if err != nil {
		t.Fatalf("Hash chain verification error: %v", err)
	}
	if !chainResult.Valid {
		t.Errorf("Hash chain should be valid: %s", chainResult.ErrorMessage)
	}
	if chainResult.TotalEvents != 10 {
		t.Errorf("Chain should cover 10 events, got %d", chainResult.TotalEvents)
	}

	// 6. Verify first event has genesis hash
	genesisHash := sha256.Sum256([]byte(""))
	expectedGenesis := hex.EncodeToString(genesisHash[:])
	if events[0].PrevHash != expectedGenesis {
		t.Errorf("First event should have genesis hash: got %s", events[0].PrevHash)
	}

	// 7. Verify UI section present on UI events
	for i := 0; i < 7; i++ {
		if events[i].UI == nil {
			t.Errorf("Event %d (%s): expected UI section to be present", i, events[i].EventType)
		}
	}

	// 8. Verify AppDriven section present on app-driven events (AC#3)
	for i := 7; i < 10; i++ {
		if events[i].AppDriven == nil {
			t.Errorf("Event %d (%s): expected AppDriven section to be present", i, events[i].EventType)
		}
		if events[i].AppDriven.UIContext == nil {
			t.Errorf("Event %d (%s): expected AppDriven.UIContext to be present", i, events[i].EventType)
		}
		if events[i].AppDriven.Correlation == nil {
			t.Errorf("Event %d (%s): expected AppDriven.Correlation to be present", i, events[i].EventType)
		}
	}

	// 9. Verify specific field values for ui.resource.read event
	readEvent := events[2]
	if readEvent.UI.ResourceURI != "ui://dashboard-server/analytics.html" {
		t.Errorf("resource.read: ResourceURI mismatch: %s", readEvent.UI.ResourceURI)
	}
	if readEvent.UI.ResourceSizeBytes != 145000 {
		t.Errorf("resource.read: ResourceSizeBytes mismatch: %d", readEvent.UI.ResourceSizeBytes)
	}
	if readEvent.UI.ScanResult == nil || readEvent.UI.ScanResult.DangerousPatternsFound != 0 {
		t.Error("resource.read: ScanResult mismatch")
	}

	// 10. Verify CSP mediation on csp.domain_stripped event
	cspEvent := events[5]
	if cspEvent.UI.CSPMediation == nil {
		t.Fatal("csp.domain_stripped: CSPMediation should not be nil")
	}
	if len(cspEvent.UI.CSPMediation.DomainsStripped) != 2 {
		t.Errorf("csp.domain_stripped: expected 2 stripped domains, got %d", len(cspEvent.UI.CSPMediation.DomainsStripped))
	}

	// 11. Verify permission mediation on permission.denied event
	permEvent := events[6]
	if permEvent.UI.PermissionsMediation == nil {
		t.Fatal("permission.denied: PermissionsMediation should not be nil")
	}
	if len(permEvent.UI.PermissionsMediation.PermissionsDenied) != 2 {
		t.Errorf("permission.denied: expected 2 denied permissions, got %d",
			len(permEvent.UI.PermissionsMediation.PermissionsDenied))
	}

	// 12. Verify app_driven correlation fields
	appEvent := events[7]
	if appEvent.AppDriven.Correlation.ToolCallsInUISession != 1 {
		t.Errorf("app_driven: ToolCallsInUISession mismatch: %d", appEvent.AppDriven.Correlation.ToolCallsInUISession)
	}
	if !appEvent.AppDriven.Correlation.UserInteractionInferred {
		t.Error("app_driven: UserInteractionInferred should be true")
	}
	if appEvent.AppDriven.UIContext.OriginatingTool != "render-analytics" {
		t.Errorf("app_driven: OriginatingTool mismatch: %s", appEvent.AppDriven.UIContext.OriginatingTool)
	}

	t.Log("FULL SCENARIO PASSED: All 10 event types emitted with correct structure, severity, trace_id, and hash chain integrity")
}

// RFA-j2d.8: UI audit event extensions for MCP-UI
// Implements UI-specific event types, structs, and emit functions per
// Reference Architecture Section 7.9.9.
//
// All 10 UI event types flow through the existing Auditor.Log mechanism,
// ensuring they participate in the hash chain and route to the same audit
// log sink as existing gateway events.
package middleware

// ----- UI Event Type Constants (10 total) -----

const (
	// UIEventCapabilityStripped is emitted when _meta.ui is removed because
	// the server is not approved for UI capabilities.
	UIEventCapabilityStripped = "ui.capability.stripped"

	// UIEventCapabilityAuditPassthrough is emitted when UI metadata is passed
	// through in audit-only mode.
	UIEventCapabilityAuditPassthrough = "ui.capability.audit_passthrough"

	// UIEventResourceRead is emitted when a ui:// resource is successfully served.
	UIEventResourceRead = "ui.resource.read"

	// UIEventResourceBlocked is emitted when a resource is blocked by scan,
	// hash, size, or type checks.
	UIEventResourceBlocked = "ui.resource.blocked"

	// UIEventResourceHashMismatch is emitted when content has changed from
	// the baseline hash.
	UIEventResourceHashMismatch = "ui.resource.hash_mismatch"

	// UIEventCSPDomainStripped is emitted when CSP domains are removed by
	// mediation.
	UIEventCSPDomainStripped = "ui.csp.domain_stripped"

	// UIEventPermissionDenied is emitted when a permission is removed by
	// mediation.
	UIEventPermissionDenied = "ui.permission.denied"

	// UIEventToolInvocationAppDriven is emitted when a tool call originates
	// from a UI app.
	UIEventToolInvocationAppDriven = "tool.invocation.app_driven"

	// UIEventToolInvocationAppDrivenBlocked is emitted when an app-driven
	// tool call is blocked.
	UIEventToolInvocationAppDrivenBlocked = "tool.invocation.app_driven.blocked"

	// UIEventToolInvocationAppDrivenRateLimited is emitted when an app-driven
	// tool call is rate limited.
	UIEventToolInvocationAppDrivenRateLimited = "tool.invocation.app_driven.rate_limited"
)

// ----- Severity Levels -----

const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// UIEventSeverity returns the severity level for a given UI event type.
// Severity assignments per Reference Architecture Section 7.9.9:
//
//	Info:     capability stripped, audit passthrough, resource read, app-driven invocation
//	Warning: CSP domain stripped, permission denied, app-driven rate limited
//	High:    resource blocked, app-driven blocked
//	Critical: resource hash mismatch
func UIEventSeverity(eventType string) string {
	switch eventType {
	case UIEventCapabilityStripped:
		return SeverityInfo
	case UIEventCapabilityAuditPassthrough:
		return SeverityWarning
	case UIEventResourceRead:
		return SeverityInfo
	case UIEventResourceBlocked:
		return SeverityHigh
	case UIEventResourceHashMismatch:
		return SeverityCritical
	case UIEventCSPDomainStripped:
		return SeverityWarning
	case UIEventPermissionDenied:
		return SeverityWarning
	case UIEventToolInvocationAppDriven:
		return SeverityInfo
	case UIEventToolInvocationAppDrivenBlocked:
		return SeverityHigh
	case UIEventToolInvocationAppDrivenRateLimited:
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

// ----- UI Audit Data Structs -----

// UIAuditData holds UI-specific fields for audit events. Populated for events
// with the "ui." prefix or "tool.invocation.app_driven*" event types.
type UIAuditData struct {
	ResourceURI         string                `json:"resource_uri,omitempty"`
	ResourceContentHash string                `json:"resource_content_hash,omitempty"`
	ResourceSizeBytes   int64                 `json:"resource_size_bytes,omitempty"`
	ContentType         string                `json:"content_type,omitempty"`
	HashVerified        *bool                 `json:"hash_verified,omitempty"` // pointer to distinguish false from absent
	ScanResult          *UIAuditScanResult    `json:"scan_result,omitempty"`
	CSPMediation        *UIAuditCSPMediation  `json:"csp_mediation,omitempty"`
	PermissionsMediation *UIAuditPermissions  `json:"permissions_mediation,omitempty"`
	CapabilityGrantMode string                `json:"capability_grant_mode,omitempty"`
}

// UIAuditScanResult holds resource scan results.
type UIAuditScanResult struct {
	DangerousPatternsFound int `json:"dangerous_patterns_found"`
	CSPViolationsFound     int `json:"csp_violations_found"`
}

// UIAuditCSPMediation holds CSP mediation decisions.
type UIAuditCSPMediation struct {
	DomainsStripped []string `json:"domains_stripped"`
	DomainsAllowed  []string `json:"domains_allowed"`
}

// UIAuditPermissions holds permission mediation decisions.
type UIAuditPermissions struct {
	PermissionsDenied  []string `json:"permissions_denied"`
	PermissionsAllowed []string `json:"permissions_allowed"`
}

// AppDrivenData holds app-driven tool invocation context and correlation data.
// Populated for tool.invocation.app_driven* event types.
type AppDrivenData struct {
	UIContext   *AppDrivenUIContext   `json:"ui_context,omitempty"`
	Correlation *AppDrivenCorrelation `json:"correlation,omitempty"`
}

// AppDrivenUIContext provides context about where the app-driven tool call
// originated from in the UI session.
type AppDrivenUIContext struct {
	ResourceURI     string `json:"resource_uri,omitempty"`
	ContentHash     string `json:"content_hash,omitempty"`
	OriginatingTool string `json:"originating_tool,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
}

// AppDrivenCorrelation provides correlation data for app-driven tool calls
// within a UI session.
type AppDrivenCorrelation struct {
	UISessionStart         string `json:"ui_session_start,omitempty"`
	ToolCallsInUISession   int    `json:"tool_calls_in_ui_session"`
	UserInteractionInferred bool   `json:"user_interaction_inferred"`
}

// ----- Emit Functions -----

// UIAuditEventParams holds the parameters for emitting a UI audit event.
// Callers populate the fields relevant to their event type and pass to
// EmitUIEvent.
type UIAuditEventParams struct {
	EventType string
	SessionID string
	TraceID   string
	SPIFFEID  string
	UI        *UIAuditData
	AppDriven *AppDrivenData
}

// EmitUIEvent constructs a full AuditEvent with UI-specific data and logs it
// through the Auditor's hash-chained pipeline. This ensures UI events:
//   - participate in the existing hash chain (hash_previous field)
//   - route to the same audit log sink (stdout + JSONL file)
//   - include trace_id for cross-event correlation
//   - carry the correct severity for the event type
func (a *Auditor) EmitUIEvent(params UIAuditEventParams) {
	severity := UIEventSeverity(params.EventType)

	event := AuditEvent{
		EventType: params.EventType,
		Severity:  severity,
		SessionID: params.SessionID,
		TraceID:   params.TraceID,
		SPIFFEID:  params.SPIFFEID,
		Action:    params.EventType, // Use event type as action for backward compatibility
		Result:    severity,         // Use severity as result for backward compatibility
		UI:        params.UI,
		AppDriven: params.AppDriven,
	}

	// Log through the standard Auditor pipeline. This handles:
	// - timestamp assignment
	// - hash chain (prev_hash, bundle_digest, registry_digest)
	// - writing to stdout and JSONL file
	a.Log(event)
}

// AllUIEventTypes returns all 10 UI event type constants. Useful for
// validation, testing, and documentation.
func AllUIEventTypes() []string {
	return []string{
		UIEventCapabilityStripped,
		UIEventCapabilityAuditPassthrough,
		UIEventResourceRead,
		UIEventResourceBlocked,
		UIEventResourceHashMismatch,
		UIEventCSPDomainStripped,
		UIEventPermissionDenied,
		UIEventToolInvocationAppDriven,
		UIEventToolInvocationAppDrivenBlocked,
		UIEventToolInvocationAppDrivenRateLimited,
	}
}

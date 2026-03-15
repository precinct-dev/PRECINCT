// MCP-UI CSP and Permissions Mediator - RFA-j2d.3
// Implements gateway-level mediation of _meta.ui.csp and _meta.ui.permissions
// in tool schemas (Reference Architecture Section 7.9.4).
//
// The gateway rewrites these advisory declarations from MCP servers before
// forwarding to the host, enforcing organizational policy:
//
// CSP mediation:
//   - connectDomains: intersected with grant's allowed_csp_connect_domains
//   - resourceDomains: intersected with grant's allowed_csp_resource_domains
//   - frameDomains: ALWAYS empty (hard constraint - nested iframes denied)
//   - baseUriDomains: ALWAYS empty (hard constraint - same-origin only)
//   - max_connect_domains and max_resource_domains enforced after intersection
//
// Permissions mediation:
//   - Each permission kept only if grant's allowed_permissions includes it
//   - Hard constraints override grants (e.g., camera_allowed=false in config
//     means camera is always denied regardless of grant)
//
// All stripped domains and denied permissions are logged as audit events.
package gateway

import (
	"path"
	"strings"
)

// UICSPInput represents the _meta.ui.csp fields from a tool schema as
// declared by the MCP server. These are advisory and subject to mediation.
type UICSPInput struct {
	ConnectDomains  []string `json:"connectDomains,omitempty"`
	ResourceDomains []string `json:"resourceDomains,omitempty"`
	FrameDomains    []string `json:"frameDomains,omitempty"`
	BaseURIDomains  []string `json:"baseUriDomains,omitempty"`
}

// UIPermissionsInput represents the _meta.ui.permissions fields from a tool
// schema. Each key is a permission name (camera, microphone, geolocation,
// clipboardWrite) and the value is whether the server requests it.
type UIPermissionsInput struct {
	Camera         bool `json:"camera,omitempty"`
	Microphone     bool `json:"microphone,omitempty"`
	Geolocation    bool `json:"geolocation,omitempty"`
	ClipboardWrite bool `json:"clipboardWrite,omitempty"`
}

// UICSPMediationResult holds the output of CSP mediation: the rewritten CSP
// fields and a list of audit events for stripped domains.
type UICSPMediationResult struct {
	// Rewritten CSP fields (post-mediation)
	ConnectDomains  []string
	ResourceDomains []string
	FrameDomains    []string // Always empty after mediation
	BaseURIDomains  []string // Always empty after mediation

	// Audit trail
	Events []UICSPMediationEvent
}

// UIPermissionsMediationResult holds the output of permissions mediation:
// the rewritten permissions and a list of audit events for denied permissions.
type UIPermissionsMediationResult struct {
	// Rewritten permissions (post-mediation)
	Camera         bool
	Microphone     bool
	Geolocation    bool
	ClipboardWrite bool

	// Audit trail
	Events []UICSPMediationEvent
}

// UICSPMediationEvent represents a single mediation decision for audit logging.
// These feed into the existing EmitUIEvent pipeline via the Auditor.
type UICSPMediationEvent struct {
	EventType string // "ui.csp.domain_stripped" or "ui.permission.denied"
	Server    string
	Tenant    string
	ToolName  string
	Field     string // CSP field name (e.g., "connectDomains") or permission name
	Domain    string // The domain that was stripped (empty for permission events)
	Reason    string // Why it was stripped/denied
}

// MediateCSP rewrites _meta.ui.csp fields according to the capability grant
// and hard constraints. It returns the mediated CSP and audit events.
//
// Mediation rules:
//  1. frameDomains: ALWAYS empty (hard constraint, regardless of grant)
//  2. baseUriDomains: ALWAYS empty (hard constraint, regardless of grant)
//  3. connectDomains: intersected with grant.AllowedCSPConnectDomains,
//     then truncated to config.CSPHardConstraints.MaxConnectDomains
//  4. resourceDomains: intersected with grant.AllowedCSPResourceDomains,
//     then truncated to config.CSPHardConstraints.MaxResourceDomains
func MediateCSP(
	input UICSPInput,
	grant *UICapabilityGrant,
	config *UIConfig,
	server, tenant, toolName string,
) UICSPMediationResult {
	result := UICSPMediationResult{}

	// --- frameDomains: ALWAYS empty (hard constraint) ---
	for _, domain := range input.FrameDomains {
		if domain != "" {
			result.Events = append(result.Events, UICSPMediationEvent{
				EventType: "ui.csp.domain_stripped",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Field:     "frameDomains",
				Domain:    domain,
				Reason:    "hard_constraint_frame_domains_denied",
			})
		}
	}
	result.FrameDomains = []string{} // Always empty

	// --- baseUriDomains: ALWAYS empty (hard constraint) ---
	for _, domain := range input.BaseURIDomains {
		if domain != "" {
			result.Events = append(result.Events, UICSPMediationEvent{
				EventType: "ui.csp.domain_stripped",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Field:     "baseUriDomains",
				Domain:    domain,
				Reason:    "hard_constraint_base_uri_denied",
			})
		}
	}
	result.BaseURIDomains = []string{} // Always empty

	// --- connectDomains: intersect with grant allowlist ---
	var allowedConnect []string
	if grant != nil {
		allowedConnect = grant.AllowedCSPConnectDomains
	}
	connectResult, connectEvents := intersectDomains(
		input.ConnectDomains,
		allowedConnect,
		"connectDomains",
		config.CSPHardConstraints.MaxConnectDomains,
		server, tenant, toolName,
	)
	result.ConnectDomains = connectResult
	result.Events = append(result.Events, connectEvents...)

	// --- resourceDomains: intersect with grant allowlist ---
	var allowedResource []string
	if grant != nil {
		allowedResource = grant.AllowedCSPResourceDomains
	}
	resourceResult, resourceEvents := intersectDomains(
		input.ResourceDomains,
		allowedResource,
		"resourceDomains",
		config.CSPHardConstraints.MaxResourceDomains,
		server, tenant, toolName,
	)
	result.ResourceDomains = resourceResult
	result.Events = append(result.Events, resourceEvents...)

	return result
}

// MediatePermissions rewrites _meta.ui.permissions according to the capability
// grant and hard constraints. Returns the mediated permissions and audit events.
//
// Mediation rules:
//  1. Hard constraints override everything: if config says camera_allowed=false,
//     camera is always denied regardless of grant.
//  2. For permissions not blocked by hard constraints, keep only if the grant's
//     allowed_permissions list includes the permission name.
//  3. Log each denied permission as a ui.permission.denied event.
func MediatePermissions(
	input UIPermissionsInput,
	grant *UICapabilityGrant,
	config *UIConfig,
	server, tenant, toolName string,
) UIPermissionsMediationResult {
	result := UIPermissionsMediationResult{}

	// Build the set of grant-allowed permissions for fast lookup
	grantAllowed := make(map[string]bool)
	if grant != nil {
		for _, p := range grant.AllowedPermissions {
			grantAllowed[p] = true
		}
	}

	// --- camera ---
	if input.Camera {
		if !config.PermissionsHardConstraints.CameraAllowed {
			result.Camera = false
			result.Events = append(result.Events, UICSPMediationEvent{
				EventType: "ui.permission.denied",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Field:     "camera",
				Reason:    "hard_constraint_camera_denied",
			})
		} else if !grantAllowed["camera"] {
			result.Camera = false
			result.Events = append(result.Events, UICSPMediationEvent{
				EventType: "ui.permission.denied",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Field:     "camera",
				Reason:    "not_in_grant_allowed_permissions",
			})
		} else {
			result.Camera = true
		}
	}

	// --- microphone ---
	if input.Microphone {
		if !config.PermissionsHardConstraints.MicrophoneAllowed {
			result.Microphone = false
			result.Events = append(result.Events, UICSPMediationEvent{
				EventType: "ui.permission.denied",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Field:     "microphone",
				Reason:    "hard_constraint_microphone_denied",
			})
		} else if !grantAllowed["microphone"] {
			result.Microphone = false
			result.Events = append(result.Events, UICSPMediationEvent{
				EventType: "ui.permission.denied",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Field:     "microphone",
				Reason:    "not_in_grant_allowed_permissions",
			})
		} else {
			result.Microphone = true
		}
	}

	// --- geolocation ---
	if input.Geolocation {
		if !config.PermissionsHardConstraints.GeolocationAllowed {
			result.Geolocation = false
			result.Events = append(result.Events, UICSPMediationEvent{
				EventType: "ui.permission.denied",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Field:     "geolocation",
				Reason:    "hard_constraint_geolocation_denied",
			})
		} else if !grantAllowed["geolocation"] {
			result.Geolocation = false
			result.Events = append(result.Events, UICSPMediationEvent{
				EventType: "ui.permission.denied",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Field:     "geolocation",
				Reason:    "not_in_grant_allowed_permissions",
			})
		} else {
			result.Geolocation = true
		}
	}

	// --- clipboardWrite ---
	if input.ClipboardWrite {
		if !config.PermissionsHardConstraints.ClipboardWriteAllowed {
			result.ClipboardWrite = false
			result.Events = append(result.Events, UICSPMediationEvent{
				EventType: "ui.permission.denied",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Field:     "clipboardWrite",
				Reason:    "hard_constraint_clipboard_write_denied",
			})
		} else if !grantAllowed["clipboardWrite"] {
			result.ClipboardWrite = false
			result.Events = append(result.Events, UICSPMediationEvent{
				EventType: "ui.permission.denied",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Field:     "clipboardWrite",
				Reason:    "not_in_grant_allowed_permissions",
			})
		} else {
			result.ClipboardWrite = true
		}
	}

	return result
}

// intersectDomains computes the intersection of server-declared domains with
// the grant's allowlist using glob matching. Domains not in the allowlist are
// stripped and logged. The result is truncated to maxDomains.
//
// Returns the allowed domains and audit events for stripped domains.
func intersectDomains(
	declared []string,
	allowlist []string,
	fieldName string,
	maxDomains int,
	server, tenant, toolName string,
) ([]string, []UICSPMediationEvent) {
	var allowed []string
	var events []UICSPMediationEvent

	for _, domain := range declared {
		if domain == "" {
			continue
		}
		if domainMatchesAllowlist(domain, allowlist) {
			allowed = append(allowed, domain)
		} else {
			events = append(events, UICSPMediationEvent{
				EventType: "ui.csp.domain_stripped",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Field:     fieldName,
				Domain:    domain,
				Reason:    "not_in_grant_allowlist",
			})
		}
	}

	// Enforce max domains hard constraint
	if maxDomains > 0 && len(allowed) > maxDomains {
		// Log the domains that are truncated
		for _, domain := range allowed[maxDomains:] {
			events = append(events, UICSPMediationEvent{
				EventType: "ui.csp.domain_stripped",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Field:     fieldName,
				Domain:    domain,
				Reason:    "max_domains_exceeded",
			})
		}
		allowed = allowed[:maxDomains]
	}

	// Return empty slice instead of nil for consistency
	if allowed == nil {
		allowed = []string{}
	}

	return allowed, events
}

// domainMatchesAllowlist checks if a domain matches any entry in the allowlist.
// Supports glob matching using path.Match semantics:
//   - "*.example.com" matches "api.example.com"
//   - "https://api.acme.corp" matches exactly "https://api.acme.corp"
//
// An empty allowlist means no domains are allowed.
func domainMatchesAllowlist(domain string, allowlist []string) bool {
	for _, pattern := range allowlist {
		// Try exact match first (most common case)
		if domain == pattern {
			return true
		}
		// Try glob match for wildcard patterns
		if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
			if matched, err := path.Match(pattern, domain); err == nil && matched {
				return true
			}
		}
	}
	return false
}

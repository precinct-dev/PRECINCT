// UI Response Processor - RFA-j2d.6
// Orchestrates UI-specific response processing for the gateway proxy handler.
// This is the central integration point that routes MCP responses through the
// appropriate UI control functions based on request type:
//
//   - tools/list responses: capability gating (RFA-j2d.1) + CSP mediation (RFA-j2d.3)
//   - ui:// resource reads: resource controls (RFA-j2d.2) + registry verification (RFA-j2d.5)
//   - all other responses: pass through unmodified
//
// This operates on the RESPONSE path (post-proxy) and does NOT modify the
// existing 13-step middleware chain on the REQUEST path.
//
// Reference Architecture Section 7.9.7.
package gateway

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

// UIResponseProcessor orchestrates UI-specific response processing.
// It holds references to the various UI control components and delegates
// to them based on the request type.
type UIResponseProcessor struct {
	capabilityGating *UICapabilityGating
	resourceControls *UIResourceControls
	registry         *middleware.ToolRegistry
	uiConfig         *UIConfig
	auditor          *middleware.Auditor
}

// NewUIResponseProcessor creates a new UIResponseProcessor with the given components.
func NewUIResponseProcessor(
	capabilityGating *UICapabilityGating,
	resourceControls *UIResourceControls,
	registry *middleware.ToolRegistry,
	uiConfig *UIConfig,
	auditor *middleware.Auditor,
) *UIResponseProcessor {
	return &UIResponseProcessor{
		capabilityGating: capabilityGating,
		resourceControls: resourceControls,
		registry:         registry,
		uiConfig:         uiConfig,
		auditor:          auditor,
	}
}

// ProcessToolsListResponse applies both capability gating and CSP/permissions
// mediation to a tools/list JSON-RPC response body. This is the integrated
// pipeline for tools/list responses on the response path.
//
// Processing order:
//  1. Capability gating (strip _meta.ui for denied/unapproved servers/tools)
//  2. CSP mediation (rewrite _meta.ui.csp for allowed tools)
//  3. Permissions mediation (rewrite _meta.ui.permissions for allowed tools)
//
// Parameters:
//   - responseBody: the raw JSON-RPC response from upstream
//   - server: the MCP server name
//   - tenant: the tenant identifier
//
// Returns the processed response body.
func (p *UIResponseProcessor) ProcessToolsListResponse(
	responseBody []byte,
	server, tenant string,
) []byte {
	// Step 1: Apply capability gating (strip _meta.ui for denied/unapproved)
	gatedBody, gatingEvents, err := p.capabilityGating.ApplyUICapabilityGating(responseBody, server, tenant)
	if err != nil {
		slog.Error("UI capability gating failed", "error", err)
		return responseBody
	}

	// Emit capability gating audit events
	for _, evt := range gatingEvents {
		p.auditor.EmitUIEvent(middleware.UIAuditEventParams{
			EventType: evt.EventType,
			UI: &middleware.UIAuditData{
				CapabilityGrantMode: evt.Mode,
			},
		})
	}

	// Step 2: Apply CSP and permissions mediation to surviving _meta.ui entries
	mediatedBody := p.mediateCSPAndPermissions(gatedBody, server, tenant)

	return mediatedBody
}

// mediateCSPAndPermissions walks the tools/list response after capability gating
// and applies CSP + permissions mediation to each tool that still has _meta.ui.
// Only tools whose _meta.ui survived capability gating are mediated.
func (p *UIResponseProcessor) mediateCSPAndPermissions(
	responseBody []byte,
	server, tenant string,
) []byte {
	// Parse the JSON-RPC response
	var response map[string]interface{}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		slog.Error("CSP mediation: failed to parse tools/list response", "error", err)
		return responseBody
	}

	result, ok := response["result"]
	if !ok {
		return responseBody
	}
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return responseBody
	}
	tools, ok := resultMap["tools"]
	if !ok {
		return responseBody
	}
	toolList, ok := tools.([]interface{})
	if !ok {
		return responseBody
	}

	// Look up the grant for CSP/permissions mediation
	grant := p.capabilityGating.LookupGrant(server, tenant)

	modified := false
	for _, toolItem := range toolList {
		tool, ok := toolItem.(map[string]interface{})
		if !ok {
			continue
		}

		meta, hasMeta := tool["_meta"]
		if !hasMeta {
			continue
		}
		metaMap, ok := meta.(map[string]interface{})
		if !ok {
			continue
		}
		uiRaw, hasUI := metaMap["ui"]
		if !hasUI {
			continue
		}

		uiMap, ok := uiRaw.(map[string]interface{})
		if !ok {
			continue
		}

		toolName, _ := tool["name"].(string)

		// Mediate CSP if present
		if cspRaw, hasCSP := uiMap["csp"]; hasCSP {
			cspInput := parseCSPInput(cspRaw)
			cspResult := MediateCSP(cspInput, grant, p.uiConfig, server, tenant, toolName)

			// Write back mediated CSP
			uiMap["csp"] = map[string]interface{}{
				"connectDomains":  cspResult.ConnectDomains,
				"resourceDomains": cspResult.ResourceDomains,
				"frameDomains":    cspResult.FrameDomains,
				"baseUriDomains":  cspResult.BaseURIDomains,
			}
			modified = true

			// Emit CSP mediation audit events
			var strippedDomains []string
			for _, evt := range cspResult.Events {
				strippedDomains = append(strippedDomains, evt.Domain)
			}
			if len(cspResult.Events) > 0 {
				p.auditor.EmitUIEvent(middleware.UIAuditEventParams{
					EventType: cspResult.Events[0].EventType,
					UI: &middleware.UIAuditData{
						CSPMediation: &middleware.UIAuditCSPMediation{
							DomainsStripped: strippedDomains,
							DomainsAllowed:  cspResult.ConnectDomains,
						},
					},
				})
			}
		}

		// Mediate permissions if present
		if permsRaw, hasPerms := uiMap["permissions"]; hasPerms {
			permsInput := parsePermissionsInput(permsRaw)
			permsResult := MediatePermissions(permsInput, grant, p.uiConfig, server, tenant, toolName)

			// Write back mediated permissions
			uiMap["permissions"] = map[string]interface{}{
				"camera":         permsResult.Camera,
				"microphone":     permsResult.Microphone,
				"geolocation":    permsResult.Geolocation,
				"clipboardWrite": permsResult.ClipboardWrite,
			}
			modified = true

			// Emit permissions mediation audit events
			var deniedPerms []string
			var allowedPerms []string
			for _, evt := range permsResult.Events {
				deniedPerms = append(deniedPerms, evt.Field)
			}
			// Track which permissions were allowed
			if permsResult.Camera {
				allowedPerms = append(allowedPerms, "camera")
			}
			if permsResult.Microphone {
				allowedPerms = append(allowedPerms, "microphone")
			}
			if permsResult.Geolocation {
				allowedPerms = append(allowedPerms, "geolocation")
			}
			if permsResult.ClipboardWrite {
				allowedPerms = append(allowedPerms, "clipboardWrite")
			}
			if len(permsResult.Events) > 0 {
				p.auditor.EmitUIEvent(middleware.UIAuditEventParams{
					EventType: permsResult.Events[0].EventType,
					UI: &middleware.UIAuditData{
						PermissionsMediation: &middleware.UIAuditPermissions{
							PermissionsDenied:  deniedPerms,
							PermissionsAllowed: allowedPerms,
						},
					},
				})
			}
		}
	}

	if !modified {
		return responseBody
	}

	// Re-serialize
	processedBody, err := json.Marshal(response)
	if err != nil {
		slog.Error("CSP mediation: failed to re-serialize response", "error", err)
		return responseBody
	}

	return processedBody
}

// ProcessUIResourceResponse applies resource controls and registry verification
// to a ui:// resource read response.
//
// Processing order:
//  1. Content-type validation (must be text/html;profile=mcp-app)
//  2. Size limit enforcement
//  3. Content scanning for dangerous patterns
//  4. Hash verification (rug-pull detection)
//  5. Registry verification (resource must be registered with matching hash)
//
// Parameters:
//   - content: the raw resource content from upstream
//   - contentType: the Content-Type header from upstream
//   - server: the MCP server name
//   - tenant: the tenant identifier
//   - resourceURI: the ui:// resource URI
//
// Returns:
//   - allowed: whether the resource passed all controls
//   - reason: reason for blocking if not allowed
//   - events: audit events generated during processing
func (p *UIResponseProcessor) ProcessUIResourceResponse(
	content []byte,
	contentType string,
	server, tenant, resourceURI string,
) (allowed bool, reason string, events []UIResourceControlEvent) {
	// Look up per-server size limit override from grant
	var maxSizeOverride int64
	grant := p.capabilityGating.LookupGrant(server, tenant)
	if grant != nil && grant.MaxResourceSizeBytes > 0 {
		maxSizeOverride = grant.MaxResourceSizeBytes
	}

	// Step 1-4: Apply resource controls (content-type, size, scan, hash)
	result := p.resourceControls.ApplyResourceControls(
		content, contentType, server, tenant, resourceURI, maxSizeOverride,
	)

	if !result.Allowed {
		// Emit audit events for blocked resources
		for _, evt := range result.Events {
			p.auditor.EmitUIEvent(middleware.UIAuditEventParams{
				EventType: evt.EventType,
				UI: &middleware.UIAuditData{
					ResourceURI: evt.ResourceURI,
				},
			})
		}
		return false, result.Reason, result.Events
	}

	// Step 5: Registry verification (RFA-j2d.5)
	registryResult := p.registry.VerifyUIResource(server, resourceURI, content)
	if !registryResult.Allowed {
		evt := UIResourceControlEvent{
			EventType:   "ui.resource.registry_blocked",
			Server:      server,
			Tenant:      tenant,
			ResourceURI: resourceURI,
			Reason:      registryResult.Reason,
			Severity:    registryResult.AlertLevel,
		}
		p.auditor.EmitUIEvent(middleware.UIAuditEventParams{
			EventType: evt.EventType,
			UI: &middleware.UIAuditData{
				ResourceURI: resourceURI,
			},
		})
		return false, registryResult.Reason, []UIResourceControlEvent{evt}
	}

	return true, "", nil
}

// parseCSPInput extracts UICSPInput from an untyped map (JSON-decoded _meta.ui.csp).
func parseCSPInput(raw interface{}) UICSPInput {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return UICSPInput{}
	}
	return UICSPInput{
		ConnectDomains:  extractStringSlice(m, "connectDomains"),
		ResourceDomains: extractStringSlice(m, "resourceDomains"),
		FrameDomains:    extractStringSlice(m, "frameDomains"),
		BaseURIDomains:  extractStringSlice(m, "baseUriDomains"),
	}
}

// parsePermissionsInput extracts UIPermissionsInput from an untyped map.
func parsePermissionsInput(raw interface{}) UIPermissionsInput {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return UIPermissionsInput{}
	}
	return UIPermissionsInput{
		Camera:         extractBool(m, "camera"),
		Microphone:     extractBool(m, "microphone"),
		Geolocation:    extractBool(m, "geolocation"),
		ClipboardWrite: extractBool(m, "clipboardWrite"),
	}
}

// extractStringSlice extracts a []string from a map field that is []interface{}.
func extractStringSlice(m map[string]interface{}, key string) []string {
	raw, ok := m[key]
	if !ok {
		return nil
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// extractBool extracts a bool from a map field.
func extractBool(m map[string]interface{}, key string) bool {
	raw, ok := m[key]
	if !ok {
		return false
	}
	b, ok := raw.(bool)
	if !ok {
		return false
	}
	return b
}

// UIResourceBlockedError represents a blocked UI resource response for
// generating the JSON error body returned to the caller.
type UIResourceBlockedError struct {
	Error  string `json:"error"`
	Detail string `json:"detail"`
}

// NewUIResourceBlockedError creates a standard blocked response.
func NewUIResourceBlockedError(reason string) UIResourceBlockedError {
	return UIResourceBlockedError{
		Error:  "ui_resource_blocked",
		Detail: fmt.Sprintf("UI resource blocked: %s", reason),
	}
}

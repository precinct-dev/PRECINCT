// MCP-UI Capability Gating - RFA-j2d.1
// Implements per-server, per-tenant, per-tool opt-in capability gating for MCP-UI
// features (Reference Architecture Section 7.9.2).
//
// Three enforcement modes:
//   - deny (default): Strip _meta.ui from tool listings, block ui:// reads with 403
//   - allow:          Permit _meta.ui and ui:// reads (subject to approved_tools list)
//   - audit-only:     Permit but flag all UI activity; emit high-priority audit events
//
// The global kill switch (UIConfig.Enabled=false) overrides all grants.
package gateway

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// UICapabilityMode represents the enforcement mode for a server/tenant pair.
type UICapabilityMode string

const (
	UICapabilityModeDeny      UICapabilityMode = "deny"
	UICapabilityModeAllow     UICapabilityMode = "allow"
	UICapabilityModeAuditOnly UICapabilityMode = "audit-only"
)

// UICapabilityGrant defines a per-server/tenant capability grant from the
// ui_capability_grants.yaml policy data file.
type UICapabilityGrant struct {
	Server                    string   `yaml:"server"                     json:"server"`
	Tenant                    string   `yaml:"tenant"                     json:"tenant"`
	Mode                      string   `yaml:"mode"                       json:"mode"`
	ApprovedTools             []string `yaml:"approved_tools"             json:"approved_tools"`
	MaxResourceSizeBytes      int64    `yaml:"max_resource_size_bytes"    json:"max_resource_size_bytes"`
	AllowedCSPConnectDomains  []string `yaml:"allowed_csp_connect_domains"  json:"allowed_csp_connect_domains"`
	AllowedCSPResourceDomains []string `yaml:"allowed_csp_resource_domains" json:"allowed_csp_resource_domains"`
	AllowedPermissions        []string `yaml:"allowed_permissions"          json:"allowed_permissions"`
	ApprovedAt                string   `yaml:"approved_at"                json:"approved_at"`
	ApprovedBy                string   `yaml:"approved_by"                json:"approved_by"`
}

// uiCapabilityGrantsFile is the YAML wrapper for the grants data file.
type uiCapabilityGrantsFile struct {
	Grants []UICapabilityGrant `yaml:"ui_capability_grants"`
}

// UICapabilityGatingEvent represents an audit event emitted by the capability gating logic.
// Downstream audit middleware consumes these to write structured events.
type UICapabilityGatingEvent struct {
	EventType string `json:"event_type"`
	Server    string `json:"server"`
	Tenant    string `json:"tenant"`
	ToolName  string `json:"tool_name,omitempty"`
	Mode      string `json:"mode"`
	Reason    string `json:"reason"`
}

// UICapabilityGating encapsulates the gating logic. It loads grants from
// a YAML file and provides methods to query mode, strip _meta.ui from
// tool listings, and block ui:// resource reads.
type UICapabilityGating struct {
	grants   []UICapabilityGrant
	grantMap map[string]*UICapabilityGrant // key: "server|tenant"
	uiConfig *UIConfig
}

// NewUICapabilityGating creates a new UICapabilityGating from the gateway UIConfig
// and an optional grants YAML file path. If the file does not exist or cannot
// be parsed, the gating operates with no grants (all servers default to deny or
// the UIConfig.DefaultMode).
func NewUICapabilityGating(uiConfig *UIConfig, grantsPath string) *UICapabilityGating {
	g := &UICapabilityGating{
		uiConfig: uiConfig,
		grantMap: make(map[string]*UICapabilityGrant),
	}

	if grantsPath == "" {
		return g
	}

	grants, err := LoadUICapabilityGrants(grantsPath)
	if err != nil {
		log.Printf("[WARN] Failed to load UI capability grants from %s: %v (operating with no grants)", grantsPath, err)
		return g
	}

	g.grants = grants
	for i := range grants {
		key := grantKey(grants[i].Server, grants[i].Tenant)
		g.grantMap[key] = &grants[i]
	}

	return g
}

// LoadUICapabilityGrants loads capability grants from a YAML file.
func LoadUICapabilityGrants(path string) ([]UICapabilityGrant, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read UI capability grants file %s: %w", path, err)
	}

	var wrapper uiCapabilityGrantsFile
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse UI capability grants YAML: %w", err)
	}

	return wrapper.Grants, nil
}

// grantKey builds the lookup key for a server/tenant pair.
func grantKey(server, tenant string) string {
	return server + "|" + tenant
}

// LookupGrant returns the grant for a server/tenant pair, or nil if none.
func (g *UICapabilityGating) LookupGrant(server, tenant string) *UICapabilityGrant {
	return g.grantMap[grantKey(server, tenant)]
}

// ResolveMode determines the effective capability mode for a server/tenant pair.
// Resolution order:
//  1. Global kill switch: if ui.enabled=false -> deny (always)
//  2. Explicit grant -> grant.Mode
//  3. No grant -> UIConfig.DefaultMode
func (g *UICapabilityGating) ResolveMode(server, tenant string) UICapabilityMode {
	// Global kill switch
	if !g.uiConfig.Enabled {
		return UICapabilityModeDeny
	}

	// Look up explicit grant
	grant := g.LookupGrant(server, tenant)
	if grant != nil {
		return parseCapabilityMode(grant.Mode)
	}

	// Fall back to default mode
	return parseCapabilityMode(g.uiConfig.DefaultMode)
}

// IsToolApproved checks whether a specific tool is in the grant's approved_tools list.
// If the approved_tools list is empty, ALL tools are considered approved (for the
// purpose of the allow/audit-only modes). If the list is non-empty, only tools
// in the list are approved.
func (g *UICapabilityGating) IsToolApproved(server, tenant, toolName string) bool {
	grant := g.LookupGrant(server, tenant)
	if grant == nil {
		// No grant = no tools approved
		return false
	}

	// Empty approved_tools list means all tools are approved
	if len(grant.ApprovedTools) == 0 {
		return true
	}

	for _, t := range grant.ApprovedTools {
		if t == toolName {
			return true
		}
	}
	return false
}

// ApplyUICapabilityGating processes a tools/list JSON-RPC response, stripping
// or retaining _meta.ui based on the resolved mode for the given server/tenant.
//
// Returns:
//   - processedBody: the modified response body (JSON bytes)
//   - events: audit events generated during processing
//   - err: any JSON parsing error
//
// The function modifies _meta.ui in-place for each tool in the response.
func (g *UICapabilityGating) ApplyUICapabilityGating(
	responseBody []byte,
	server, tenant string,
) ([]byte, []UICapabilityGatingEvent, error) {
	mode := g.ResolveMode(server, tenant)
	var events []UICapabilityGatingEvent

	// Parse the JSON-RPC response to find tools with _meta.ui
	var response map[string]interface{}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return responseBody, nil, fmt.Errorf("failed to parse tools/list response: %w", err)
	}

	// Navigate to result.tools (standard JSON-RPC response structure)
	result, ok := response["result"]
	if !ok {
		// No result field - return as-is
		return responseBody, events, nil
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return responseBody, events, nil
	}

	tools, ok := resultMap["tools"]
	if !ok {
		return responseBody, events, nil
	}

	toolList, ok := tools.([]interface{})
	if !ok {
		return responseBody, events, nil
	}

	modified := false

	for _, toolItem := range toolList {
		tool, ok := toolItem.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if tool has _meta.ui
		meta, hasMeta := tool["_meta"]
		if !hasMeta {
			continue
		}

		metaMap, ok := meta.(map[string]interface{})
		if !ok {
			continue
		}

		_, hasUI := metaMap["ui"]
		if !hasUI {
			continue
		}

		// Get tool name for logging/filtering
		toolName, _ := tool["name"].(string)

		switch mode {
		case UICapabilityModeDeny:
			// Strip _meta.ui
			delete(metaMap, "ui")
			modified = true

			// If _meta is now empty, remove it entirely
			if len(metaMap) == 0 {
				delete(tool, "_meta")
			}

			events = append(events, UICapabilityGatingEvent{
				EventType: "ui.capability.stripped",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Mode:      string(UICapabilityModeDeny),
				Reason:    "server_not_approved",
			})

		case UICapabilityModeAuditOnly:
			// Keep _meta.ui but emit audit event
			events = append(events, UICapabilityGatingEvent{
				EventType: "ui.capability.audit_passthrough",
				Server:    server,
				Tenant:    tenant,
				ToolName:  toolName,
				Mode:      string(UICapabilityModeAuditOnly),
				Reason:    "audit_only_mode",
			})

		case UICapabilityModeAllow:
			// Check if tool is in approved_tools list
			if !g.IsToolApproved(server, tenant, toolName) {
				// Strip _meta.ui for unapproved tools
				delete(metaMap, "ui")
				modified = true

				if len(metaMap) == 0 {
					delete(tool, "_meta")
				}

				events = append(events, UICapabilityGatingEvent{
					EventType: "ui.capability.stripped",
					Server:    server,
					Tenant:    tenant,
					ToolName:  toolName,
					Mode:      string(UICapabilityModeAllow),
					Reason:    "tool_not_in_approved_list",
				})
			}
			// Approved tools keep _meta.ui
		}
	}

	// Re-serialize if modified
	if modified {
		processedBody, err := json.Marshal(response)
		if err != nil {
			return responseBody, events, fmt.Errorf("failed to re-serialize tools/list response: %w", err)
		}
		return processedBody, events, nil
	}

	return responseBody, events, nil
}

// CheckUIResourceReadAllowed determines whether a ui:// resource read is permitted
// for the given server/tenant. Returns:
//   - allowed: true if the read should proceed
//   - event: audit event if generated (nil if none)
//
// Behavior:
//   - Global kill switch off -> deny
//   - deny mode -> deny with 403
//   - audit-only -> allow with audit event
//   - allow -> allow (resource controls applied separately by RFA-j2d.2)
func (g *UICapabilityGating) CheckUIResourceReadAllowed(
	server, tenant, resourceURI string,
) (bool, *UICapabilityGatingEvent) {
	mode := g.ResolveMode(server, tenant)

	switch mode {
	case UICapabilityModeDeny:
		return false, &UICapabilityGatingEvent{
			EventType: "ui.resource.blocked",
			Server:    server,
			Tenant:    tenant,
			Mode:      string(UICapabilityModeDeny),
			Reason:    "ui_capability_denied",
		}

	case UICapabilityModeAuditOnly:
		return true, &UICapabilityGatingEvent{
			EventType: "ui.capability.audit_passthrough",
			Server:    server,
			Tenant:    tenant,
			Mode:      string(UICapabilityModeAuditOnly),
			Reason:    "audit_only_ui_resource_read",
		}

	case UICapabilityModeAllow:
		return true, nil

	default:
		// Unknown mode -> deny (fail closed)
		return false, &UICapabilityGatingEvent{
			EventType: "ui.resource.blocked",
			Server:    server,
			Tenant:    tenant,
			Mode:      string(mode),
			Reason:    "unknown_mode_fail_closed",
		}
	}
}

// IsUIResourceURI returns true if the URI has the ui:// scheme.
func IsUIResourceURI(uri string) bool {
	return strings.HasPrefix(uri, "ui://")
}

// parseCapabilityMode converts a string to UICapabilityMode.
// Unrecognized values default to deny (fail-closed).
func parseCapabilityMode(mode string) UICapabilityMode {
	switch mode {
	case "deny":
		return UICapabilityModeDeny
	case "allow":
		return UICapabilityModeAllow
	case "audit-only":
		return UICapabilityModeAuditOnly
	default:
		return UICapabilityModeDeny
	}
}

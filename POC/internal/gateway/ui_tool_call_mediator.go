// MCP-UI Tool-Call Mediation - RFA-j2d.4
// Implements stricter gateway controls for tool calls originating from UI apps
// via postMessage (Reference Architecture Section 7.9.5).
//
// App-driven tool calls have different risk characteristics than agent-driven
// (LLM-driven) calls:
//   - Lower friction (single click vs LLM deliberation)
//   - Higher rate (limited by click speed vs inference speed)
//   - Less visibility (UI interaction may not be in model context)
//   - Requires explicit UI-to-action correlation for auditing
//
// This module provides:
//  1. Call origin identification (app-driven vs agent-driven)
//  2. Separate rate limit configuration for app-driven calls
//  3. Tool allowlisting against UICapabilityGrant.ApprovedTools
//  4. Visibility enforcement (app-only excluded from agent, model-only blocked from app)
//  5. Cross-server app-driven call blocking
//  6. Forced step-up for app-driven high/critical risk tools
//  7. Audit event emission with ui_context and correlation data
package gateway

import (
	"time"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
)

// CallOrigin represents whether a tool call is agent-driven or app-driven.
type CallOrigin string

const (
	// CallOriginAgent indicates the call was initiated by the LLM agent.
	CallOriginAgent CallOrigin = "agent"
	// CallOriginApp indicates the call was initiated by a UI app via postMessage.
	CallOriginApp CallOrigin = "app"
)

// ToolVisibility represents the visibility constraint on a tool.
type ToolVisibility string

const (
	// VisibilityModel means the tool is only for model/agent use.
	VisibilityModel ToolVisibility = "model"
	// VisibilityApp means the tool is only for app/UI use.
	VisibilityApp ToolVisibility = "app"
	// VisibilityBoth means the tool is available to both model and app.
	VisibilityBoth ToolVisibility = "both"
)

// UIToolCallContext carries the UI context for an app-driven tool call.
// Populated from the request when the host annotates app-originated calls.
type UIToolCallContext struct {
	ResourceURI     string `json:"resource_uri,omitempty"`
	ContentHash     string `json:"content_hash,omitempty"`
	OriginatingTool string `json:"originating_tool,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
}

// ToolCallMediationRequest represents a tool call that needs mediation.
type ToolCallMediationRequest struct {
	ToolName   string             // The tool being invoked
	Server     string             // MCP server name
	Tenant     string             // Tenant identifier
	RiskLevel  string             // Tool risk level from registry: low, medium, high, critical
	Visibility []ToolVisibility   // Tool visibility constraints (may be empty = both)
	UIContext  *UIToolCallContext // Non-nil if UI context is present in the request
	CallOrigin CallOrigin         // Detected call origin
}

// ToolCallMediationResult contains the outcome of tool call mediation.
type ToolCallMediationResult struct {
	Allowed        bool   `json:"allowed"`
	Reason         string `json:"reason"`
	RequiresStepUp bool   `json:"requires_step_up"`
	RateLimited    bool   `json:"rate_limited"`
	AuditEventType string `json:"audit_event_type,omitempty"`
}

// AppDrivenRateLimitConfig holds the separate rate limit parameters for
// app-driven tool calls. Values come from UIConfig.AppToolCalls.
type AppDrivenRateLimitConfig struct {
	Enabled           bool // Whether separate rate limiting is enabled
	RequestsPerMinute int  // Default: 20
	Burst             int  // Default: 5
}

// ToolCallMediator implements the mediation logic for app-driven tool calls.
// It is stateless per-call; rate limiting state lives in the RateLimiter.
type ToolCallMediator struct {
	uiConfig         *UIConfig
	capabilityGating *UICapabilityGating
}

// NewToolCallMediator creates a new mediator with the given configuration.
func NewToolCallMediator(uiConfig *UIConfig, capabilityGating *UICapabilityGating) *ToolCallMediator {
	return &ToolCallMediator{
		uiConfig:         uiConfig,
		capabilityGating: capabilityGating,
	}
}

// DetectCallOrigin determines whether a tool call is app-driven or agent-driven.
//
// A call is considered app-driven if:
//  1. The request has explicit UI context (host annotated the call), OR
//  2. The tool's visibility includes "app" AND there is an active UI session
//     (indicated by a non-empty session ID in the UI context).
//
// If the host does not annotate origin, ALL calls to app-visible tools during
// an active UI session are treated as potentially app-driven (fail-safe).
func DetectCallOrigin(uiContext *UIToolCallContext, visibility []ToolVisibility) CallOrigin {
	// If explicit UI context is present with a resource_uri or originating_tool,
	// this is definitively app-driven (host annotated the call).
	if uiContext != nil && (uiContext.ResourceURI != "" || uiContext.OriginatingTool != "") {
		return CallOriginApp
	}

	// If there's a UI session active (session ID present) and the tool is
	// app-visible, treat as potentially app-driven.
	if uiContext != nil && uiContext.SessionID != "" && hasAppVisibility(visibility) {
		return CallOriginApp
	}

	return CallOriginAgent
}

// hasAppVisibility returns true if the visibility list includes "app" or "both",
// or if the list is empty (default = both).
func hasAppVisibility(visibility []ToolVisibility) bool {
	if len(visibility) == 0 {
		return true // Empty visibility means both
	}
	for _, v := range visibility {
		if v == VisibilityApp || v == VisibilityBoth {
			return true
		}
	}
	return false
}

// hasModelVisibility returns true if the visibility list includes "model" or "both",
// or if the list is empty (default = both).
func hasModelVisibility(visibility []ToolVisibility) bool {
	if len(visibility) == 0 {
		return true
	}
	for _, v := range visibility {
		if v == VisibilityModel || v == VisibilityBoth {
			return true
		}
	}
	return false
}

// CheckToolAllowlist verifies that an app-driven call targets a tool that
// is in the capability grant's approved_tools list for the given server/tenant.
//
// Returns true if the tool is allowed, false if blocked.
// Agent-driven calls bypass this check entirely.
func (m *ToolCallMediator) CheckToolAllowlist(req *ToolCallMediationRequest) bool {
	if req.CallOrigin != CallOriginApp {
		return true // Agent-driven calls are not subject to app allowlisting
	}

	if m.capabilityGating == nil {
		return false // No capability gating = no approved tools = deny (fail closed)
	}

	return m.capabilityGating.IsToolApproved(req.Server, req.Tenant, req.ToolName)
}

// CheckVisibility enforces tool visibility constraints:
//   - Tools with visibility ["app"] (app-only) MUST NOT be in the agent's tool list.
//   - Tools with visibility ["model"] (model-only) MUST NOT be callable from app.
//
// Returns (allowed bool, reason string).
func CheckVisibility(callOrigin CallOrigin, visibility []ToolVisibility) (bool, string) {
	switch callOrigin {
	case CallOriginApp:
		// App-driven: block if tool is model-only
		if isModelOnly(visibility) {
			return false, "model-only tool cannot be called from app"
		}
	case CallOriginAgent:
		// Agent-driven: block if tool is app-only
		if isAppOnly(visibility) {
			return false, "app-only tool must not be in agent tool list"
		}
	}
	return true, ""
}

// isModelOnly returns true if the visibility list contains only "model".
func isModelOnly(visibility []ToolVisibility) bool {
	if len(visibility) == 0 {
		return false // Empty = both
	}
	for _, v := range visibility {
		if v != VisibilityModel {
			return false
		}
	}
	return true
}

// isAppOnly returns true if the visibility list contains only "app".
func isAppOnly(visibility []ToolVisibility) bool {
	if len(visibility) == 0 {
		return false // Empty = both
	}
	for _, v := range visibility {
		if v != VisibilityApp {
			return false
		}
	}
	return true
}

// CheckCrossServerBlocked returns true if an app-driven call attempts to
// invoke a tool on a different server than the originating UI resource.
// Cross-server tool calls from apps are ALWAYS blocked per the MCP Apps spec.
//
// The originating server is inferred from the UI context's resource_uri.
// If the tool's server does not match the originating server, the call is blocked.
func CheckCrossServerBlocked(req *ToolCallMediationRequest) (bool, string) {
	if req.CallOrigin != CallOriginApp {
		return false, "" // Agent-driven calls are not subject to cross-server blocking
	}

	if req.UIContext == nil || req.UIContext.ResourceURI == "" {
		return false, "" // No UI context to determine origin server
	}

	// Extract server from resource URI: ui://<server>/...
	originServer := extractServerFromResourceURI(req.UIContext.ResourceURI)
	if originServer == "" {
		return false, "" // Cannot determine origin server
	}

	if originServer != req.Server {
		return true, "cross-server app-driven tool calls are always blocked"
	}

	return false, ""
}

// extractServerFromResourceURI extracts the server name from a ui:// resource URI.
// Format: ui://<server-name>/<path>
func extractServerFromResourceURI(uri string) string {
	// Must start with "ui://"
	if len(uri) < 6 || uri[:5] != "ui://" {
		return ""
	}
	rest := uri[5:]
	// Find the next "/" after the server name
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[:i]
		}
	}
	// No path separator: the entire rest is the server name
	return rest
}

// RequiresAppDrivenStepUp returns true if an app-driven call to a high or
// critical risk tool should force step-up gating, regardless of session risk score.
//
// Rationale: buttons create dangerously low-friction paths to high-impact actions.
// Only applies when UIConfig.AppToolCalls.ForceStepUpForHighRisk is true.
func (m *ToolCallMediator) RequiresAppDrivenStepUp(req *ToolCallMediationRequest) bool {
	if req.CallOrigin != CallOriginApp {
		return false
	}

	if !m.uiConfig.AppToolCalls.ForceStepUpForHighRisk {
		return false
	}

	return req.RiskLevel == "high" || req.RiskLevel == "critical"
}

// GetAppDrivenRateLimitConfig returns the rate limit configuration for app-driven
// calls based on the UIConfig.
func (m *ToolCallMediator) GetAppDrivenRateLimitConfig() AppDrivenRateLimitConfig {
	return AppDrivenRateLimitConfig{
		Enabled:           m.uiConfig.AppToolCalls.SeparateRateLimit,
		RequestsPerMinute: m.uiConfig.AppToolCalls.RequestsPerMinute,
		Burst:             m.uiConfig.AppToolCalls.Burst,
	}
}

// Mediate runs the full mediation pipeline for a tool call.
// It checks visibility, allowlisting, cross-server blocking, and step-up requirements.
//
// This does NOT enforce rate limiting (that happens in the rate limiter middleware)
// or execute step-up (that happens in step-up gating middleware). It returns
// the mediation decision for the calling middleware to act on.
func (m *ToolCallMediator) Mediate(req *ToolCallMediationRequest) *ToolCallMediationResult {
	result := &ToolCallMediationResult{
		Allowed: true,
	}

	// 1. Visibility enforcement
	allowed, reason := CheckVisibility(req.CallOrigin, req.Visibility)
	if !allowed {
		result.Allowed = false
		result.Reason = reason
		result.AuditEventType = middleware.UIEventToolInvocationAppDrivenBlocked
		return result
	}

	// 2. Tool allowlisting (app-driven only)
	if !m.CheckToolAllowlist(req) {
		result.Allowed = false
		result.Reason = "tool not in approved_tools for this server/tenant"
		result.AuditEventType = middleware.UIEventToolInvocationAppDrivenBlocked
		return result
	}

	// 3. Cross-server blocking (app-driven only)
	blocked, reason := CheckCrossServerBlocked(req)
	if blocked {
		result.Allowed = false
		result.Reason = reason
		result.AuditEventType = middleware.UIEventToolInvocationAppDrivenBlocked
		return result
	}

	// 4. Step-up requirement (app-driven high/critical risk)
	if m.RequiresAppDrivenStepUp(req) {
		result.RequiresStepUp = true
	}

	// 5. Audit event type for allowed app-driven calls
	if req.CallOrigin == CallOriginApp {
		result.AuditEventType = middleware.UIEventToolInvocationAppDriven
	}

	return result
}

// BuildAppDrivenAuditData constructs the audit data for an app-driven tool call.
// Returns the AppDrivenData structure suitable for inclusion in an AuditEvent.
func BuildAppDrivenAuditData(
	uiContext *UIToolCallContext,
	toolCallCount int,
	uiSessionStart time.Time,
) *middleware.AppDrivenData {
	data := &middleware.AppDrivenData{
		Correlation: &middleware.AppDrivenCorrelation{
			ToolCallsInUISession:    toolCallCount,
			UserInteractionInferred: true, // App-driven = user interaction
		},
	}

	if !uiSessionStart.IsZero() {
		data.Correlation.UISessionStart = uiSessionStart.UTC().Format(time.RFC3339)
	}

	if uiContext != nil {
		data.UIContext = &middleware.AppDrivenUIContext{
			ResourceURI:     uiContext.ResourceURI,
			ContentHash:     uiContext.ContentHash,
			OriginatingTool: uiContext.OriginatingTool,
			SessionID:       uiContext.SessionID,
		}
	}

	return data
}

// IsToolAppOnly returns true if the given visibility list marks the tool as app-only.
// Exported for use by middleware that filters agent tool lists.
func IsToolAppOnly(visibility []ToolVisibility) bool {
	return isAppOnly(visibility)
}

// IsToolModelOnly returns true if the given visibility list marks the tool as model-only.
// Exported for use by middleware that filters app tool calls.
func IsToolModelOnly(visibility []ToolVisibility) bool {
	return isModelOnly(visibility)
}

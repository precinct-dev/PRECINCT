// OPA UI Input Extension - RFA-j2d.7
// Extends the OPA evaluation context with UI-specific fields for MCP-UI
// (Apps Extension) security decisions (Reference Architecture Section 7.9.8).
//
// The UIInput struct is marshaled into the "ui" section of the OPA input
// document, enabling Rego policies in the mcp.ui.policy package to make
// decisions about UI resource access, app-driven tool calls, and rate limits.
package middleware

// UIInput represents UI-specific fields added to the OPA evaluation input.
// Marshaled as the "ui" section of the OPA input document.
type UIInput struct {
	// Enabled indicates whether MCP-UI is active for this request context.
	Enabled bool `json:"enabled"`

	// ResourceURI is the ui:// URI being accessed (for resource reads).
	ResourceURI string `json:"resource_uri,omitempty"`

	// ResourceContentHash is the SHA-256 hash of the UI resource content,
	// used for integrity verification against the UI resource registry.
	ResourceContentHash string `json:"resource_content_hash,omitempty"`

	// DeclaredCSP holds the Content Security Policy declared by the MCP server
	// for this UI resource.
	DeclaredCSP *DeclaredCSPInput `json:"declared_csp,omitempty"`

	// DeclaredPermissions holds the browser permissions declared by the MCP server.
	DeclaredPermissions *DeclaredPermsInput `json:"declared_permissions,omitempty"`

	// ToolVisibility lists the visibility scopes for this tool (e.g., "model", "app").
	ToolVisibility []string `json:"tool_visibility,omitempty"`

	// CallOrigin indicates who initiated the tool call: "model" or "app".
	CallOrigin string `json:"call_origin,omitempty"`

	// AppSessionToolCalls is the number of tool calls made by the app in this session.
	AppSessionToolCalls int `json:"app_session_tool_calls"`

	// ResourceRegistered indicates whether the UI resource is in the registry.
	ResourceRegistered bool `json:"resource_registered"`

	// ResourceHashVerified indicates whether the resource content hash matches the registry.
	ResourceHashVerified bool `json:"resource_hash_verified"`
}

// DeclaredCSPInput represents the Content Security Policy declarations from the MCP server.
type DeclaredCSPInput struct {
	ConnectDomains  []string `json:"connectDomains,omitempty"`
	ResourceDomains []string `json:"resourceDomains,omitempty"`
	FrameDomains    []string `json:"frameDomains,omitempty"`
	BaseURIDomains  []string `json:"baseUriDomains,omitempty"`
}

// DeclaredPermsInput represents browser permission declarations from the MCP server.
type DeclaredPermsInput struct {
	Camera         bool `json:"camera"`
	Microphone     bool `json:"microphone"`
	Geolocation    bool `json:"geolocation"`
	ClipboardWrite bool `json:"clipboardWrite"`
}

// UIPolicyInput represents the full input to the mcp.ui.policy OPA package.
// It combines the standard OPA input fields needed by UI policy rules with
// the UI-specific input section.
type UIPolicyInput struct {
	UI            UIInput `json:"ui"`
	ToolServer    string  `json:"tool_server"`
	Tool          string  `json:"tool"`
	ToolRiskLevel string  `json:"tool_risk_level"`
}

// UIPolicyResult holds the evaluation results from the mcp.ui.policy package.
// Each field corresponds to a rule in the Rego policy.
type UIPolicyResult struct {
	DenyUIResource    bool `json:"deny_ui_resource"`
	DenyAppToolCall   bool `json:"deny_app_tool_call"`
	RequiresStepUp    bool `json:"requires_step_up"`
	ExcessiveAppCalls bool `json:"excessive_app_calls"`
}

// BuildUIInput constructs a UIInput from the available request context data.
// Parameters:
//   - enabled: whether MCP-UI is active (from gateway config)
//   - resourceURI: the ui:// URI being accessed (empty if not a resource read)
//   - contentHash: SHA-256 hash of resource content (empty if not verified)
//   - callOrigin: "model" or "app" (empty if unknown)
//   - appSessionToolCalls: number of app-driven tool calls in this session
//   - resourceRegistered: whether the resource is in the registry
//   - resourceHashVerified: whether the resource hash matches
func BuildUIInput(
	enabled bool,
	resourceURI string,
	contentHash string,
	callOrigin string,
	appSessionToolCalls int,
	resourceRegistered bool,
	resourceHashVerified bool,
) UIInput {
	return UIInput{
		Enabled:              enabled,
		ResourceURI:          resourceURI,
		ResourceContentHash:  contentHash,
		CallOrigin:           callOrigin,
		AppSessionToolCalls:  appSessionToolCalls,
		ResourceRegistered:   resourceRegistered,
		ResourceHashVerified: resourceHashVerified,
	}
}

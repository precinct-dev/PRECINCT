// Tool Registry Implementation - RFA-qq0.5, RFA-qq0.19, RFA-j2d.5
// Implements hash-based verification of MCP tools to detect poisoning attacks.
// Loads tool definitions from config/tool-registry.yaml and verifies SHA-256 hashes.
// RFA-qq0.19: Adds poisoning pattern detection using regex patterns to identify
// malicious instructions embedded in tool descriptions.
// RFA-j2d.5: Extends with UI resource registration and hash verification for ui:// content.
// Hash mismatches on UI resources are treated as rug-pull attacks (critical severity).
package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"
)

// MCPRequest represents a simplified MCP JSON-RPC request
type MCPRequest struct {
	Jsonrpc string                 `json:"jsonrpc"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params"`
	ID      interface{}            `json:"id"`
}

// VerifyResult represents the result of tool verification
type VerifyResult struct {
	Allowed    bool
	Reason     string
	Action     string // ActionAllow or ActionBlock
	AlertLevel string // AlertInfo, AlertWarning, AlertCritical
}

// Action constants for verification results
const (
	ActionAllow = "allow"
	ActionBlock = "block"
)

// Alert level constants
const (
	AlertInfo     = "info"
	AlertWarning  = "warning"
	AlertCritical = "critical"
)

// Poisoning patterns to detect (RFA-qq0.19)
// These patterns identify malicious instructions embedded in tool descriptions
var poisoningPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<IMPORTANT>.*?</IMPORTANT>`),
	regexp.MustCompile(`(?i)<SYSTEM>.*?</SYSTEM>`),
	regexp.MustCompile(`(?i)<!--.*?-->`),
	regexp.MustCompile(`(?i)before\s+using\s+this\s+tool.*?first`),
	regexp.MustCompile(`(?i)ignore\s+(previous|all|prior)\s+instructions`),
	regexp.MustCompile(`(?i)you\s+must\s+(always|first|never)`),
	regexp.MustCompile(`(?i)send.*?(email|http|webhook|upload).*?to`),
}

// mcpProtocolMethods lists MCP protocol-level methods that pass through the tool
// registry without verification. These are part of the MCP protocol itself (JSON-RPC
// method envelopes, discovery, lifecycle), not user-defined tools. Blocking them
// would break normal MCP operation. The "notifications/" prefix is handled separately
// via strings.HasPrefix since notification method names are open-ended.
// Fix for RFA-rqj: ToolRegistryVerify was treating these as tool names.
var mcpProtocolMethods = map[string]bool{
	"tools/list":             true,
	"tools/call":             true,
	"resources/read":         true,
	"resources/list":         true,
	"prompts/list":           true,
	"prompts/get":            true,
	"sampling/createMessage": true,
	"initialize":             true,
	"ping":                   true,
}

// ToolDefinition represents a tool from the registry config
type ToolDefinition struct {
	Name                string                 `yaml:"name"`
	Description         string                 `yaml:"description"`
	Hash                string                 `yaml:"hash"`
	InputSchema         map[string]interface{} `yaml:"input_schema"`
	AllowedDestinations []string               `yaml:"allowed_destinations"`
	AllowedPaths        []string               `yaml:"allowed_paths"`
	RiskLevel           string                 `yaml:"risk_level"`
	RequiresStepUp      bool                   `yaml:"requires_step_up"`
}

// UIResourceCSP represents the approved Content Security Policy declaration for a UI resource.
// This captures the CSP that was reviewed and approved during the onboarding workflow (Section 7.9.6).
type UIResourceCSP struct {
	DefaultSrc []string `json:"default_src" yaml:"default_src"`
	ScriptSrc  []string `json:"script_src" yaml:"script_src"`
	StyleSrc   []string `json:"style_src" yaml:"style_src"`
	ConnectSrc []string `json:"connect_src" yaml:"connect_src"`
	ImgSrc     []string `json:"img_src" yaml:"img_src"`
}

// UIPermissions represents the approved browser permissions for a UI resource.
// These are reviewed during onboarding and enforced by the gateway on every resource read.
type UIPermissions struct {
	Camera         bool `json:"camera" yaml:"camera"`
	Microphone     bool `json:"microphone" yaml:"microphone"`
	Geolocation    bool `json:"geolocation" yaml:"geolocation"`
	ClipboardWrite bool `json:"clipboard_write" yaml:"clipboard_write"`
}

// UIScanResult captures the static analysis results at approval time.
// Used for audit trail and to compare against future scans.
type UIScanResult struct {
	ScannedAt        time.Time `json:"scanned_at" yaml:"scanned_at"`
	DangerousPattern bool      `json:"dangerous_pattern" yaml:"dangerous_pattern"`
	ScriptCount      int       `json:"script_count" yaml:"script_count"`
	ExternalRefs     int       `json:"external_refs" yaml:"external_refs"`
}

// RegisteredUIResource represents a UI resource registered in the tool registry.
// Every ui:// resource must be registered with a content hash baseline. On each read,
// the gateway verifies the content hash matches the registered baseline.
// Hash mismatches are treated as rug-pull attacks (critical severity).
// Implements Reference Architecture Section 7.9.6.
type RegisteredUIResource struct {
	Server        string         `json:"server" yaml:"server"`
	ResourceURI   string         `json:"resource_uri" yaml:"resource_uri"` // e.g., "ui://dashboard/analytics.html"
	ContentHash   string         `json:"content_hash" yaml:"content_hash"` // SHA-256 of HTML content
	Version       string         `json:"version" yaml:"version"`
	ApprovedAt    time.Time      `json:"approved_at" yaml:"approved_at"`
	ApprovedBy    string         `json:"approved_by" yaml:"approved_by"`
	MaxSizeBytes  int64          `json:"max_size_bytes" yaml:"max_size_bytes"`
	DeclaredCSP   *UIResourceCSP `json:"declared_csp" yaml:"declared_csp"`     // Approved CSP declaration
	DeclaredPerms *UIPermissions `json:"declared_perms" yaml:"declared_perms"` // Approved permissions
	ScanResult    *UIScanResult  `json:"scan_result" yaml:"scan_result"`       // Static analysis at approval time
}

// uiResourceKey returns the map key for a UI resource: "server|resourceURI".
// This composite key ensures uniqueness across servers.
func uiResourceKey(server, resourceURI string) string {
	return server + "|" + resourceURI
}

// ToolRegistryConfig represents the tool registry configuration file
type ToolRegistryConfig struct {
	Tools       []ToolDefinition       `yaml:"tools"`
	UIResources []RegisteredUIResource `yaml:"ui_resources"`
}

// ToolRegistry manages tool verification with hash checking and UI resource verification.
// RFA-j2d.5: Extended with uiResources map for UI resource hash verification.
type ToolRegistry struct {
	tools       map[string]ToolDefinition       // tool_name -> definition
	uiResources map[string]RegisteredUIResource // "server|resourceURI" -> registration
}

// NewToolRegistry creates a new tool registry from a config file.
// The config file contains both tool definitions and UI resource registrations.
func NewToolRegistry(configPath string) (*ToolRegistry, error) {
	registry := &ToolRegistry{
		tools:       make(map[string]ToolDefinition),
		uiResources: make(map[string]RegisteredUIResource),
	}

	// Load configuration from file
	if configPath != "" {
		if err := registry.loadConfig(configPath); err != nil {
			return nil, fmt.Errorf("failed to load tool registry config: %w", err)
		}
	}

	return registry, nil
}

// loadConfig loads tool definitions and UI resource registrations from YAML config file.
// RFA-j2d.5: Extended to load ui_resources section alongside tools.
func (tr *ToolRegistry) loadConfig(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config ToolRegistryConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Load tools into map
	for _, tool := range config.Tools {
		tr.tools[tool.Name] = tool
	}

	// RFA-j2d.5: Load UI resources into map, keyed by "server|resourceURI"
	for _, res := range config.UIResources {
		key := uiResourceKey(res.Server, res.ResourceURI)
		tr.uiResources[key] = res
	}

	return nil
}

// VerifyTool checks if a tool is allowed and matches expected hash
// Returns (allowed, reason/hash)
func (tr *ToolRegistry) VerifyTool(toolName string, providedHash string) (bool, string) {
	toolDef, exists := tr.tools[toolName]
	if !exists {
		return false, "tool_not_found"
	}

	// Verify hash if provided
	if providedHash != "" && providedHash != toolDef.Hash {
		return false, "hash_mismatch"
	}

	return true, toolDef.Hash
}

// VerifyToolWithPoisoningCheck checks tool authorization, hash, and poisoning patterns (RFA-qq0.19)
// Returns VerifyResult with action and alert level
func (tr *ToolRegistry) VerifyToolWithPoisoningCheck(toolName string, providedHash string) VerifyResult {
	// Check if tool exists
	toolDef, exists := tr.tools[toolName]
	if !exists {
		return VerifyResult{
			Allowed:    false,
			Reason:     "tool_not_found",
			Action:     ActionBlock,
			AlertLevel: AlertWarning,
		}
	}

	// Check for poisoning patterns in description (RFA-qq0.19)
	if matchedPattern := containsPoisoningPattern(toolDef.Description); matchedPattern != "" {
		return VerifyResult{
			Allowed:    false,
			Reason:     fmt.Sprintf("poisoning_pattern_detected: %s", matchedPattern),
			Action:     ActionBlock,
			AlertLevel: AlertCritical,
		}
	}

	// Verify hash if provided
	if providedHash != "" && providedHash != toolDef.Hash {
		return VerifyResult{
			Allowed:    false,
			Reason:     "hash_mismatch",
			Action:     ActionBlock,
			AlertLevel: AlertWarning,
		}
	}

	return VerifyResult{
		Allowed:    true,
		Reason:     "verified",
		Action:     ActionAllow,
		AlertLevel: AlertInfo,
	}
}

// containsPoisoningPattern checks if text contains any known poisoning patterns (RFA-qq0.19)
// Returns the matched pattern name or empty string if no match
func containsPoisoningPattern(text string) string {
	patternNames := []string{
		"<IMPORTANT> tag",
		"<SYSTEM> tag",
		"HTML comment",
		"before using...first instruction",
		"ignore instructions command",
		"you must command",
		"send to external destination",
	}

	for i, pattern := range poisoningPatterns {
		if pattern.MatchString(text) {
			return patternNames[i]
		}
	}
	return ""
}

// GetToolDefinition returns the tool definition for a given tool name
func (tr *ToolRegistry) GetToolDefinition(toolName string) (ToolDefinition, bool) {
	toolDef, exists := tr.tools[toolName]
	return toolDef, exists
}

// GetUIResource returns the registered UI resource for a given server and resource URI.
// RFA-j2d.5: Used for lookup during verification and by downstream middleware.
func (tr *ToolRegistry) GetUIResource(server, resourceURI string) (RegisteredUIResource, bool) {
	key := uiResourceKey(server, resourceURI)
	res, exists := tr.uiResources[key]
	return res, exists
}

// UIResourceCount returns the number of registered UI resources.
// Useful for diagnostics and testing.
func (tr *ToolRegistry) UIResourceCount() int {
	return len(tr.uiResources)
}

// RegisterUIResource adds or updates a UI resource registration programmatically.
// RFA-j2d.6: Used for test injection and dynamic registration workflows.
func (tr *ToolRegistry) RegisterUIResource(res RegisteredUIResource) {
	key := uiResourceKey(res.Server, res.ResourceURI)
	tr.uiResources[key] = res
}

// VerifyUIResource checks if a UI resource is registered and its content hash matches.
// This implements Reference Architecture Section 7.9.6:
//   - Not registered: block with reason "ui resource not in registry"
//   - Hash mismatch: block with reason "ui resource content hash mismatch - possible rug pull"
//     (critical alert - rug-pull detection)
//   - Content exceeds max_size_bytes: block with reason "ui resource exceeds approved size limit"
//   - Otherwise: allow
//
// The content parameter is the raw HTML/resource content read from the MCP server.
// SHA-256 hash is computed over the content and compared against the registered baseline.
func (tr *ToolRegistry) VerifyUIResource(server, resourceURI string, content []byte) VerifyResult {
	key := uiResourceKey(server, resourceURI)
	registration, exists := tr.uiResources[key]

	// Check 1: Resource must be registered
	if !exists {
		return VerifyResult{
			Allowed:    false,
			Reason:     "ui resource not in registry",
			Action:     ActionBlock,
			AlertLevel: AlertWarning,
		}
	}

	// Check 2: Content size must not exceed registered max_size_bytes
	// Only enforced when max_size_bytes > 0 (0 means no limit)
	if registration.MaxSizeBytes > 0 && int64(len(content)) > registration.MaxSizeBytes {
		return VerifyResult{
			Allowed:    false,
			Reason:     fmt.Sprintf("ui resource exceeds approved size limit (size=%d, max=%d)", len(content), registration.MaxSizeBytes),
			Action:     ActionBlock,
			AlertLevel: AlertWarning,
		}
	}

	// Check 3: Compute SHA-256 hash of content and compare with registered hash
	hash := sha256.Sum256(content)
	computedHash := hex.EncodeToString(hash[:])

	if computedHash != registration.ContentHash {
		return VerifyResult{
			Allowed:    false,
			Reason:     "ui resource content hash mismatch - possible rug pull",
			Action:     ActionBlock,
			AlertLevel: AlertCritical,
		}
	}

	// All checks passed
	return VerifyResult{
		Allowed:    true,
		Reason:     "ui resource verified",
		Action:     ActionAllow,
		AlertLevel: AlertInfo,
	}
}

// ComputeUIResourceHash computes the SHA-256 hash of UI resource content.
// This is the canonical hash computation for UI resource registration.
// Used during the onboarding workflow (Section 7.9.6 Step 4) to compute
// the baseline hash that gets stored in the registry.
func ComputeUIResourceHash(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

// ComputeHash computes SHA-256 hash of tool description + input schema
// This is the canonical hash computation for tool verification
func ComputeHash(description string, inputSchema map[string]interface{}) string {
	// Serialize input schema to canonical JSON (sorted keys, no whitespace)
	schemaJSON, err := json.Marshal(inputSchema)
	if err != nil {
		// If schema can't be marshaled, use empty string
		schemaJSON = []byte("{}")
	}

	// Compute hash over description + schema
	content := description + string(schemaJSON)
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// ToolRegistryVerify middleware verifies tool authorization with hash checking and poisoning detection (RFA-qq0.19)
func ToolRegistryVerify(next http.Handler, registry *ToolRegistry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.2: Create OTel span for step 5
		ctx, span := tracer.Start(r.Context(), "gateway.tool_registry_verify",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 5),
				attribute.String("mcp.gateway.middleware", "tool_registry_verify"),
			),
		)
		defer span.End()

		// Get request body from context
		body := GetRequestBody(ctx)
		if len(body) == 0 {
			// No body to verify, pass through
			span.SetAttributes(
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "no body"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Parse MCP request to extract tool name
		var mcpReq MCPRequest
		if err := json.Unmarshal(body, &mcpReq); err != nil {
			// Not a valid MCP request, pass through
			span.SetAttributes(
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "not MCP request"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Extract tool name from method or params
		toolName := mcpReq.Method
		if toolName == "" {
			// Try to get from params
			if tn, ok := mcpReq.Params["tool"]; ok {
				if toolNameStr, ok := tn.(string); ok {
					toolName = toolNameStr
				}
			}
		}

		// RFA-rqj: MCP protocol methods pass through without tool registry verification.
		// These are part of the MCP protocol itself, not user-defined tools.
		if mcpProtocolMethods[toolName] || strings.HasPrefix(toolName, "notifications/") {
			span.SetAttributes(
				attribute.String("tool_name", toolName),
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "protocol method passthrough"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Verify tool if we extracted a name
		toolHashVerified := false
		if toolName != "" {
			span.SetAttributes(attribute.String("tool_name", toolName))

			// Extract provided hash from params if present
			providedHash := ""
			if hash, ok := mcpReq.Params["tool_hash"]; ok {
				if hashStr, ok := hash.(string); ok {
					providedHash = hashStr
				}
			}

			// Use new verification with poisoning check (RFA-qq0.19)
			result := registry.VerifyToolWithPoisoningCheck(toolName, providedHash)
			if !result.Allowed {
				// Log critical alert for poisoning detection
				if result.AlertLevel == AlertCritical {
					// TODO: Emit audit event with critical alert level
					// For now, log to stdout (audit logging is middleware step 4)
					fmt.Printf("[CRITICAL] Poisoning pattern detected in tool %s: %s\n", toolName, result.Reason)
				}
				span.SetAttributes(
					attribute.Bool("hash_verified", false),
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", result.Reason),
				)
				http.Error(w, fmt.Sprintf("Tool not authorized: %s", result.Reason), http.StatusForbidden)
				return
			}
			toolHashVerified = true
			span.SetAttributes(
				attribute.Bool("hash_verified", true),
				attribute.String("registry_digest", "verified"),
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "tool verified"),
			)
		}

		// Store verification status in context for audit (RFA-qq0.13)
		ctx = WithToolHashVerified(ctx, toolHashVerified)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

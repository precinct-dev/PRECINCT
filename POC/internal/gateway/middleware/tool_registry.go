// Tool Registry Implementation - RFA-qq0.5, RFA-qq0.19, RFA-j2d.5, RFA-dh9, RFA-lo1.4
// Implements hash-based verification of MCP tools to detect poisoning attacks.
// Loads tool definitions from config/tool-registry.yaml and verifies SHA-256 hashes.
// RFA-qq0.19: Adds poisoning pattern detection using regex patterns to identify
// malicious instructions embedded in tool descriptions.
// RFA-j2d.5: Extends with UI resource registration and hash verification for ui:// content.
// Hash mismatches on UI resources are treated as rug-pull attacks (critical severity).
// RFA-dh9: Adds fsnotify-based hot-reload. Watch() starts a file watcher that
// automatically reloads the registry YAML on file change without gateway restart.
// RFA-lo1.4: Adds cosign-blob signature verification for registry hot-reload.
// When a public key is configured (TOOL_REGISTRY_PUBLIC_KEY), registry updates
// must have a companion .sig file with a valid Ed25519 signature. Without a key,
// reload works in dev mode with warning logs.
package middleware

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
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
	// RequiredScope defines the SPIKE token scope required to access this tool.
	// Format: "location.operation.destination" (e.g., "tools.docker.read").
	// When empty, scope validation is permissive (any scope accepted).
	// RFA-0gr: Replaces hardcoded scope in TokenSubstitution middleware.
	RequiredScope string `yaml:"required_scope"`
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
// RFA-dh9: Protected by sync.RWMutex for concurrent-safe reads during hot-reload.
// RFA-lo1.4: Added publicKey for cosign-blob attestation on hot-reload.
type ToolRegistry struct {
	mu          sync.RWMutex
	tools       map[string]ToolDefinition       // tool_name -> definition
	uiResources map[string]RegisteredUIResource // "server|resourceURI" -> registration
	configPath  string                          // path to YAML config file (for Watch)
	publicKey   ed25519.PublicKey               // RFA-lo1.4: Ed25519 public key for signature verification (nil = dev mode)
}

// NewToolRegistry creates a new tool registry from a config file.
// The config file contains both tool definitions and UI resource registrations.
func NewToolRegistry(configPath string) (*ToolRegistry, error) {
	registry := &ToolRegistry{
		tools:       make(map[string]ToolDefinition),
		uiResources: make(map[string]RegisteredUIResource),
		configPath:  configPath,
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
// RFA-dh9: Now performs atomic swap under write lock for hot-reload safety.
// Caller must NOT hold tr.mu when calling this method.
func (tr *ToolRegistry) loadConfig(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config ToolRegistryConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Build new maps outside the lock
	newTools := make(map[string]ToolDefinition, len(config.Tools))
	for _, tool := range config.Tools {
		newTools[tool.Name] = tool
	}
	newUIResources := make(map[string]RegisteredUIResource, len(config.UIResources))
	for _, res := range config.UIResources {
		key := uiResourceKey(res.Server, res.ResourceURI)
		newUIResources[key] = res
	}

	// Atomic swap under write lock
	tr.mu.Lock()
	tr.tools = newTools
	tr.uiResources = newUIResources
	tr.mu.Unlock()

	return nil
}

// SetPublicKey configures an Ed25519 public key for cosign-blob signature verification.
// The pemData should be PEM-encoded (PKCS8 or raw Ed25519 public key).
// When a public key is set, Watch() will require companion .sig files for every
// registry reload. Without a public key, Watch() accepts all updates (dev mode).
//
// RFA-lo1.4: Called from gateway.New() with the value of TOOL_REGISTRY_PUBLIC_KEY.
func (tr *ToolRegistry) SetPublicKey(pemData []byte) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from public key data")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not Ed25519 (got %T)", pub)
	}

	tr.publicKey = edPub
	return nil
}

// HasPublicKey returns true if a public key is configured for signature verification.
func (tr *ToolRegistry) HasPublicKey() bool {
	return tr.publicKey != nil
}

// verifySignature verifies an Ed25519 signature over data.
// The sig parameter should be the base64-decoded raw signature bytes.
// Returns nil if signature is valid, error otherwise.
//
// RFA-lo1.4: Used by Watch() to verify registry file updates.
func (tr *ToolRegistry) verifySignature(data, sig []byte) error {
	if tr.publicKey == nil {
		return fmt.Errorf("no public key configured for signature verification")
	}

	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	if !ed25519.Verify(tr.publicKey, data, sig) {
		return fmt.Errorf("signature verification failed: invalid signature")
	}

	return nil
}

// readAndVerifySigFile reads the companion .sig file for a registry YAML file,
// base64-decodes it, and verifies the signature against the YAML data.
// Returns nil if the signature is valid, error otherwise.
//
// The .sig file is expected to contain a base64-encoded Ed25519 signature,
// matching the format produced by `cosign sign-blob --key <key> <file>`.
func (tr *ToolRegistry) readAndVerifySigFile(yamlData []byte, configPath string) error {
	sigPath := configPath + ".sig"
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("failed to read signature file %s: %w", sigPath, err)
	}

	// Trim whitespace (cosign output may have trailing newline)
	sigB64 := strings.TrimSpace(string(sigData))
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("failed to base64-decode signature from %s: %w", sigPath, err)
	}

	return tr.verifySignature(yamlData, sig)
}

// ToolCount returns the number of registered tools. Useful for diagnostics and testing.
func (tr *ToolRegistry) ToolCount() int {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	return len(tr.tools)
}

// Watch starts an fsnotify watcher on the registry YAML file. When the file
// changes on disk, the registry is automatically reloaded (atomic swap via
// sync.RWMutex). Returns a stop function that must be called for graceful
// shutdown. If configPath is empty, Watch is a no-op and returns a no-op stop.
//
// RFA-dh9: Walking skeleton for registry hot-reload.
// RFA-lo1.4: When a public key is configured (via SetPublicKey), Watch requires
// a companion .sig file for every reload. The .sig file must contain a valid
// base64-encoded Ed25519 signature over the YAML content. If verification fails,
// the old registry is kept and a critical audit event is emitted. When no public
// key is configured (dev mode), all updates are accepted with a warning.
//
// Debounce: editors often fire multiple fsnotify events for a single save
// (write + chmod, rename + create). We debounce by waiting 100ms after the
// last event before reloading.
func (tr *ToolRegistry) Watch() (stop func(), err error) {
	noop := func() {}

	if tr.configPath == "" {
		return noop, nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return noop, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	// Watch the directory containing the config file rather than the file itself.
	// Many editors (vim, emacs, VS Code) use atomic save (rename + create) which
	// removes the original inode. Watching the directory ensures we catch these
	// rename-based writes. We filter events by filename inside the loop.
	configDir := filepath.Dir(tr.configPath)
	configBase := filepath.Base(tr.configPath)

	if err := watcher.Add(configDir); err != nil {
		_ = watcher.Close()
		return noop, fmt.Errorf("failed to watch directory %s: %w", configDir, err)
	}

	// RFA-lo1.4: Log attestation mode at startup
	if tr.publicKey != nil {
		log.Printf("[tool-registry] watching %s for changes (attestation: ENABLED)", tr.configPath)
	} else {
		log.Printf("[tool-registry] WARNING: Registry hot-reload is enabled WITHOUT attestation. Unsigned updates will be accepted.")
		log.Printf("[tool-registry] watching %s for changes (attestation: DISABLED)", tr.configPath)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var debounceTimer *time.Timer
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Filter: only react to the config file itself
				if filepath.Base(event.Name) != configBase {
					continue
				}
				// React to write and create events (create covers atomic-save via rename)
				if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
					continue
				}
				// Debounce: reset timer on each event, reload after 100ms of quiet
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(100*time.Millisecond, func() {
					log.Printf("[tool-registry] file change detected: %s (op=%s), reloading", event.Name, event.Op)
					tr.reloadWithAttestation()
				})
			case watchErr, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("[tool-registry] watcher error: %v", watchErr)
			}
		}
	}()

	stopFn := func() {
		_ = watcher.Close()
		<-done // wait for goroutine to exit
	}

	return stopFn, nil
}

// reloadWithAttestation performs the hot-reload logic with optional signature
// verification. When a public key is configured, the companion .sig file is
// checked before accepting the new registry data. On verification failure,
// the old registry is kept and a critical audit event is logged.
//
// RFA-lo1.4: Central reload logic called by Watch() on file change.
func (tr *ToolRegistry) reloadWithAttestation() {
	// Read the YAML data first (we need it for both loading and sig verification)
	yamlData, err := os.ReadFile(tr.configPath)
	if err != nil {
		log.Printf("[tool-registry] reload failed, keeping old registry: failed to read config file: %v", err)
		return
	}

	if tr.publicKey != nil {
		// Attestation mode: verify signature before accepting update
		if sigErr := tr.readAndVerifySigFile(yamlData, tr.configPath); sigErr != nil {
			log.Printf("[CRITICAL] [tool-registry] signature verification failed, keeping old registry: %v", sigErr)
			log.Printf("[AUDIT] registry_reload_rejected: signature_verification_failed path=%s", tr.configPath)
			return
		}
		log.Printf("[tool-registry] signature verification passed for %s", tr.configPath)
	} else {
		// Dev mode: accept without verification but warn
		log.Printf("[tool-registry] WARNING: accepting unsigned registry update (no public key configured)")
	}

	// Parse and atomically swap
	var config ToolRegistryConfig
	if err := yaml.Unmarshal(yamlData, &config); err != nil {
		log.Printf("[tool-registry] reload failed, keeping old registry: failed to parse config file: %v", err)
		return
	}

	newTools := make(map[string]ToolDefinition, len(config.Tools))
	for _, tool := range config.Tools {
		newTools[tool.Name] = tool
	}
	newUIResources := make(map[string]RegisteredUIResource, len(config.UIResources))
	for _, res := range config.UIResources {
		key := uiResourceKey(res.Server, res.ResourceURI)
		newUIResources[key] = res
	}

	tr.mu.Lock()
	tr.tools = newTools
	tr.uiResources = newUIResources
	tr.mu.Unlock()

	tr.mu.RLock()
	toolCount := len(tr.tools)
	uiCount := len(tr.uiResources)
	tr.mu.RUnlock()
	log.Printf("[tool-registry] reload successful: %d tools, %d ui_resources", toolCount, uiCount)
}

// VerifyTool checks if a tool is allowed and matches expected hash
// Returns (allowed, reason/hash)
func (tr *ToolRegistry) VerifyTool(toolName string, providedHash string) (bool, string) {
	tr.mu.RLock()
	toolDef, exists := tr.tools[toolName]
	tr.mu.RUnlock()
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
	tr.mu.RLock()
	toolDef, exists := tr.tools[toolName]
	tr.mu.RUnlock()
	// Check if tool exists
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
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	toolDef, exists := tr.tools[toolName]
	return toolDef, exists
}

// ScopeResolver resolves the required SPIKE token scope for a given tool name.
// RFA-0gr: Replaces hardcoded scope validation in TokenSubstitution middleware.
type ScopeResolver interface {
	// ResolveScope returns the required scope components (location, operation, destination)
	// for the given tool name. If the tool is not found or has no required scope,
	// returns empty strings and found=false. When found=false, scope validation
	// should be permissive (allow any scope, matching the behavior for tokens
	// without a scope field).
	ResolveScope(toolName string) (location, operation, destination string, found bool)
}

// ToolRegistryScopeResolver resolves scope from the tool registry's RequiredScope field.
// RFA-0gr: Backed by ToolRegistry for dynamic scope lookup.
type ToolRegistryScopeResolver struct {
	registry *ToolRegistry
}

// NewToolRegistryScopeResolver creates a ScopeResolver backed by the tool registry.
func NewToolRegistryScopeResolver(registry *ToolRegistry) *ToolRegistryScopeResolver {
	return &ToolRegistryScopeResolver{registry: registry}
}

// ResolveScope looks up the required scope for a tool from the registry.
// The RequiredScope field uses "location.operation.destination" format.
// Returns the three components and found=true if the tool has a required scope.
// Returns empty strings and found=false if the tool is not registered or has
// no required scope defined.
func (r *ToolRegistryScopeResolver) ResolveScope(toolName string) (location, operation, destination string, found bool) {
	toolDef, exists := r.registry.GetToolDefinition(toolName)
	if !exists || toolDef.RequiredScope == "" {
		return "", "", "", false
	}

	parts := strings.SplitN(toolDef.RequiredScope, ".", 3)
	if len(parts) != 3 {
		// Malformed scope in registry -- treat as not found rather than failing
		return "", "", "", false
	}

	return parts[0], parts[1], parts[2], true
}

// GetUIResource returns the registered UI resource for a given server and resource URI.
// RFA-j2d.5: Used for lookup during verification and by downstream middleware.
func (tr *ToolRegistry) GetUIResource(server, resourceURI string) (RegisteredUIResource, bool) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	key := uiResourceKey(server, resourceURI)
	res, exists := tr.uiResources[key]
	return res, exists
}

// UIResourceCount returns the number of registered UI resources.
// Useful for diagnostics and testing.
func (tr *ToolRegistry) UIResourceCount() int {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	return len(tr.uiResources)
}

// RegisterUIResource adds or updates a UI resource registration programmatically.
// RFA-j2d.6: Used for test injection and dynamic registration workflows.
func (tr *ToolRegistry) RegisterUIResource(res RegisteredUIResource) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
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
	tr.mu.RLock()
	key := uiResourceKey(server, resourceURI)
	registration, exists := tr.uiResources[key]
	tr.mu.RUnlock()

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

		parsed, err := ParseMCPRequestBody(body)
		if err != nil {
			// Not a valid MCP request, pass through
			span.SetAttributes(
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "not MCP request"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		rpcMethod := parsed.RPCMethod

		// RFA-rqj: MCP protocol methods pass through without tool registry verification.
		// These are part of the MCP protocol itself, not user-defined tools.
		//
		// NOTE: tools/call is a protocol method envelope but MUST NOT bypass tool
		// verification. We verify the effective tool name inside tools/call.
		if !parsed.IsToolsCall() && (mcpProtocolMethods[rpcMethod] || strings.HasPrefix(rpcMethod, "notifications/")) {
			span.SetAttributes(
				attribute.String("tool_name", rpcMethod),
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "protocol method passthrough"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		toolName, toolErr := parsed.EffectiveToolName()
		if parsed.IsToolsCall() && toolErr != nil {
			span.SetAttributes(
				attribute.Bool("hash_verified", false),
				attribute.String("mcp.result", "denied"),
				attribute.String("mcp.reason", "invalid tools/call"),
			)
			WriteGatewayError(w, r.WithContext(ctx), http.StatusBadRequest, GatewayError{
				Code:           ErrMCPInvalidRequest,
				Message:        fmt.Sprintf("Invalid tools/call request: %v", toolErr),
				Middleware:     "tool_registry_verify",
				MiddlewareStep: 5,
				Remediation:    "Use MCP spec tools/call with params.name and params.arguments.",
			})
			return
		}

		// Verify tool if we extracted a name
		toolHashVerified := false
		if toolName != "" {
			span.SetAttributes(attribute.String("tool_name", toolName))

			// Extract provided hash from params if present
			providedHash := ""
			if hash, ok := parsed.Params["tool_hash"]; ok {
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
				// Map tool registry reasons to specific error codes
				errCode := ErrRegistryToolUnknown
				if strings.Contains(result.Reason, "hash_mismatch") {
					errCode = ErrRegistryHashMismatch
				}
				WriteGatewayError(w, r.WithContext(ctx), http.StatusForbidden, GatewayError{
					Code:           errCode,
					Message:        fmt.Sprintf("Tool not authorized: %s", result.Reason),
					Middleware:     "tool_registry_verify",
					MiddlewareStep: 5,
					Details:        map[string]any{"tool": toolName, "reason": result.Reason, "alert_level": result.AlertLevel},
					Remediation:    "Verify the tool is registered and its hash matches the registry.",
				})
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

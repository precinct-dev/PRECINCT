package middleware

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"gopkg.in/yaml.v3"
)

// OPAEngineConfig holds runtime configuration injected into OPA data store.
// These values are accessible in Rego policies via data.config.<key>.
// PortRouteAuth mirrors gateway.PortRouteAuth for OPA data injection.
// It is intentionally a separate type so the middleware package does not
// import the gateway package (which would create a cycle).
type PortRouteAuth struct {
	Path       string   `json:"path"`
	PathPrefix string   `json:"path_prefix,omitempty"`
	Methods    []string `json:"methods"`
	AuthModel  string   `json:"auth_model"`
}

type OPAEngineConfig struct {
	// AllowedBasePath is the base directory for path-based access control.
	// Injected as data.config.allowed_base_path in OPA policies.
	// If empty, the policy falls back to its default ("/" -- fail-open for
	// path checks; SPIFFE and tool authorization still enforce access control).
	AllowedBasePath string
	// PolicyReloadPublicKeyPEM enables Ed25519 companion-signature verification
	// for .rego/.yaml reloads when set. Empty keeps backward-compatible dev mode.
	PolicyReloadPublicKeyPEM []byte
	// PortRouteAuthorizations are route authorization rules contributed by
	// registered port adapters. Injected as data.port_route_authorizations
	// in the OPA data store. The core policy uses these to grant
	// destination_allowed for port-claimed routes.
	PortRouteAuthorizations []PortRouteAuth
}

// OPAEngine handles embedded OPA policy evaluation
type OPAEngine struct {
	policyDir             string
	runtimeCfg            OPAEngineConfig
	query                 *rego.PreparedEvalQuery
	contextQuery          *rego.PreparedEvalQuery          // RFA-xwc: query for mcp.context policy
	uiPolicyQueries       *uiPolicyPreparedQueries         // RFA-j2d.7: queries for mcp.ui.policy rules
	dataSourcePolicyQuery *dataSourcePolicyPreparedQueries // OC-4zrf: queries for precinct.data_source policy
	policyCount           int
	publicKey             ed25519.PublicKey
	mu                    sync.RWMutex
	watcher               *fsnotify.Watcher
	stopChan              chan struct{}
}

// dataSourcePolicyPreparedQueries holds compiled queries for data source policy rules.
// OC-4zrf: Each query evaluates a single rule in the precinct.data_source package.
type dataSourcePolicyPreparedQueries struct {
	allow rego.PreparedEvalQuery
	deny  rego.PreparedEvalQuery
}

// OPAEngineReloadResult captures metadata from a policy reload operation.
type OPAEngineReloadResult struct {
	PolicyCount         int
	AttestationVerified bool
	AttestationMode     string
	Rejected            bool
	RejectionReason     string
}

// uiPolicyPreparedQueries holds the compiled queries for each rule in the
// mcp.ui.policy Rego package. Each query evaluates a single boolean rule.
type uiPolicyPreparedQueries struct {
	denyUIResource    rego.PreparedEvalQuery
	denyAppToolCall   rego.PreparedEvalQuery
	requiresStepUp    rego.PreparedEvalQuery
	excessiveAppCalls rego.PreparedEvalQuery
}

// NewOPAEngine creates a new embedded OPA engine.
// cfg provides runtime configuration injected into the OPA data store.
// Pass an empty OPAEngineConfig{} for backward-compatible behavior (policy defaults apply).
func NewOPAEngine(policyDir string, cfg ...OPAEngineConfig) (*OPAEngine, error) {
	var runtimeCfg OPAEngineConfig
	if len(cfg) > 0 {
		runtimeCfg = cfg[0]
	}
	engine := &OPAEngine{
		policyDir:  policyDir,
		runtimeCfg: runtimeCfg,
		stopChan:   make(chan struct{}),
	}

	if len(runtimeCfg.PolicyReloadPublicKeyPEM) > 0 {
		if err := engine.SetPublicKey(runtimeCfg.PolicyReloadPublicKeyPEM); err != nil {
			return nil, fmt.Errorf("failed to configure OPA reload attestation: %w", err)
		}
	}

	// Load and compile policies
	if err := engine.loadPolicies(); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	// Start file watcher for hot-reload
	if err := engine.startWatcher(); err != nil {
		return nil, fmt.Errorf("failed to start policy watcher: %w", err)
	}

	return engine, nil
}

// SetPublicKey configures an Ed25519 public key for OPA policy reload attestation.
// The PEM data must be a PKIX-encoded Ed25519 public key.
func (e *OPAEngine) SetPublicKey(pemData []byte) error {
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

	e.mu.Lock()
	e.publicKey = edPub
	e.mu.Unlock()
	return nil
}

// HasPublicKey returns true when reload attestation is enabled.
func (e *OPAEngine) HasPublicKey() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.publicKey != nil
}

func (e *OPAEngine) attestationMode() string {
	if e.HasPublicKey() {
		return "ed25519"
	}
	return "disabled"
}

func (e *OPAEngine) verifySignature(data, sig []byte) error {
	e.mu.RLock()
	publicKey := e.publicKey
	e.mu.RUnlock()

	if publicKey == nil {
		return fmt.Errorf("no public key configured for signature verification")
	}

	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	if !ed25519.Verify(publicKey, data, sig) {
		return fmt.Errorf("signature verification failed: invalid signature")
	}

	return nil
}

func (e *OPAEngine) readAndVerifySigFile(fileData []byte, path string) error {
	sigPath := path + ".sig"
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("failed to read signature file %s: %w", sigPath, err)
	}

	sigB64 := strings.TrimSpace(string(sigData))
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("failed to base64-decode signature from %s: %w", sigPath, err)
	}

	return e.verifySignature(fileData, sig)
}

func (e *OPAEngine) attestedPolicyFiles() ([]string, error) {
	files, err := os.ReadDir(e.policyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy directory: %w", err)
	}

	paths := make([]string, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		switch filepath.Ext(file.Name()) {
		case ".rego", ".yaml", ".yml":
			paths = append(paths, filepath.Join(e.policyDir, file.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func (e *OPAEngine) verifyPolicyAttestation() error {
	if !e.HasPublicKey() {
		return nil
	}

	paths, err := e.attestedPolicyFiles()
	if err != nil {
		return err
	}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read policy file %s: %w", filepath.Base(path), err)
		}
		if err := e.readAndVerifySigFile(content, path); err != nil {
			return fmt.Errorf("policy attestation failed for %s: %w", filepath.Base(path), err)
		}
	}
	return nil
}

// loadPolicies loads all .rego and .yaml files from policy directory and compiles them
func (e *OPAEngine) loadPolicies() error {
	// Read all policy files
	files, err := os.ReadDir(e.policyDir)
	if err != nil {
		return fmt.Errorf("failed to read policy directory: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no policy files found in %s", e.policyDir)
	}

	// Build rego options
	var regoOpts []func(*rego.Rego)

	// Add policy files (.rego)
	hasPolicyFile := false
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if filepath.Ext(file.Name()) == ".rego" {
			policyPath := filepath.Join(e.policyDir, file.Name())
			content, err := os.ReadFile(policyPath)
			if err != nil {
				return fmt.Errorf("failed to read policy file %s: %w", file.Name(), err)
			}
			regoOpts = append(regoOpts, rego.Module(file.Name(), string(content)))
			hasPolicyFile = true
		}
	}

	if !hasPolicyFile {
		return fmt.Errorf("no .rego policy files found in %s", e.policyDir)
	}

	// Create in-memory store for data files
	ctx := context.Background()
	dataStore := inmem.New()

	// Load data files (.yaml, .json) into the store
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		ext := filepath.Ext(file.Name())
		if ext == ".yaml" || ext == ".yml" {
			dataPath := filepath.Join(e.policyDir, file.Name())
			content, err := os.ReadFile(dataPath)
			if err != nil {
				slog.Warn("failed to read data file", "file", file.Name(), "error", err)
				continue
			}

			var data map[string]interface{}
			if err := yaml.Unmarshal(content, &data); err != nil {
				slog.Warn("failed to parse YAML data file", "file", file.Name(), "error", err)
				continue
			}

			// Write each top-level key from YAML as a separate data entry
			// This makes data.tool_grants accessible if YAML has "tool_grants: ..." at top level
			for key, value := range data {
				path := storage.MustParsePath("/" + key)
				if err := storage.WriteOne(ctx, dataStore, storage.AddOp, path, value); err != nil {
					slog.Warn("failed to write data to store", "key", key, "error", err)
				}
			}
		}
	}

	// Inject runtime config into the data store as data.config.*
	// This makes values available to Rego policies via data.config.<key>.
	// RFA-2jl: allowed_base_path replaces hardcoded path in mcp_policy.rego.
	if e.runtimeCfg.AllowedBasePath != "" {
		configData := map[string]interface{}{
			"allowed_base_path": e.runtimeCfg.AllowedBasePath,
		}
		configPath := storage.MustParsePath("/config")
		if err := storage.WriteOne(ctx, dataStore, storage.AddOp, configPath, configData); err != nil {
			return fmt.Errorf("failed to write runtime config to OPA data store: %w", err)
		}
	}

	// Inject port route authorizations as data.port_route_authorizations.
	// Port adapters declare their routes; the core policy uses this data
	// to grant destination_allowed without hardcoding port-specific paths.
	if len(e.runtimeCfg.PortRouteAuthorizations) > 0 {
		// Convert to []interface{} for OPA data store compatibility.
		routes := make([]interface{}, len(e.runtimeCfg.PortRouteAuthorizations))
		for i, r := range e.runtimeCfg.PortRouteAuthorizations {
			entry := map[string]interface{}{
				"methods":    toInterfaceSlice(r.Methods),
				"auth_model": r.AuthModel,
			}
			if r.Path != "" {
				entry["path"] = r.Path
			}
			if r.PathPrefix != "" {
				entry["path_prefix"] = r.PathPrefix
			}
			routes[i] = entry
		}
		routesPath := storage.MustParsePath("/port_route_authorizations")
		if err := storage.WriteOne(ctx, dataStore, storage.AddOp, routesPath, routes); err != nil {
			return fmt.Errorf("failed to write port route authorizations to OPA data store: %w", err)
		}
	}

	// Add store to rego options
	regoOpts = append(regoOpts, rego.Store(dataStore))

	// Copy base options to avoid slice aliasing issues when appending query paths
	baseOpts := make([]func(*rego.Rego), len(regoOpts))
	copy(baseOpts, regoOpts)

	// Set query path: /mcp/allow (matches our policy package structure)
	mainOpts := append(baseOpts, rego.Query("data.mcp.allow"))

	// Compile main MCP policy
	r := rego.New(mainOpts...)

	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to compile policy: %w", err)
	}

	// RFA-xwc: Compile context injection policy (mcp.context.allow_context)
	// This is step 7 of the mandatory validation pipeline (Section 10.15.1)
	contextOpts := append(regoOpts, rego.Query("data.mcp.context.allow_context"))
	contextR := rego.New(contextOpts...)

	var contextQueryPtr *rego.PreparedEvalQuery
	contextPrepared, err := contextR.PrepareForEval(ctx)
	if err != nil {
		// Context policy is optional -- log warning but do not fail startup.
		// Fail-closed: if context policy cannot compile, EvaluateContextPolicy
		// will deny all context injection requests via the nil-query check.
		slog.Warn("failed to compile context policy, context injection will be denied", "error", err)
	} else {
		contextQueryPtr = &contextPrepared
	}

	// RFA-j2d.7: Compile mcp.ui.policy rules (deny_ui_resource, deny_app_tool_call,
	// requires_step_up, excessive_app_calls). UI policy is optional -- if the
	// policy file is not present, EvaluateUIPolicy returns a safe default (all false).
	var uiQueries *uiPolicyPreparedQueries
	uiRuleNames := []struct {
		name  string
		query string
	}{
		{"deny_ui_resource", "data.mcp.ui.policy.deny_ui_resource"},
		{"deny_app_tool_call", "data.mcp.ui.policy.deny_app_tool_call"},
		{"requires_step_up", "data.mcp.ui.policy.requires_step_up"},
		{"excessive_app_calls", "data.mcp.ui.policy.excessive_app_calls"},
	}

	compiledUIQueries := make([]rego.PreparedEvalQuery, len(uiRuleNames))
	uiCompileOK := true
	for i, rule := range uiRuleNames {
		ruleOpts := append(regoOpts, rego.Query(rule.query))
		r := rego.New(ruleOpts...)
		p, compileErr := r.PrepareForEval(ctx)
		if compileErr != nil {
			slog.Warn("failed to compile UI policy rule, using defaults", "rule", rule.name, "error", compileErr)
			uiCompileOK = false
			break
		}
		compiledUIQueries[i] = p
	}

	if uiCompileOK {
		uiQueries = &uiPolicyPreparedQueries{
			denyUIResource:    compiledUIQueries[0],
			denyAppToolCall:   compiledUIQueries[1],
			requiresStepUp:    compiledUIQueries[2],
			excessiveAppCalls: compiledUIQueries[3],
		}
	}

	// OC-4zrf: Compile data source policy (precinct.data_source allow/deny rules).
	// Data source policy is optional -- if the policy file is not present,
	// EvaluateDataSourcePolicy returns a safe default (deny all).
	var dsQueries *dataSourcePolicyPreparedQueries
	dsRules := []struct {
		name  string
		query string
	}{
		{"allow", "data.precinct.data_source.allow"},
		{"deny", "data.precinct.data_source.deny"},
	}
	compiledDSQueries := make([]rego.PreparedEvalQuery, len(dsRules))
	dsCompileOK := true
	for i, rule := range dsRules {
		ruleOpts := append(regoOpts, rego.Query(rule.query))
		r := rego.New(ruleOpts...)
		p, compileErr := r.PrepareForEval(ctx)
		if compileErr != nil {
			slog.Warn("failed to compile data source policy rule, using defaults", "rule", rule.name, "error", compileErr)
			dsCompileOK = false
			break
		}
		compiledDSQueries[i] = p
	}
	if dsCompileOK {
		dsQueries = &dataSourcePolicyPreparedQueries{
			allow: compiledDSQueries[0],
			deny:  compiledDSQueries[1],
		}
	}

	// Atomically update queries
	e.mu.Lock()
	e.query = &prepared
	e.contextQuery = contextQueryPtr
	e.uiPolicyQueries = uiQueries
	e.dataSourcePolicyQuery = dsQueries
	e.policyCount = 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if filepath.Ext(file.Name()) == ".rego" {
			e.policyCount++
		}
	}
	e.mu.Unlock()

	slog.Info("OPA policies loaded successfully", "policy_dir", e.policyDir)
	return nil
}

// RegisterPortRouteAuthorizations adds port route authorizations to the engine config
// and reloads policies so they appear as data.port_route_authorizations in OPA.
// Call this after all port adapters have been registered.
func (e *OPAEngine) RegisterPortRouteAuthorizations(routes []PortRouteAuth) error {
	e.runtimeCfg.PortRouteAuthorizations = append(e.runtimeCfg.PortRouteAuthorizations, routes...)
	return e.loadPolicies()
}

// PolicyCount returns the number of compiled .rego policy files in the current engine state.
func (e *OPAEngine) PolicyCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policyCount
}

// Reload performs a policy reload from disk and returns summary metadata.
func (e *OPAEngine) Reload() (OPAEngineReloadResult, error) {
	result := OPAEngineReloadResult{
		AttestationMode: e.attestationMode(),
	}

	if e.HasPublicKey() {
		if err := e.verifyPolicyAttestation(); err != nil {
			result.Rejected = true
			result.RejectionReason = err.Error()
			return result, err
		}
		result.AttestationVerified = true
	}

	if err := e.loadPolicies(); err != nil {
		return result, err
	}
	result.PolicyCount = e.PolicyCount()
	return result, nil
}

// Evaluate evaluates OPA policy with given input
func (e *OPAEngine) Evaluate(input OPAInput) (bool, string, error) {
	e.mu.RLock()
	query := e.query
	e.mu.RUnlock()

	if query == nil {
		// Fail closed if no policy loaded
		return false, "opa_not_initialized", nil
	}

	ctx := context.Background()
	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		// Fail closed on evaluation error
		slog.Error("OPA evaluation error", "error", err)
		return false, "opa_evaluation_error", nil
	}

	// Parse result
	if len(results) == 0 {
		// No results = undefined = deny
		return false, "opa_undefined", nil
	}

	result := results[0]
	if len(result.Expressions) == 0 {
		return false, "opa_no_expressions", nil
	}

	// Handle result - can be bool or struct with allow field
	allow := false
	reason := ""

	switch v := result.Expressions[0].Value.(type) {
	case bool:
		allow = v
	case map[string]interface{}:
		if allowVal, ok := v["allow"].(bool); ok {
			allow = allowVal
		}
		if reasonVal, ok := v["reason"].(string); ok {
			reason = reasonVal
		}
	}

	return allow, reason, nil
}

// EvaluateContextPolicy evaluates the OPA context injection policy (mcp.context.allow_context)
// RFA-xwc: Step 7 of the mandatory validation pipeline (Section 10.15.1)
// Returns (allowed, reason, error). Fails closed if policy is not loaded.
func (e *OPAEngine) EvaluateContextPolicy(input ContextPolicyInput) (bool, string, error) {
	e.mu.RLock()
	query := e.contextQuery
	e.mu.RUnlock()

	if query == nil {
		// Fail closed if no context policy loaded
		return false, "context_policy_not_loaded", nil
	}

	ctx := context.Background()
	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		// Fail closed on evaluation error
		slog.Error("OPA context policy evaluation error", "error", err)
		return false, "context_policy_evaluation_error", nil
	}

	// Parse result -- allow_context is a boolean
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return false, "context_policy_undefined", nil
	}

	switch v := results[0].Expressions[0].Value.(type) {
	case bool:
		if v {
			return true, "", nil
		}
		// Policy denied -- try to get the reason by evaluating deny_reason
		reason := e.getContextDenyReason(input)
		return false, reason, nil
	default:
		return false, "context_policy_unexpected_result", nil
	}
}

// getContextDenyReason evaluates data.mcp.context.deny_reason for a structured denial reason.
// Falls back to "context_injection_denied" if deny_reason cannot be determined.
func (e *OPAEngine) getContextDenyReason(input ContextPolicyInput) string {
	// Build a one-off query for deny_reason. This is acceptable for the denial
	// path (not hot path) since denials are infrequent.
	e.mu.RLock()
	defer e.mu.RUnlock()

	// We cannot easily prepare a second query at load time for deny_reason without
	// duplicating all the module loading. Instead, return a generic reason.
	// The context_policy.rego provides deny_reason rules, but since we only have
	// the allow_context prepared query, we return a meaningful default.
	return "context_injection_denied"
}

// EvaluateUIPolicy evaluates the mcp.ui.policy Rego rules against the given input.
// RFA-j2d.7: Returns a UIPolicyResult with each rule's boolean result.
// If the UI policy was not compiled (e.g., no ui_policy.rego file), returns
// a safe default (all false = no denials, no step-up, no excessive calls).
func (e *OPAEngine) EvaluateUIPolicy(input UIPolicyInput) (UIPolicyResult, error) {
	e.mu.RLock()
	queries := e.uiPolicyQueries
	e.mu.RUnlock()

	result := UIPolicyResult{}

	if queries == nil {
		// UI policy not loaded -- safe default (no denials)
		return result, nil
	}

	ctx := context.Background()
	evalInput := rego.EvalInput(input)

	// Evaluate each rule independently
	var err error
	result.DenyUIResource, err = evalBoolRule(ctx, &queries.denyUIResource, evalInput)
	if err != nil {
		slog.Error("OPA UI policy evaluation error", "rule", "deny_ui_resource", "error", err)
	}

	result.DenyAppToolCall, err = evalBoolRule(ctx, &queries.denyAppToolCall, evalInput)
	if err != nil {
		slog.Error("OPA UI policy evaluation error", "rule", "deny_app_tool_call", "error", err)
	}

	result.RequiresStepUp, err = evalBoolRule(ctx, &queries.requiresStepUp, evalInput)
	if err != nil {
		slog.Error("OPA UI policy evaluation error", "rule", "requires_step_up", "error", err)
	}

	result.ExcessiveAppCalls, err = evalBoolRule(ctx, &queries.excessiveAppCalls, evalInput)
	if err != nil {
		slog.Error("OPA UI policy evaluation error", "rule", "excessive_app_calls", "error", err)
	}

	return result, nil
}

// evalBoolRule evaluates a single boolean Rego rule. Returns false on error or
// if the result is undefined (fail-closed for denial rules, safe for flag rules).
func evalBoolRule(ctx context.Context, query *rego.PreparedEvalQuery, opts ...rego.EvalOption) (bool, error) {
	results, err := query.Eval(ctx, opts...)
	if err != nil {
		return false, err
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return false, nil
	}
	val, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, nil
	}
	return val, nil
}

// UIPolicyEvaluator interface for UI policy evaluation.
// Satisfied by OPAEngine.
type UIPolicyEvaluator interface {
	EvaluateUIPolicy(input UIPolicyInput) (UIPolicyResult, error)
}

// DataSourcePolicyResult captures the outcome of data source policy evaluation.
// OC-4zrf: Returned by EvaluateDataSourcePolicy.
type DataSourcePolicyResult struct {
	Allowed     bool     // true if the data source access is permitted
	DenyReasons []string // reasons for denial (from deny[msg] rules)
}

// DataSourcePolicyEvaluator interface for data source policy evaluation.
// OC-4zrf: Satisfied by OPAEngine.
type DataSourcePolicyEvaluator interface {
	EvaluateDataSourcePolicy(input OPAInput) (DataSourcePolicyResult, error)
}

// EvaluateDataSourcePolicy evaluates the data source policy (precinct.data_source).
// OC-4zrf: Returns allow/deny with reasons. Fails closed if policy is not loaded.
func (e *OPAEngine) EvaluateDataSourcePolicy(input OPAInput) (DataSourcePolicyResult, error) {
	e.mu.RLock()
	queries := e.dataSourcePolicyQuery
	e.mu.RUnlock()

	result := DataSourcePolicyResult{}

	if queries == nil {
		// Fail closed if no data source policy loaded
		result.DenyReasons = append(result.DenyReasons, "data_source_policy_not_loaded")
		return result, nil
	}

	ctx := context.Background()
	evalInput := rego.EvalInput(input)

	// Evaluate allow rule
	allowed, err := evalBoolRule(ctx, &queries.allow, evalInput)
	if err != nil {
		slog.Error("OPA data source policy evaluation error", "rule", "allow", "error", err)
		result.DenyReasons = append(result.DenyReasons, "data_source_policy_evaluation_error")
		return result, nil
	}

	// Evaluate deny rules (set of string reasons)
	denyResults, err := queries.deny.Eval(ctx, evalInput)
	if err != nil {
		slog.Error("OPA data source policy evaluation error", "rule", "deny", "error", err)
		result.DenyReasons = append(result.DenyReasons, "data_source_policy_evaluation_error")
		return result, nil
	}

	// Collect deny reasons from the deny[msg] set
	var denyReasons []string
	if len(denyResults) > 0 && len(denyResults[0].Expressions) > 0 {
		switch v := denyResults[0].Expressions[0].Value.(type) {
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					denyReasons = append(denyReasons, s)
				}
			}
		}
	}

	// Decision: allowed if allow==true AND no deny reasons
	if allowed && len(denyReasons) == 0 {
		result.Allowed = true
	} else {
		result.Allowed = false
		if len(denyReasons) > 0 {
			result.DenyReasons = denyReasons
		} else if !allowed {
			result.DenyReasons = append(result.DenyReasons, "data_source_access_denied")
		}
	}

	return result, nil
}

// startWatcher starts file system watcher for hot-reload
func (e *OPAEngine) startWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	e.watcher = watcher

	// Watch policy directory
	if err := watcher.Add(e.policyDir); err != nil {
		_ = watcher.Close()
		return fmt.Errorf("failed to watch policy directory: %w", err)
	}

	if e.HasPublicKey() {
		slog.Info("opa policy hot-reload watching with attestation", "path", e.policyDir, "attestation", e.attestationMode())
	} else {
		slog.Warn("opa policy hot-reload enabled WITHOUT attestation, unsigned updates will be accepted")
		slog.Info("opa policy hot-reload watching", "path", e.policyDir, "attestation", e.attestationMode())
	}

	// Start watcher goroutine
	go e.watchLoop()

	return nil
}

// watchLoop monitors file changes and reloads policies
func (e *OPAEngine) watchLoop() {
	for {
		select {
		case event, ok := <-e.watcher.Events:
			if !ok {
				return
			}

			// Reload on write or create events for policy files or companion signatures.
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				ext := filepath.Ext(event.Name)
				if ext == ".rego" || ext == ".yaml" || ext == ".yml" || ext == ".sig" {
					slog.Info("policy file changed, reloading", "file", event.Name)
					result, err := e.Reload()
					if err != nil {
						if result.Rejected {
							slog.Error("opa policy reload rejected, keeping previous policy", "reason", result.RejectionReason, "attestation_mode", result.AttestationMode)
						} else {
							slog.Warn("failed to reload policies, keeping previous policy", "error", err)
						}
					} else {
						slog.Info("policies reloaded successfully", "policy_count", result.PolicyCount, "attestation_mode", result.AttestationMode, "attestation_verified", result.AttestationVerified)
					}
				}
			}

		case err, ok := <-e.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("policy watcher error", "error", err)

		case <-e.stopChan:
			return
		}
	}
}

// Close stops the file watcher
func (e *OPAEngine) Close() error {
	close(e.stopChan)
	if e.watcher != nil {
		return e.watcher.Close()
	}
	return nil
}

// toInterfaceSlice converts []string to []interface{} for OPA data store compatibility.
func toInterfaceSlice(ss []string) []interface{} {
	out := make([]interface{}, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

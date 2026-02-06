package middleware

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"gopkg.in/yaml.v3"
)

// OPAEngineConfig holds runtime configuration injected into OPA data store.
// These values are accessible in Rego policies via data.config.<key>.
type OPAEngineConfig struct {
	// AllowedBasePath is the base directory for path-based access control.
	// Injected as data.config.allowed_base_path in OPA policies.
	// If empty, the policy falls back to its default ("/" -- fail-open for
	// path checks; SPIFFE and tool authorization still enforce access control).
	AllowedBasePath string
}

// OPAEngine handles embedded OPA policy evaluation
type OPAEngine struct {
	policyDir    string
	runtimeCfg   OPAEngineConfig
	query        *rego.PreparedEvalQuery
	contextQuery *rego.PreparedEvalQuery // RFA-xwc: query for mcp.context policy
	mu           sync.RWMutex
	watcher      *fsnotify.Watcher
	stopChan     chan struct{}
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
				log.Printf("Warning: failed to read data file %s: %v", file.Name(), err)
				continue
			}

			var data map[string]interface{}
			if err := yaml.Unmarshal(content, &data); err != nil {
				log.Printf("Warning: failed to parse YAML data file %s: %v", file.Name(), err)
				continue
			}

			// Write each top-level key from YAML as a separate data entry
			// This makes data.tool_grants accessible if YAML has "tool_grants: ..." at top level
			for key, value := range data {
				path := storage.MustParsePath("/" + key)
				if err := storage.WriteOne(ctx, dataStore, storage.AddOp, path, value); err != nil {
					log.Printf("Warning: failed to write data to store for key %s: %v", key, err)
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
		log.Printf("Warning: failed to compile context policy: %v (context injection will be denied)", err)
	} else {
		contextQueryPtr = &contextPrepared
	}

	// Atomically update queries
	e.mu.Lock()
	e.query = &prepared
	e.contextQuery = contextQueryPtr
	e.mu.Unlock()

	log.Printf("OPA policies loaded successfully from %s", e.policyDir)
	return nil
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
		log.Printf("OPA evaluation error: %v", err)
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
		log.Printf("OPA context policy evaluation error: %v", err)
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

// startWatcher starts file system watcher for hot-reload
func (e *OPAEngine) startWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	e.watcher = watcher

	// Watch policy directory
	if err := watcher.Add(e.policyDir); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to watch policy directory: %w", err)
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

			// Reload on write or create events for .rego or .yaml files
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				ext := filepath.Ext(event.Name)
				if ext == ".rego" || ext == ".yaml" || ext == ".yml" {
					log.Printf("Policy file changed: %s, reloading...", event.Name)
					if err := e.loadPolicies(); err != nil {
						log.Printf("Warning: failed to reload policies: %v (keeping previous policy)", err)
					} else {
						log.Printf("Policies reloaded successfully")
					}
				}
			}

		case err, ok := <-e.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Policy watcher error: %v", err)

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

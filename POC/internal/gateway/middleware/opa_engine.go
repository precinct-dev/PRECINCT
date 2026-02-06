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

// OPAEngine handles embedded OPA policy evaluation
type OPAEngine struct {
	policyDir string
	query     *rego.PreparedEvalQuery
	mu        sync.RWMutex
	watcher   *fsnotify.Watcher
	stopChan  chan struct{}
}

// NewOPAEngine creates a new embedded OPA engine
func NewOPAEngine(policyDir string) (*OPAEngine, error) {
	engine := &OPAEngine{
		policyDir: policyDir,
		stopChan:  make(chan struct{}),
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

	// Add store to rego options
	regoOpts = append(regoOpts, rego.Store(dataStore))

	// Set query path: /mcp/allow (matches our policy package structure)
	regoOpts = append(regoOpts, rego.Query("data.mcp.allow"))

	// Compile policy
	r := rego.New(regoOpts...)

	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to compile policy: %w", err)
	}

	// Atomically update query
	e.mu.Lock()
	e.query = &prepared
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

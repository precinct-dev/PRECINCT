// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// Extension Registry -- pluggable extension slots for the PRECINCT gateway.
//
// Three named extension slots are exposed at safe positions in the middleware
// chain. Each slot dispatches to external HTTP sidecar services configured via
// a hot-reloadable YAML file. Zero extensions configured = zero overhead.
//
// Valid slots: post_authz, post_inspection, post_analysis.
package middleware

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// ExtensionSlotName identifies a named extension slot in the middleware chain.
type ExtensionSlotName string

const (
	// SlotPostAuthz runs after OPA policy (step 6), before DLP (step 7).
	// Use cases: tool checkers, pre-scan authorization enrichment, custom RBAC.
	SlotPostAuthz ExtensionSlotName = "post_authz"

	// SlotPostInspection runs after DLP (step 7), before Session (step 8).
	// Use cases: content scanners (Skulto), markdown validators, format checkers.
	SlotPostInspection ExtensionSlotName = "post_inspection"

	// SlotPostAnalysis runs after DeepScan (step 10), before RateLimit (step 11).
	// Use cases: final approval gates, aggregated risk decisions, custom blocking.
	SlotPostAnalysis ExtensionSlotName = "post_analysis"
)

// ValidSlots is the set of allowed slot names. Any other value is rejected at
// config load time with a clear error message.
var ValidSlots = map[ExtensionSlotName]bool{
	SlotPostAuthz:      true,
	SlotPostInspection: true,
	SlotPostAnalysis:   true,
}

// ExtensionFilters controls which requests are dispatched to this extension.
// Empty slices mean "match all".
type ExtensionFilters struct {
	Methods []string `yaml:"methods"` // MCP method names (e.g., "tools/call")
	Tools   []string `yaml:"tools"`   // tool names within tools/call
}

// ExtensionRequestFields controls which request fields are included in the
// payload sent to the extension sidecar.
type ExtensionRequestFields struct {
	IncludeBody          bool `yaml:"include_body"`
	IncludeSPIFFEID      bool `yaml:"include_spiffe_id"`
	IncludeToolName      bool `yaml:"include_tool_name"`
	IncludeSecurityFlags bool `yaml:"include_security_flags"`
}

// ExtensionCBConfig holds per-extension circuit breaker settings.
type ExtensionCBConfig struct {
	FailureThreshold int `yaml:"failure_threshold"`
	ResetTimeoutMs   int `yaml:"reset_timeout_ms"`
}

// ExtensionDefinition represents a single extension sidecar registration.
type ExtensionDefinition struct {
	Name           string                 `yaml:"name"`
	Slot           ExtensionSlotName      `yaml:"slot"`
	Enabled        bool                   `yaml:"enabled"`
	Endpoint       string                 `yaml:"endpoint"`
	TimeoutMs      int                    `yaml:"timeout_ms"`
	FailMode       string                 `yaml:"fail_mode"` // "fail_open" or "fail_closed"
	Priority       int                    `yaml:"priority"`  // lower = runs first
	Description    string                 `yaml:"description"`
	Filters        ExtensionFilters       `yaml:"filters"`
	RequestFields  ExtensionRequestFields `yaml:"request_fields"`
	CircuitBreaker *ExtensionCBConfig     `yaml:"circuit_breaker,omitempty"`
}

// MatchesRequest returns true if this extension should be invoked for the given
// MCP method and tool name. Empty filter slices mean "match all".
func (ext *ExtensionDefinition) MatchesRequest(mcpMethod, toolName string) bool {
	if len(ext.Filters.Methods) > 0 {
		found := false
		for _, m := range ext.Filters.Methods {
			if m == mcpMethod {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(ext.Filters.Tools) > 0 {
		found := false
		for _, t := range ext.Filters.Tools {
			if t == toolName {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ExtensionRegistryConfig is the top-level YAML structure for extensions.yaml.
type ExtensionRegistryConfig struct {
	Version    string                `yaml:"version"`
	Extensions []ExtensionDefinition `yaml:"extensions"`
}

// ExtensionRegistry manages extension definitions loaded from YAML.
// Extensions are grouped by slot and sorted by priority within each slot.
// Thread-safe for concurrent reads during hot-reload via sync.RWMutex.
type ExtensionRegistry struct {
	mu         sync.RWMutex
	bySlot     map[ExtensionSlotName][]ExtensionDefinition
	configPath string
}

// NewExtensionRegistry creates a new extension registry from a YAML config file.
// It loads the file, validates slot names, filters enabled extensions, groups by
// slot, and sorts each group by priority.
func NewExtensionRegistry(configPath string) (*ExtensionRegistry, error) {
	r := &ExtensionRegistry{
		bySlot:     make(map[ExtensionSlotName][]ExtensionDefinition),
		configPath: configPath,
	}
	if configPath != "" {
		if err := r.loadConfig(configPath); err != nil {
			return nil, fmt.Errorf("failed to load extension registry config: %w", err)
		}
	}
	return r, nil
}

// loadConfig reads the YAML file, validates, and atomically swaps the registry.
func (r *ExtensionRegistry) loadConfig(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config ExtensionRegistryConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Build new map: validate slots, filter enabled, group by slot, sort by priority.
	newBySlot := make(map[ExtensionSlotName][]ExtensionDefinition)
	for _, ext := range config.Extensions {
		if !ValidSlots[ext.Slot] {
			return fmt.Errorf("invalid extension slot %q for extension %q; valid slots: post_authz, post_inspection, post_analysis", ext.Slot, ext.Name)
		}
		if !ext.Enabled {
			continue
		}
		newBySlot[ext.Slot] = append(newBySlot[ext.Slot], ext)
	}

	// Sort each slot group by priority (lower = first).
	for slot := range newBySlot {
		sort.Slice(newBySlot[slot], func(i, j int) bool {
			return newBySlot[slot][i].Priority < newBySlot[slot][j].Priority
		})
	}

	// Atomic swap under write lock.
	r.mu.Lock()
	r.bySlot = newBySlot
	r.mu.Unlock()

	return nil
}

// ExtensionsForSlot returns a snapshot of extensions registered for the given slot.
// Returns nil if no extensions are registered for the slot.
func (r *ExtensionRegistry) ExtensionsForSlot(slot ExtensionSlotName) []ExtensionDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	exts := r.bySlot[slot]
	if len(exts) == 0 {
		return nil
	}
	// Return a copy so callers can't mutate the registry.
	result := make([]ExtensionDefinition, len(exts))
	copy(result, exts)
	return result
}

// Reload re-reads the YAML config, validates slot names, and atomically swaps
// the extension map. Returns the total number of enabled extensions loaded.
func (r *ExtensionRegistry) Reload() (int, error) {
	if r.configPath == "" {
		return 0, nil
	}
	if err := r.loadConfig(r.configPath); err != nil {
		return 0, err
	}
	r.mu.RLock()
	total := 0
	for _, exts := range r.bySlot {
		total += len(exts)
	}
	r.mu.RUnlock()
	return total, nil
}

// Watch starts an fsnotify watcher on the config file directory. When the file
// changes, the registry is automatically reloaded. Returns a stop function.
// Follows the same pattern as ToolRegistry.Watch().
func (r *ExtensionRegistry) Watch() (stop func(), err error) {
	noop := func() {}

	if r.configPath == "" {
		return noop, nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return noop, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	configDir := filepath.Dir(r.configPath)
	configBase := filepath.Base(r.configPath)

	if err := watcher.Add(configDir); err != nil {
		_ = watcher.Close()
		return noop, fmt.Errorf("failed to watch directory %s: %w", configDir, err)
	}

	slog.Info("extension-registry watching for changes", "path", r.configPath)

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
				if filepath.Base(event.Name) != configBase {
					continue
				}
				if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
					continue
				}
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(100*time.Millisecond, func() {
					slog.Info("extension-registry file change detected, reloading", "file", event.Name)
					count, reloadErr := r.Reload()
					if reloadErr != nil {
						slog.Error("extension-registry reload failed, keeping old config", "error", reloadErr)
					} else {
						slog.Info("extension-registry reload successful", "extensions", count)
					}
				})
			case watchErr, ok := <-watcher.Errors:
				if !ok {
					return
				}
				slog.Error("extension-registry watcher error", "error", watchErr)
			}
		}
	}()

	stopFn := func() {
		_ = watcher.Close()
		<-done
	}
	return stopFn, nil
}

// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// Reversibility Classifier Tests - OC-ytph
// Unit tests: keyword matching, param escalation, ToolDefinition override, defaults.
// Integration test: loads actual tool-registry.yaml and classifies real tools.
package middleware

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

func TestClassifyReversibility_DeleteFile(t *testing.T) {
	r := ClassifyReversibility("bash", "delete_file", nil, nil)
	if r.Score != 3 {
		t.Errorf("Score: got %d, want 3", r.Score)
	}
	if r.Category != "irreversible" {
		t.Errorf("Category: got %q, want %q", r.Category, "irreversible")
	}
	if !r.RequiresBackup {
		t.Error("RequiresBackup: got false, want true")
	}
}

func TestClassifyReversibility_UpdateConfig(t *testing.T) {
	r := ClassifyReversibility("config", "update_config", nil, nil)
	if r.Score != 2 {
		t.Errorf("Score: got %d, want 2", r.Score)
	}
	if r.Category != "partially_reversible" {
		t.Errorf("Category: got %q, want %q", r.Category, "partially_reversible")
	}
	if !r.RequiresBackup {
		t.Error("RequiresBackup: got false, want true")
	}
}

func TestClassifyReversibility_SendMessage(t *testing.T) {
	r := ClassifyReversibility("messaging", "send_message", nil, nil)
	if r.Score != 1 {
		t.Errorf("Score: got %d, want 1", r.Score)
	}
	if r.Category != "costly_reversible" {
		t.Errorf("Category: got %q, want %q", r.Category, "costly_reversible")
	}
	if r.RequiresBackup {
		t.Error("RequiresBackup: got true, want false")
	}
}

func TestClassifyReversibility_ListFiles(t *testing.T) {
	r := ClassifyReversibility("fs", "list_files", nil, nil)
	if r.Score != 0 {
		t.Errorf("Score: got %d, want 0", r.Score)
	}
	if r.Category != "reversible" {
		t.Errorf("Category: got %q, want %q", r.Category, "reversible")
	}
	if r.RequiresBackup {
		t.Error("RequiresBackup: got true, want false")
	}
}

func TestClassifyReversibility_UnknownAction(t *testing.T) {
	r := ClassifyReversibility("tool", "unknown_action", nil, nil)
	if r.Score != 1 {
		t.Errorf("Score: got %d, want 1 (default)", r.Score)
	}
	if r.Category != "costly_reversible" {
		t.Errorf("Category: got %q, want %q", r.Category, "costly_reversible")
	}
}

func TestClassifyReversibility_ParamsCommandEscalation(t *testing.T) {
	params := map[string]interface{}{
		"command": "rm -rf /tmp/data",
	}
	r := ClassifyReversibility("bash", "exec", params, nil)
	if r.Score != 3 {
		t.Errorf("Score: got %d, want 3 (escalated via params command)", r.Score)
	}
	if r.Category != "irreversible" {
		t.Errorf("Category: got %q, want %q", r.Category, "irreversible")
	}
	if !r.RequiresBackup {
		t.Error("RequiresBackup: got false, want true")
	}
}

func TestClassifyReversibility_ToolDefCriticalElevation(t *testing.T) {
	toolDef := &ToolDefinition{
		Name:      "bash",
		RiskLevel: "critical",
	}
	// "list" is Score=0 normally, but RiskLevel=critical enforces minimum Score=2
	r := ClassifyReversibility("bash", "list", nil, toolDef)
	if r.Score != 2 {
		t.Errorf("Score: got %d, want 2 (minimum from RiskLevel=critical)", r.Score)
	}
	if r.Category != "partially_reversible" {
		t.Errorf("Category: got %q, want %q", r.Category, "partially_reversible")
	}
	if !r.RequiresBackup {
		t.Error("RequiresBackup: got false, want true")
	}
}

func TestClassifyReversibility_EmptyAction(t *testing.T) {
	r := ClassifyReversibility("tool", "", nil, nil)
	if r.Score != 1 {
		t.Errorf("Score: got %d, want 1 (default for empty action)", r.Score)
	}
}

func TestClassifyReversibility_CaseInsensitive(t *testing.T) {
	r := ClassifyReversibility("bash", "DELETE", nil, nil)
	if r.Score != 3 {
		t.Errorf("Score: got %d, want 3 (case-insensitive DELETE)", r.Score)
	}
	if r.Category != "irreversible" {
		t.Errorf("Category: got %q, want %q", r.Category, "irreversible")
	}
}

func TestClassifyReversibility_ParamsActionKey(t *testing.T) {
	// Params with "action" key (not "command") should also be checked
	params := map[string]interface{}{
		"action": "drop_table",
	}
	r := ClassifyReversibility("db", "exec", params, nil)
	if r.Score != 3 {
		t.Errorf("Score: got %d, want 3 (escalated via params action key)", r.Score)
	}
}

func TestClassifyReversibility_ParamsDontDeescalate(t *testing.T) {
	// Action is "delete" (Score=3), param command is "list" (Score=0).
	// Should keep the more severe score (3).
	params := map[string]interface{}{
		"command": "list stuff",
	}
	r := ClassifyReversibility("bash", "delete_stuff", params, nil)
	if r.Score != 3 {
		t.Errorf("Score: got %d, want 3 (params should not de-escalate)", r.Score)
	}
}

func TestClassifyReversibility_NilParams(t *testing.T) {
	// Nil params map should not panic
	r := ClassifyReversibility("tool", "delete_file", nil, nil)
	if r.Score != 3 {
		t.Errorf("Score: got %d, want 3", r.Score)
	}
}

func TestClassifyReversibility_AllIrreversibleKeywords(t *testing.T) {
	keywords := []string{"delete", "rm", "remove", "drop", "reset", "wipe",
		"shutdown", "terminate", "revoke", "purge", "destroy", "truncate"}
	for _, kw := range keywords {
		r := ClassifyReversibility("tool", kw, nil, nil)
		if r.Score != 3 {
			t.Errorf("keyword %q: Score=%d, want 3", kw, r.Score)
		}
	}
}

func TestClassifyReversibility_AllReversibleKeywords(t *testing.T) {
	keywords := []string{"read", "list", "search", "get", "health", "status",
		"ping", "head", "describe", "show", "count", "exists"}
	for _, kw := range keywords {
		r := ClassifyReversibility("tool", kw, nil, nil)
		if r.Score != 0 {
			t.Errorf("keyword %q: Score=%d, want 0", kw, r.Score)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration Test -- loads actual tool-registry.yaml
// ---------------------------------------------------------------------------

func TestClassifyReversibility_Integration_ToolRegistry(t *testing.T) {
	// Locate config/tool-registry.yaml relative to this test file
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// thisFile: .../POC/internal/gateway/middleware/reversibility_test.go
	pocRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	registryPath := filepath.Join(pocRoot, "config", "tool-registry.yaml")

	if _, err := os.Stat(registryPath); err != nil {
		t.Fatalf("tool-registry.yaml not found at %s: %v", registryPath, err)
	}

	registry, err := NewToolRegistry(registryPath)
	if err != nil {
		t.Fatalf("failed to load tool registry: %v", err)
	}

	// Sub-test 1: bash tool + exec action should be Score >= 2
	// bash has risk_level: "critical" in the registry
	bashDef, found := registry.GetToolDefinition("bash")
	if !found {
		t.Fatal("bash tool not found in registry")
	}
	bashResult := ClassifyReversibility("bash", "exec", nil, &bashDef)
	if bashResult.Score < 2 {
		t.Errorf("bash+exec: Score=%d, want >= 2 (critical tool)", bashResult.Score)
	}

	// Sub-test 2: tavily_search tool + search action should be Score=0
	tavilyDef, found := registry.GetToolDefinition("tavily_search")
	if !found {
		t.Fatal("tavily_search tool not found in registry")
	}
	tavilyResult := ClassifyReversibility("tavily_search", "search", nil, &tavilyDef)
	if tavilyResult.Score != 0 {
		t.Errorf("tavily_search+search: Score=%d, want 0", tavilyResult.Score)
	}
	if tavilyResult.Category != "reversible" {
		t.Errorf("tavily_search+search: Category=%q, want %q", tavilyResult.Category, "reversible")
	}
}

// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtensionRegistry_LoadValidConfig(t *testing.T) {
	yaml := `
version: "1"
extensions:
  - name: "tool_checker"
    slot: "post_authz"
    enabled: true
    endpoint: "http://tool-checker:8080/check"
    timeout_ms: 1000
    fail_mode: "fail_closed"
    priority: 100
  - name: "skulto"
    slot: "post_inspection"
    enabled: true
    endpoint: "http://skulto:8080/scan"
    timeout_ms: 2000
    fail_mode: "fail_open"
    priority: 200
  - name: "final_approval"
    slot: "post_analysis"
    enabled: true
    endpoint: "http://approval:8080/approve"
    timeout_ms: 3000
    fail_mode: "fail_closed"
    priority: 100
`
	path := writeTestYAML(t, yaml)
	reg, err := NewExtensionRegistry(path)
	if err != nil {
		t.Fatalf("NewExtensionRegistry failed: %v", err)
	}

	// Verify each slot has the correct extension.
	postAuthz := reg.ExtensionsForSlot(SlotPostAuthz)
	if len(postAuthz) != 1 || postAuthz[0].Name != "tool_checker" {
		t.Errorf("post_authz: got %d extensions, want 1 (tool_checker)", len(postAuthz))
	}
	postInsp := reg.ExtensionsForSlot(SlotPostInspection)
	if len(postInsp) != 1 || postInsp[0].Name != "skulto" {
		t.Errorf("post_inspection: got %d extensions, want 1 (skulto)", len(postInsp))
	}
	postAnalysis := reg.ExtensionsForSlot(SlotPostAnalysis)
	if len(postAnalysis) != 1 || postAnalysis[0].Name != "final_approval" {
		t.Errorf("post_analysis: got %d extensions, want 1 (final_approval)", len(postAnalysis))
	}
}

func TestExtensionRegistry_InvalidSlotRejected(t *testing.T) {
	yaml := `
version: "1"
extensions:
  - name: "bad_ext"
    slot: "before_everything"
    enabled: true
    endpoint: "http://bad:8080"
    timeout_ms: 1000
    fail_mode: "fail_open"
    priority: 100
`
	path := writeTestYAML(t, yaml)
	_, err := NewExtensionRegistry(path)
	if err == nil {
		t.Fatal("expected error for invalid slot name, got nil")
	}
}

func TestExtensionRegistry_PrioritySorting(t *testing.T) {
	yaml := `
version: "1"
extensions:
  - name: "c_ext"
    slot: "post_authz"
    enabled: true
    endpoint: "http://c:8080"
    timeout_ms: 1000
    fail_mode: "fail_open"
    priority: 300
  - name: "a_ext"
    slot: "post_authz"
    enabled: true
    endpoint: "http://a:8080"
    timeout_ms: 1000
    fail_mode: "fail_open"
    priority: 100
  - name: "b_ext"
    slot: "post_authz"
    enabled: true
    endpoint: "http://b:8080"
    timeout_ms: 1000
    fail_mode: "fail_open"
    priority: 200
`
	path := writeTestYAML(t, yaml)
	reg, err := NewExtensionRegistry(path)
	if err != nil {
		t.Fatalf("NewExtensionRegistry failed: %v", err)
	}

	exts := reg.ExtensionsForSlot(SlotPostAuthz)
	if len(exts) != 3 {
		t.Fatalf("expected 3 extensions, got %d", len(exts))
	}
	if exts[0].Name != "a_ext" || exts[1].Name != "b_ext" || exts[2].Name != "c_ext" {
		t.Errorf("priority order wrong: got [%s, %s, %s], want [a_ext, b_ext, c_ext]",
			exts[0].Name, exts[1].Name, exts[2].Name)
	}
}

func TestExtensionRegistry_DisabledFiltering(t *testing.T) {
	yaml := `
version: "1"
extensions:
  - name: "enabled_ext"
    slot: "post_authz"
    enabled: true
    endpoint: "http://enabled:8080"
    timeout_ms: 1000
    fail_mode: "fail_open"
    priority: 100
  - name: "disabled_ext"
    slot: "post_authz"
    enabled: false
    endpoint: "http://disabled:8080"
    timeout_ms: 1000
    fail_mode: "fail_open"
    priority: 50
`
	path := writeTestYAML(t, yaml)
	reg, err := NewExtensionRegistry(path)
	if err != nil {
		t.Fatalf("NewExtensionRegistry failed: %v", err)
	}

	exts := reg.ExtensionsForSlot(SlotPostAuthz)
	if len(exts) != 1 {
		t.Fatalf("expected 1 enabled extension, got %d", len(exts))
	}
	if exts[0].Name != "enabled_ext" {
		t.Errorf("expected enabled_ext, got %s", exts[0].Name)
	}
}

func TestExtensionRegistry_Reload(t *testing.T) {
	yaml1 := `
version: "1"
extensions:
  - name: "ext1"
    slot: "post_authz"
    enabled: true
    endpoint: "http://ext1:8080"
    timeout_ms: 1000
    fail_mode: "fail_open"
    priority: 100
`
	path := writeTestYAML(t, yaml1)
	reg, err := NewExtensionRegistry(path)
	if err != nil {
		t.Fatalf("NewExtensionRegistry failed: %v", err)
	}

	exts := reg.ExtensionsForSlot(SlotPostAuthz)
	if len(exts) != 1 {
		t.Fatalf("before reload: expected 1, got %d", len(exts))
	}

	// Overwrite with a second extension added.
	yaml2 := `
version: "1"
extensions:
  - name: "ext1"
    slot: "post_authz"
    enabled: true
    endpoint: "http://ext1:8080"
    timeout_ms: 1000
    fail_mode: "fail_open"
    priority: 100
  - name: "ext2"
    slot: "post_inspection"
    enabled: true
    endpoint: "http://ext2:8080"
    timeout_ms: 2000
    fail_mode: "fail_closed"
    priority: 50
`
	if err := os.WriteFile(path, []byte(yaml2), 0644); err != nil {
		t.Fatalf("failed to write updated YAML: %v", err)
	}

	count, err := reg.Reload()
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	if count != 2 {
		t.Errorf("Reload: expected 2 extensions, got %d", count)
	}

	exts = reg.ExtensionsForSlot(SlotPostInspection)
	if len(exts) != 1 || exts[0].Name != "ext2" {
		t.Errorf("post_inspection after reload: expected ext2, got %v", exts)
	}
}

func TestExtensionRegistry_EmptyConfig(t *testing.T) {
	yaml := `
version: "1"
extensions: []
`
	path := writeTestYAML(t, yaml)
	reg, err := NewExtensionRegistry(path)
	if err != nil {
		t.Fatalf("NewExtensionRegistry failed: %v", err)
	}

	for _, slot := range []ExtensionSlotName{SlotPostAuthz, SlotPostInspection, SlotPostAnalysis} {
		if exts := reg.ExtensionsForSlot(slot); exts != nil {
			t.Errorf("slot %s: expected nil, got %d extensions", slot, len(exts))
		}
	}
}

func TestExtensionRegistry_MixedSlots(t *testing.T) {
	yaml := `
version: "1"
extensions:
  - name: "a"
    slot: "post_authz"
    enabled: true
    endpoint: "http://a:8080"
    timeout_ms: 1000
    fail_mode: "fail_open"
    priority: 100
  - name: "b"
    slot: "post_inspection"
    enabled: true
    endpoint: "http://b:8080"
    timeout_ms: 1000
    fail_mode: "fail_open"
    priority: 200
  - name: "c"
    slot: "post_authz"
    enabled: true
    endpoint: "http://c:8080"
    timeout_ms: 1000
    fail_mode: "fail_open"
    priority: 50
  - name: "d"
    slot: "post_analysis"
    enabled: true
    endpoint: "http://d:8080"
    timeout_ms: 1000
    fail_mode: "fail_open"
    priority: 100
`
	path := writeTestYAML(t, yaml)
	reg, err := NewExtensionRegistry(path)
	if err != nil {
		t.Fatalf("NewExtensionRegistry failed: %v", err)
	}

	// post_authz should have 2 extensions: c (50) before a (100).
	authz := reg.ExtensionsForSlot(SlotPostAuthz)
	if len(authz) != 2 {
		t.Fatalf("post_authz: expected 2, got %d", len(authz))
	}
	if authz[0].Name != "c" || authz[1].Name != "a" {
		t.Errorf("post_authz order: got [%s, %s], want [c, a]", authz[0].Name, authz[1].Name)
	}

	// post_inspection should have 1 extension.
	insp := reg.ExtensionsForSlot(SlotPostInspection)
	if len(insp) != 1 || insp[0].Name != "b" {
		t.Errorf("post_inspection: expected [b], got %v", insp)
	}

	// post_analysis should have 1 extension.
	analysis := reg.ExtensionsForSlot(SlotPostAnalysis)
	if len(analysis) != 1 || analysis[0].Name != "d" {
		t.Errorf("post_analysis: expected [d], got %v", analysis)
	}
}

func TestExtensionDefinition_MatchesRequest(t *testing.T) {
	tests := []struct {
		name      string
		filters   ExtensionFilters
		method    string
		tool      string
		wantMatch bool
	}{
		{"empty filters match all", ExtensionFilters{}, "tools/call", "read_file", true},
		{"method match", ExtensionFilters{Methods: []string{"tools/call"}}, "tools/call", "", true},
		{"method mismatch", ExtensionFilters{Methods: []string{"tools/call"}}, "tools/list", "", false},
		{"tool match", ExtensionFilters{Tools: []string{"read_file"}}, "tools/call", "read_file", true},
		{"tool mismatch", ExtensionFilters{Tools: []string{"write_file"}}, "tools/call", "read_file", false},
		{"both match", ExtensionFilters{Methods: []string{"tools/call"}, Tools: []string{"read_file"}}, "tools/call", "read_file", true},
		{"method match tool mismatch", ExtensionFilters{Methods: []string{"tools/call"}, Tools: []string{"write_file"}}, "tools/call", "read_file", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := ExtensionDefinition{Filters: tt.filters}
			got := ext.MatchesRequest(tt.method, tt.tool)
			if got != tt.wantMatch {
				t.Errorf("MatchesRequest(%q, %q) = %v, want %v", tt.method, tt.tool, got, tt.wantMatch)
			}
		})
	}
}

func TestExtensionRegistry_EmptyPath(t *testing.T) {
	reg, err := NewExtensionRegistry("")
	if err != nil {
		t.Fatalf("NewExtensionRegistry with empty path failed: %v", err)
	}
	if exts := reg.ExtensionsForSlot(SlotPostAuthz); exts != nil {
		t.Errorf("expected nil extensions for empty path registry")
	}
}

// writeTestYAML writes YAML content to a temp file and returns the path.
func writeTestYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "extensions.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test YAML: %v", err)
	}
	return path
}

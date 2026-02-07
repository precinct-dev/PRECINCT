package middleware

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestOPAEngineInitialization verifies OPA engine creation and policy loading
func TestOPAEngineInitialization(t *testing.T) {
	// Create temp directory with test policies
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "test_policy.rego")
	dataPath := filepath.Join(tmpDir, "test_data.yaml")

	// Write minimal valid policy
	policyContent := `package test
default allow = false
allow = true {
	input.tool == "allowed_tool"
}
`
	if err := os.WriteFile(policyPath, []byte(policyContent), 0644); err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}

	// Write minimal data file
	dataContent := `tools:
  - name: allowed_tool
`
	if err := os.WriteFile(dataPath, []byte(dataContent), 0644); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}

	// Create OPA engine
	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
}

// TestOPAEngineEvaluate verifies policy evaluation
func TestOPAEngineEvaluate(t *testing.T) {
	// Create temp directory with test policies
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "test_policy.rego")

	// Write test policy with structured result
	policyContent := `package mcp
default allow = {
	"allow": false,
	"reason": "default_deny"
}
allow = {
	"allow": true,
	"reason": "allowed"
} {
	input.tool == "allowed_tool"
}
allow = {
	"allow": false,
	"reason": "tool_not_allowed"
} {
	input.tool != "allowed_tool"
}
`
	if err := os.WriteFile(policyPath, []byte(policyContent), 0644); err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}

	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	tests := []struct {
		name       string
		input      OPAInput
		wantAllow  bool
		wantReason string
	}{
		{
			name: "AllowedTool",
			input: OPAInput{
				SPIFFEID: "spiffe://test/agent",
				Tool:     "allowed_tool",
				Action:   "execute",
			},
			wantAllow:  true,
			wantReason: "allowed",
		},
		{
			name: "DeniedTool",
			input: OPAInput{
				SPIFFEID: "spiffe://test/agent",
				Tool:     "denied_tool",
				Action:   "execute",
			},
			wantAllow:  false,
			wantReason: "tool_not_allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason, err := engine.Evaluate(tt.input)
			if err != nil {
				t.Errorf("Evaluate failed: %v", err)
			}
			if allowed != tt.wantAllow {
				t.Errorf("Expected allow=%v, got %v", tt.wantAllow, allowed)
			}
			if reason != tt.wantReason {
				t.Errorf("Expected reason=%s, got %s", tt.wantReason, reason)
			}
		})
	}
}

// TestOPAEngineFailClosed verifies fail-closed behavior
func TestOPAEngineFailClosed(t *testing.T) {
	// Create engine with invalid policy
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "invalid.rego")

	// Write syntactically invalid policy
	invalidPolicy := `package mcp
	this is not valid rego syntax
`
	if err := os.WriteFile(policyPath, []byte(invalidPolicy), 0644); err != nil {
		t.Fatalf("Failed to write invalid policy: %v", err)
	}

	// Engine creation should fail
	_, err := NewOPAEngine(tmpDir)
	if err == nil {
		t.Error("Expected error for invalid policy, got nil")
	}
}

// TestOPAEngineMissingPolicyFiles verifies startup failure when policy files missing
func TestOPAEngineMissingPolicyFiles(t *testing.T) {
	// Create empty directory
	tmpDir := t.TempDir()

	// Engine creation should fail
	_, err := NewOPAEngine(tmpDir)
	if err == nil {
		t.Error("Expected error for missing policy files, got nil")
	}
}

// TestOPAEngineHotReload verifies policy hot-reload functionality
func TestOPAEngineHotReload(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "test_policy.rego")

	// Write initial policy (denies everything)
	initialPolicy := `package mcp
default allow = {
	"allow": false,
	"reason": "default_deny"
}
`
	if err := os.WriteFile(policyPath, []byte(initialPolicy), 0644); err != nil {
		t.Fatalf("Failed to write initial policy: %v", err)
	}

	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	// Test initial policy (should deny)
	input := OPAInput{
		SPIFFEID: "spiffe://test/agent",
		Tool:     "test_tool",
		Action:   "execute",
	}
	allowed, _, err := engine.Evaluate(input)
	if err != nil {
		t.Fatalf("Initial evaluation failed: %v", err)
	}
	if allowed {
		t.Error("Expected initial policy to deny, got allow")
	}

	// Update policy (allows everything)
	updatedPolicy := `package mcp
default allow = {
	"allow": true,
	"reason": "allowed"
}
`
	if err := os.WriteFile(policyPath, []byte(updatedPolicy), 0644); err != nil {
		t.Fatalf("Failed to write updated policy: %v", err)
	}

	// Wait for file watcher to detect change
	time.Sleep(500 * time.Millisecond)

	// Test updated policy (should allow)
	allowed, reason, err := engine.Evaluate(input)
	if err != nil {
		t.Fatalf("Post-reload evaluation failed: %v", err)
	}
	if !allowed {
		t.Errorf("Expected updated policy to allow, got deny with reason: %s", reason)
	}
}

// TestOPAEngineContextPolicyEvaluate verifies the context injection policy evaluation
// RFA-xwc: Tests for step 7 of the mandatory validation pipeline
func TestOPAEngineContextPolicyEvaluate(t *testing.T) {
	tmpDir := t.TempDir()

	// Write the actual context policy from config/opa/context_policy.rego
	// Includes step-up approval path for sensitive content (AC #3)
	contextPolicy := `package mcp.context

import rego.v1

default allow_context := false

allow_context if {
    input.context.source == "external"
    input.context.validated == true
    input.context.classification != "sensitive"
    input.context.handle != ""
    not session_is_high_risk
}

allow_context if {
    input.context.source == "external"
    input.context.validated == true
    input.context.classification == "sensitive"
    input.context.handle != ""
    not session_is_high_risk
    input.step_up_token != ""
}

session_is_high_risk if {
    input.session.flags["high_risk"]
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "context_policy.rego"), []byte(contextPolicy), 0644); err != nil {
		t.Fatalf("Failed to write context policy: %v", err)
	}

	// Also need a basic MCP policy so the main query compiles
	mcpPolicy := `package mcp
default allow = {"allow": true, "reason": "allowed"}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "mcp_policy.rego"), []byte(mcpPolicy), 0644); err != nil {
		t.Fatalf("Failed to write MCP policy: %v", err)
	}

	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	tests := []struct {
		name      string
		input     ContextPolicyInput
		wantAllow bool
	}{
		{
			name: "allow_clean_external_content",
			input: ContextPolicyInput{
				Context: ContextInput{
					Source:         "external",
					Validated:      true,
					Classification: "clean",
					Handle:         "abc123-uuid",
				},
				Session: ContextSessionInput{
					Flags: map[string]bool{},
				},
			},
			wantAllow: true,
		},
		{
			name: "deny_sensitive_content_without_step_up",
			input: ContextPolicyInput{
				Context: ContextInput{
					Source:         "external",
					Validated:      true,
					Classification: "sensitive",
					Handle:         "abc123-uuid",
				},
				Session: ContextSessionInput{
					Flags: map[string]bool{},
				},
				StepUpToken: "", // No step-up token -> denied
			},
			wantAllow: false,
		},
		{
			name: "allow_sensitive_content_with_step_up",
			input: ContextPolicyInput{
				Context: ContextInput{
					Source:         "external",
					Validated:      true,
					Classification: "sensitive",
					Handle:         "abc123-uuid",
				},
				Session: ContextSessionInput{
					Flags: map[string]bool{},
				},
				StepUpToken: "valid-step-up-token",
			},
			wantAllow: true,
		},
		{
			name: "deny_sensitive_content_with_step_up_high_risk",
			input: ContextPolicyInput{
				Context: ContextInput{
					Source:         "external",
					Validated:      true,
					Classification: "sensitive",
					Handle:         "abc123-uuid",
				},
				Session: ContextSessionInput{
					Flags: map[string]bool{"high_risk": true},
				},
				StepUpToken: "valid-step-up-token", // Step-up present but session is high-risk -> denied
			},
			wantAllow: false,
		},
		{
			name: "deny_high_risk_session",
			input: ContextPolicyInput{
				Context: ContextInput{
					Source:         "external",
					Validated:      true,
					Classification: "clean",
					Handle:         "abc123-uuid",
				},
				Session: ContextSessionInput{
					Flags: map[string]bool{"high_risk": true},
				},
			},
			wantAllow: false,
		},
		{
			name: "deny_unvalidated_content",
			input: ContextPolicyInput{
				Context: ContextInput{
					Source:         "external",
					Validated:      false,
					Classification: "clean",
					Handle:         "abc123-uuid",
				},
				Session: ContextSessionInput{
					Flags: map[string]bool{},
				},
			},
			wantAllow: false,
		},
		{
			name: "deny_missing_handle",
			input: ContextPolicyInput{
				Context: ContextInput{
					Source:         "external",
					Validated:      true,
					Classification: "clean",
					Handle:         "",
				},
				Session: ContextSessionInput{
					Flags: map[string]bool{},
				},
			},
			wantAllow: false,
		},
		{
			name: "deny_non_external_source",
			input: ContextPolicyInput{
				Context: ContextInput{
					Source:         "internal",
					Validated:      true,
					Classification: "clean",
					Handle:         "abc123-uuid",
				},
				Session: ContextSessionInput{
					Flags: map[string]bool{},
				},
			},
			wantAllow: false,
		},
		{
			name: "allow_suspicious_but_not_sensitive",
			input: ContextPolicyInput{
				Context: ContextInput{
					Source:         "external",
					Validated:      true,
					Classification: "suspicious",
					Handle:         "abc123-uuid",
				},
				Session: ContextSessionInput{
					Flags: map[string]bool{},
				},
			},
			wantAllow: true,
		},
		{
			name: "deny_high_risk_even_with_clean_content",
			input: ContextPolicyInput{
				Context: ContextInput{
					Source:         "external",
					Validated:      true,
					Classification: "clean",
					Handle:         "valid-handle-uuid",
				},
				Session: ContextSessionInput{
					Flags: map[string]bool{"high_risk": true, "other_flag": true},
				},
			},
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason, err := engine.EvaluateContextPolicy(tt.input)
			if err != nil {
				t.Errorf("EvaluateContextPolicy failed: %v", err)
			}
			if allowed != tt.wantAllow {
				t.Errorf("Expected allow=%v, got %v (reason: %s)", tt.wantAllow, allowed, reason)
			}
			// For denials, verify we get a reason
			if !allowed && reason == "" {
				t.Error("Expected non-empty reason for denial")
			}
		})
	}
}

// TestOPAEngineContextPolicyFailClosed verifies fail-closed when context policy missing
func TestOPAEngineContextPolicyFailClosed(t *testing.T) {
	tmpDir := t.TempDir()

	// Only write MCP policy, no context policy
	mcpPolicy := `package mcp
default allow = {"allow": true, "reason": "allowed"}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "mcp_policy.rego"), []byte(mcpPolicy), 0644); err != nil {
		t.Fatalf("Failed to write MCP policy: %v", err)
	}

	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	// Even with clean content and normal session, context policy should deny
	// because the policy is not loaded (no mcp.context package)
	input := ContextPolicyInput{
		Context: ContextInput{
			Source:         "external",
			Validated:      true,
			Classification: "clean",
			Handle:         "abc123",
		},
		Session: ContextSessionInput{
			Flags: map[string]bool{},
		},
	}

	allowed, _, err := engine.EvaluateContextPolicy(input)
	if err != nil {
		t.Fatalf("Evaluation should not error (fail closed gracefully): %v", err)
	}
	if allowed {
		t.Error("Expected fail-closed (deny) when context policy is not loaded, got allow")
	}
}

// TestOPAEngineConfigInjection verifies runtime config is injected into OPA data store (RFA-2jl)
func TestOPAEngineConfigInjection(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a policy that uses data.config.allowed_base_path for path restriction
	policyContent := `package mcp
import future.keywords.if
import future.keywords.in

default poc_directory := "__UNCONFIGURED__"
poc_directory := data.config.allowed_base_path

default allow := {"allow": false, "reason": "default_deny"}

allow := {"allow": true, "reason": "allowed"} if {
	input.tool == "read"
	startswith(input.params.file_path, poc_directory)
}

allow := {"allow": false, "reason": "path_denied"} if {
	input.tool == "read"
	not startswith(input.params.file_path, poc_directory)
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "test_policy.rego"), []byte(policyContent), 0644); err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}

	tests := []struct {
		name            string
		allowedBasePath string
		filePath        string
		wantAllow       bool
		wantReason      string
	}{
		{
			name:            "AllowedPathWithConfig",
			allowedBasePath: "/workspace/poc",
			filePath:        "/workspace/poc/README.md",
			wantAllow:       true,
			wantReason:      "allowed",
		},
		{
			name:            "DeniedPathOutsideConfig",
			allowedBasePath: "/workspace/poc",
			filePath:        "/etc/passwd",
			wantAllow:       false,
			wantReason:      "path_denied",
		},
		{
			name:            "DeniedWithoutConfig",
			allowedBasePath: "", // No config injection
			filePath:        "/workspace/poc/README.md",
			wantAllow:       false,
			wantReason:      "path_denied", // Falls back to __UNCONFIGURED__ sentinel
		},
		{
			name:            "DifferentBasePathAllowed",
			allowedBasePath: "/home/user/project",
			filePath:        "/home/user/project/src/main.go",
			wantAllow:       true,
			wantReason:      "allowed",
		},
		{
			name:            "DifferentBasePathDenied",
			allowedBasePath: "/home/user/project",
			filePath:        "/home/user/other/secret.txt",
			wantAllow:       false,
			wantReason:      "path_denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg []OPAEngineConfig
			if tt.allowedBasePath != "" {
				cfg = append(cfg, OPAEngineConfig{AllowedBasePath: tt.allowedBasePath})
			}
			engine, err := NewOPAEngine(tmpDir, cfg...)
			if err != nil {
				t.Fatalf("Failed to create OPA engine: %v", err)
			}
			defer engine.Close()

			input := OPAInput{
				SPIFFEID: "spiffe://test/agent",
				Tool:     "read",
				Action:   "execute",
				Params: map[string]interface{}{
					"file_path": tt.filePath,
				},
			}

			allowed, reason, err := engine.Evaluate(input)
			if err != nil {
				t.Errorf("Evaluate failed: %v", err)
			}
			if allowed != tt.wantAllow {
				t.Errorf("Expected allow=%v, got %v (reason: %s)", tt.wantAllow, allowed, reason)
			}
			if reason != tt.wantReason {
				t.Errorf("Expected reason=%s, got %s", tt.wantReason, reason)
			}
		})
	}
}

// TestOPAEnginePerformance verifies sub-millisecond evaluation latency
func TestOPAEnginePerformance(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "test_policy.rego")

	policyContent := `package mcp
default allow = {
	"allow": true,
	"reason": "allowed"
}
`
	if err := os.WriteFile(policyPath, []byte(policyContent), 0644); err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}

	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	input := OPAInput{
		SPIFFEID: "spiffe://test/agent",
		Tool:     "test_tool",
		Action:   "execute",
	}

	// Warm up
	for i := 0; i < 10; i++ {
		_, _, _ = engine.Evaluate(input)
	}

	// Measure average latency over 100 evaluations
	start := time.Now()
	iterations := 100
	for i := 0; i < iterations; i++ {
		_, _, err := engine.Evaluate(input)
		if err != nil {
			t.Fatalf("Evaluation failed: %v", err)
		}
	}
	elapsed := time.Since(start)
	avgLatency := elapsed / time.Duration(iterations)

	t.Logf("Average evaluation latency: %v", avgLatency)

	// Verify < 1ms (target ~40us, but allow 1ms for test environment variance)
	if avgLatency > 1*time.Millisecond {
		t.Errorf("Expected latency < 1ms, got %v", avgLatency)
	}
}

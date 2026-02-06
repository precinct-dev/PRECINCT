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

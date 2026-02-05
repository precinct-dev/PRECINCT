package middleware

import (
	"os"
	"path/filepath"
	"testing"
)

func TestToolRegistryLoadConfig(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	config := `tools:
  - name: "test_tool"
    description: "Test tool"
    hash: "abc123"
    risk_level: "low"
    requires_step_up: false
  - name: "high_risk_tool"
    description: "High risk tool"
    hash: "def456"
    risk_level: "critical"
    requires_step_up: true
`

	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Create registry
	registry, err := NewToolRegistry("", configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	// Verify tools loaded
	if len(registry.tools) != 2 {
		t.Errorf("Expected 2 tools, got %d", len(registry.tools))
	}

	// Verify test_tool
	tool, exists := registry.GetToolDefinition("test_tool")
	if !exists {
		t.Error("test_tool not found")
	}
	if tool.Hash != "abc123" {
		t.Errorf("Expected hash abc123, got %s", tool.Hash)
	}
	if tool.RequiresStepUp {
		t.Error("test_tool should not require step-up")
	}

	// Verify high_risk_tool
	tool, exists = registry.GetToolDefinition("high_risk_tool")
	if !exists {
		t.Error("high_risk_tool not found")
	}
	if !tool.RequiresStepUp {
		t.Error("high_risk_tool should require step-up")
	}
}

func TestToolRegistryHashVerification(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	config := `tools:
  - name: "test_tool"
    description: "Test tool"
    hash: "correct_hash"
    risk_level: "low"
    requires_step_up: false
`

	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	registry, err := NewToolRegistry("", configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	tests := []struct {
		name         string
		toolName     string
		providedHash string
		wantAllowed  bool
		wantReason   string
	}{
		{
			name:         "CorrectHash",
			toolName:     "test_tool",
			providedHash: "correct_hash",
			wantAllowed:  true,
			wantReason:   "correct_hash",
		},
		{
			name:         "NoHashProvided",
			toolName:     "test_tool",
			providedHash: "",
			wantAllowed:  true,
			wantReason:   "correct_hash",
		},
		{
			name:         "WrongHash",
			toolName:     "test_tool",
			providedHash: "wrong_hash",
			wantAllowed:  false,
			wantReason:   "hash_mismatch",
		},
		{
			name:         "UnknownTool",
			toolName:     "unknown_tool",
			providedHash: "",
			wantAllowed:  false,
			wantReason:   "tool_not_found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := registry.VerifyTool(tt.toolName, tt.providedHash)
			if allowed != tt.wantAllowed {
				t.Errorf("VerifyTool() allowed = %v, want %v", allowed, tt.wantAllowed)
			}
			if reason != tt.wantReason {
				t.Errorf("VerifyTool() reason = %v, want %v", reason, tt.wantReason)
			}
		})
	}
}

func TestComputeHash(t *testing.T) {
	description := "Test tool"
	inputSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"param1": map[string]interface{}{
				"type": "string",
			},
		},
	}

	hash1 := ComputeHash(description, inputSchema)
	hash2 := ComputeHash(description, inputSchema)

	// Hash should be deterministic
	if hash1 != hash2 {
		t.Error("ComputeHash should be deterministic")
	}

	// Hash should be different for different inputs
	hash3 := ComputeHash("Different description", inputSchema)
	if hash1 == hash3 {
		t.Error("ComputeHash should produce different hashes for different inputs")
	}

	// Hash should be 64 characters (SHA-256 in hex)
	if len(hash1) != 64 {
		t.Errorf("Hash should be 64 characters, got %d", len(hash1))
	}
}

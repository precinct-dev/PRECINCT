//go:build integration
// +build integration

package integration

import (
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
	"github.com/RamXX/agentic_reference_architecture/POC/internal/testutil"
)

// TestEmbeddedOPAWithRealPolicies tests OPA engine with actual policy files
func TestEmbeddedOPAWithRealPolicies(t *testing.T) {
	// Use real policy directory
	policyDir := testutil.OPAPolicyDir()
	basePath := testutil.ProjectRoot()

	engine, err := middleware.NewOPAEngine(policyDir, middleware.OPAEngineConfig{
		AllowedBasePath: basePath,
	})
	if err != nil {
		t.Fatalf("Failed to create OPA engine with real policies: %v", err)
	}
	defer engine.Close()

	tests := []struct {
		name      string
		input     middleware.OPAInput
		wantAllow bool
	}{
		{
			name: "AllowedResearcherRead",
			input: middleware.OPAInput{
				SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Tool:     "read",
				Action:   "execute",
				Method:   "POST",
				Path:     "/mcp",
				Params: map[string]interface{}{
					"file_path": basePath + "/README.md",
				},
			},
			wantAllow: true,
		},
		{
			name: "DeniedResearcherWrite",
			input: middleware.OPAInput{
				SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Tool:     "file_write",
				Action:   "execute",
				Method:   "POST",
				Path:     "/mcp",
				Params:   map[string]interface{}{},
			},
			wantAllow: false,
		},
		{
			name: "AllowedGatewayRead",
			input: middleware.OPAInput{
				SPIFFEID: "spiffe://poc.local/gateways/mcp-security-gateway/dev",
				Tool:     "read",
				Action:   "execute",
				Method:   "POST",
				Path:     "/mcp",
				Params: map[string]interface{}{
					"file_path": basePath + "/README.md",
				},
			},
			wantAllow: true,
		},
		{
			name: "DeniedUnknownAgent",
			input: middleware.OPAInput{
				SPIFFEID: "spiffe://poc.local/agents/unknown/dev",
				Tool:     "file_read",
				Action:   "execute",
				Method:   "POST",
				Path:     "/mcp",
				Params:   map[string]interface{}{},
			},
			wantAllow: false,
		},
		{
			name: "DeniedPathOutsidePOC",
			input: middleware.OPAInput{
				SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Tool:     "read",
				Action:   "execute",
				Method:   "POST",
				Path:     "/mcp",
				Params: map[string]interface{}{
					"file_path": "/etc/passwd",
				},
			},
			wantAllow: false,
		},
		{
			name: "DeniedBashNotInAllowedTools",
			input: middleware.OPAInput{
				SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Tool:     "bash",
				Action:   "execute",
				Method:   "POST",
				Path:     "/mcp",
				Params: map[string]interface{}{
					"command": "ls",
				},
				StepUpToken: "valid-step-up-token",
			},
			wantAllow: false, // bash not in allowed_tools for researcher
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason, err := engine.Evaluate(tt.input)
			if err != nil {
				t.Errorf("Evaluation failed: %v", err)
			}
			if allowed != tt.wantAllow {
				t.Errorf("Expected allow=%v, got %v (reason: %s)", tt.wantAllow, allowed, reason)
			}
		})
	}
}

// TestEmbeddedOPAPerformance tests performance with real policies
func TestEmbeddedOPAPerformance(t *testing.T) {
	policyDir := testutil.OPAPolicyDir()
	basePath := testutil.ProjectRoot()

	engine, err := middleware.NewOPAEngine(policyDir, middleware.OPAEngineConfig{
		AllowedBasePath: basePath,
	})
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	input := middleware.OPAInput{
		SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Tool:     "read",
		Action:   "execute",
		Method:   "POST",
		Path:     "/mcp",
		Params: map[string]interface{}{
			"file_path": basePath + "/README.md",
		},
	}

	// Warm up
	for i := 0; i < 10; i++ {
		_, _, _ = engine.Evaluate(input)
	}

	// Measure performance (requirement: < 1ms, target ~40us)
	const iterations = 1000
	start := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < iterations; i++ {
			_, _, err := engine.Evaluate(input)
			if err != nil {
				t.Fatalf("Evaluation failed: %v", err)
			}
		}
	})

	avgNs := start.NsPerOp()
	avgMs := float64(avgNs) / 1000000.0

	t.Logf("Average latency: %.3f ms (%.1f µs)", avgMs, float64(avgNs)/1000.0)

	if avgMs > 1.0 {
		t.Errorf("Expected latency < 1ms, got %.3f ms", avgMs)
	}
}

// TestEmbeddedOPAStartupFailure tests gateway refuses to start without policies
func TestEmbeddedOPAStartupFailure(t *testing.T) {
	// Create empty directory
	tmpDir := t.TempDir()

	// Engine should fail to start
	_, err := middleware.NewOPAEngine(tmpDir)
	if err == nil {
		t.Error("Expected error when policy files missing, got nil")
	}

	t.Logf("Correctly failed with: %v", err)
}

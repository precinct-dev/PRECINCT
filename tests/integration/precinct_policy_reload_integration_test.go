// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinct-dev/precinct/internal/precinctcli"
)

func TestPrecinctPolicyReloadIntegration_ModifyGrantsAndVerifyEffect(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	grantPath := filepath.Join(pocDir(), "config", "opa", "tool_grants.yaml")
	original, err := os.ReadFile(grantPath)
	if err != nil {
		t.Fatalf("read tool_grants.yaml: %v", err)
	}
	originalSig, err := os.ReadFile(grantPath + ".sig")
	if err != nil {
		t.Fatalf("read tool_grants.yaml.sig: %v", err)
	}

	t.Cleanup(func() {
		_ = os.WriteFile(grantPath, original, 0644)
		_ = os.WriteFile(grantPath+".sig", originalSig, 0644)
		restore := exec.Command("go", "run", "./cli/precinct", "policy", "reload", "--confirm", "--format", "json")
		restore.Dir = pocDir()
		_, _ = restore.CombinedOutput()
	})

	spiffeID := "spiffe://poc.local/agents/mcp-client/policy-reload-integration/dev"
	tool := "read"
	params := `{"file_path":"/app/README.md","offset":1,"limit":2}`

	// Baseline: the offline engine should deny at layer 5 because no grant exists yet.
	before, err := precinctcli.RunPolicyTestOffline(
		spiffeID,
		tool,
		params,
		filepath.Join(pocDir(), "config", "opa"),
		filepath.Join(pocDir(), "config", "tool-registry.yaml"),
	)
	if err != nil {
		t.Fatalf("offline policy test before reload: %v", err)
	}
	if before.Verdict != "DENIED" || before.BlockingLayer != 5 {
		t.Fatalf("expected pre-reload deny at layer 5, got %+v", before)
	}

	injection := `
  - spiffe_pattern: "spiffe://poc.local/agents/mcp-client/policy-reload-integration/dev"
    description: "Policy reload integration test grant"
    allowed_tools:
      - read
    max_data_classification: internal
    requires_approval_for: []
`

	originalText := string(original)
	updatedText := strings.Replace(originalText, "\n# Data classification levels", injection+"\n# Data classification levels", 1)
	if updatedText == originalText {
		t.Fatalf("failed to inject integration grant into tool_grants.yaml")
	}
	if err := os.WriteFile(grantPath, []byte(updatedText), 0644); err != nil {
		t.Fatalf("write modified tool_grants.yaml: %v", err)
	}
	signWithProjectAttestationKey(t, grantPath)

	// Reload through the CLI command under test.
	cmd := exec.Command("go", "run", "./cli/precinct", "policy", "reload", "--confirm", "--format", "json")
	cmd.Dir = pocDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("precinct policy reload failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var reloadResp struct {
		Status        string `json:"status"`
		RegistryTools int    `json:"registry_tools"`
		OPAPolicies   int    `json:"opa_policies"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &reloadResp); err != nil {
		t.Fatalf("invalid policy reload json: %v raw=%q", err, stdout.String())
	}
	if reloadResp.Status != "reloaded" {
		t.Fatalf("expected status=reloaded, got %+v", reloadResp)
	}
	if reloadResp.OPAPolicies <= 0 {
		t.Fatalf("expected opa_policies > 0, got %+v", reloadResp)
	}

	// Post-reload: the same policy data should now evaluate as allowed.
	// This verifies the semantic change separately from the signed hot-reload path above.
	after, err := precinctcli.RunPolicyTestOffline(
		spiffeID,
		tool,
		params,
		filepath.Join(pocDir(), "config", "opa"),
		filepath.Join(pocDir(), "config", "tool-registry.yaml"),
	)
	if err != nil {
		t.Fatalf("offline policy test after reload: %v", err)
	}
	if after.Verdict != "ALLOWED" || after.BlockingLayer != 0 {
		t.Fatalf("expected post-reload allow, got %+v", after)
	}
}

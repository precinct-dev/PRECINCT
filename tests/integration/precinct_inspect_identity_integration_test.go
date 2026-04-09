// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"testing"
)

func TestPrecinctInspectIdentityIntegration_JSON(t *testing.T) {
	cmd := exec.Command(
		"go", "run", "./cli/precinct", "inspect", "identity",
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"--format", "json",
	)
	cmd.Dir = pocDir()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("precinct inspect identity failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var parsed struct {
		SPIFFEID      string `json:"spiffe_id"`
		MatchedGrants []struct {
			SPIFFEPattern string `json:"spiffe_pattern"`
		} `json:"matched_grants"`
		Tools []struct {
			Tool             string `json:"tool"`
			Authorized       bool   `json:"authorized"`
			RiskLevel        string `json:"risk_level"`
			RequiresStepUp   bool   `json:"requires_step_up"`
			ApprovalRequired bool   `json:"approval_required"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("expected valid JSON, got err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if parsed.SPIFFEID == "" || len(parsed.MatchedGrants) == 0 || len(parsed.Tools) == 0 {
		t.Fatalf("unexpected inspect identity result: %+v", parsed)
	}

	var sawRead, sawBash bool
	for _, tool := range parsed.Tools {
		switch tool.Tool {
		case "read":
			sawRead = true
			if !tool.Authorized {
				t.Fatalf("expected read to be authorized: %+v", tool)
			}
		case "bash":
			sawBash = true
			if tool.Authorized {
				t.Fatalf("expected bash to be unauthorized: %+v", tool)
			}
			if !tool.ApprovalRequired {
				t.Fatalf("expected bash to require approval: %+v", tool)
			}
		}
	}
	if !sawRead || !sawBash {
		t.Fatalf("expected both read and bash in tool output: %+v", parsed.Tools)
	}
}

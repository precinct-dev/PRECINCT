// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func snapshotConfig(projectRoot, snapshotsDir string) ([]SnapshotItem, error) {
	if err := os.MkdirAll(snapshotsDir, 0o755); err != nil {
		return nil, err
	}

	type item struct {
		srcRel  string
		dstName string
		isDir   bool
	}
	plan := []item{
		{srcRel: "config/tool-registry.yaml", dstName: "tool-registry.yaml"},
		{srcRel: "config/opa/tool_grants.yaml", dstName: "tool_grants.yaml"},
		{srcRel: "config/risk_thresholds.yaml", dstName: "risk_thresholds.yaml"},
		{srcRel: "config/spiffe-ids.yaml", dstName: "spiffe-ids.yaml"},
		{srcRel: "config/destinations.yaml", dstName: "destinations.yaml"},
		{srcRel: "config/opa/mcp_policy.rego", dstName: "mcp_policy.rego"},
		{srcRel: ".cosign", dstName: ".cosign", isDir: true},
	}

	var out []SnapshotItem
	for _, p := range plan {
		src := filepath.Join(projectRoot, p.srcRel)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(snapshotsDir, p.dstName)
		if p.isDir {
			items, err := CopyDirRecursive(src, dst)
			if err != nil {
				return nil, err
			}
			out = append(out, items...)
			continue
		}
		it, err := CopyFile(src, dst)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, nil
}

func configReferencesForControl(c Control) []string {
	mw := ""
	if c.Middleware != nil {
		mw = strings.TrimSpace(*c.Middleware)
	}

	// References are paths within <framework>/config-snapshots/.
	switch mw {
	case "spiffe_auth":
		return []string{"spiffe-ids.yaml"}
	case "opa":
		return []string{"mcp_policy.rego", "tool_grants.yaml", "tool-registry.yaml", "destinations.yaml"}
	case "tool_registry":
		return []string{"tool-registry.yaml"}
	case "dlp":
		return []string{"risk_thresholds.yaml"}
	case "deep_scan":
		return []string{"mcp_policy.rego"}
	case "session_context":
		return []string{"mcp_policy.rego", "risk_thresholds.yaml"}
	case "size_limit", "rate_limiter", "circuit_breaker":
		return []string{"risk_thresholds.yaml"}
	default:
		// Supply chain or unknown: include what we have.
		return []string{"tool-registry.yaml", "tool_grants.yaml", "risk_thresholds.yaml", "spiffe-ids.yaml", "mcp_policy.rego"}
	}
}

func testReferencesForControl(c Control) []string {
	mw := ""
	if c.Middleware != nil {
		mw = strings.TrimSpace(*c.Middleware)
	}
	if mw == "" {
		return []string{"tests/"}
	}
	// Mirrors tools/compliance/generate.py build_evidence_reference behavior.
	return []string{
		fmt.Sprintf("internal/gateway/middleware/%s_test.go", mw),
		"tests/integration/",
	}
}

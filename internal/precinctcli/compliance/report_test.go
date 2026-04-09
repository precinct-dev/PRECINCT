// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateComplianceReport_InvokesPythonAndBuildsMarkdown(t *testing.T) {
	origRun := runExternalCommand
	origResolve := resolvePythonInterpreterFn
	t.Cleanup(func() {
		runExternalCommand = origRun
		resolvePythonInterpreterFn = origResolve
	})

	resolvePythonInterpreterFn = func(projectRoot string) (string, error) {
		return "python3-test", nil
	}

	runExternalCommand = func(ctx context.Context, cwd, name string, args ...string) (string, string, error) {
		if name != "python3-test" {
			t.Fatalf("expected python3-test, got %s", name)
		}
		if len(args) < 7 || !strings.HasSuffix(args[0], "tools/compliance/generate.py") {
			t.Fatalf("unexpected args: %+v", args)
		}
		outDir := ""
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "--output-dir" {
				outDir = args[i+1]
				break
			}
		}
		if outDir == "" {
			t.Fatalf("missing --output-dir in args: %+v", args)
		}
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			t.Fatalf("mkdir out dir: %v", err)
		}
		csv := "control_id,framework,framework_requirement,status,evidence_reference,recommendation,control_name\n" +
			"GW-AUTH-001,SOC2,CC6.1,Implemented,audit-log,none,SPIFFE mTLS Authentication\n"
		if err := os.WriteFile(filepath.Join(outDir, "compliance-report.csv"), []byte(csv), 0o644); err != nil {
			t.Fatalf("write csv: %v", err)
		}
		if err := os.WriteFile(filepath.Join(outDir, "compliance-report.xlsx"), []byte("xlsx"), 0o644); err != nil {
			t.Fatalf("write xlsx: %v", err)
		}
		if err := os.WriteFile(filepath.Join(outDir, "compliance-summary.pdf"), []byte("pdf"), 0o644); err != nil {
			t.Fatalf("write pdf: %v", err)
		}
		return "ok", "", nil
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	outBase := t.TempDir()

	out, err := GenerateComplianceReport(ReportParams{
		Framework: "soc2",
		Output:    "markdown",
		OutputDir: outBase,
		WorkDir:   wd,
	})
	if err != nil {
		t.Fatalf("GenerateComplianceReport: %v", err)
	}
	if !strings.HasSuffix(out.OutputPath, ".md") {
		t.Fatalf("expected markdown output path, got %+v", out)
	}
	b, err := os.ReadFile(out.OutputPath)
	if err != nil {
		t.Fatalf("read markdown: %v", err)
	}
	if !strings.Contains(string(b), "# Compliance Report (SOC2)") {
		t.Fatalf("unexpected markdown content: %s", string(b))
	}
}

func TestGenerateComplianceReport_JSONFiltersFramework(t *testing.T) {
	origRun := runExternalCommand
	origResolve := resolvePythonInterpreterFn
	t.Cleanup(func() {
		runExternalCommand = origRun
		resolvePythonInterpreterFn = origResolve
	})

	resolvePythonInterpreterFn = func(projectRoot string) (string, error) {
		return "python3-test", nil
	}
	runExternalCommand = func(ctx context.Context, cwd, name string, args ...string) (string, string, error) {
		outDir := ""
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "--output-dir" {
				outDir = args[i+1]
				break
			}
		}
		csv := "control_id,framework,framework_requirement,status,evidence_reference,recommendation,control_name\n" +
			"GW-AUTH-001,SOC2,CC6.1,Implemented,audit-log,none,Auth One\n" +
			"GW-AUTH-001,GDPR,Art. 32,Implemented,audit-log,none,Auth One\n"
		_ = os.MkdirAll(outDir, 0o755)
		_ = os.WriteFile(filepath.Join(outDir, "compliance-report.csv"), []byte(csv), 0o644)
		_ = os.WriteFile(filepath.Join(outDir, "compliance-report.xlsx"), []byte("xlsx"), 0o644)
		_ = os.WriteFile(filepath.Join(outDir, "compliance-summary.pdf"), []byte("pdf"), 0o644)
		return "ok", "", nil
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	out, err := GenerateComplianceReport(ReportParams{
		Framework: "soc2",
		Output:    "json",
		OutputDir: t.TempDir(),
		WorkDir:   wd,
	})
	if err != nil {
		t.Fatalf("GenerateComplianceReport: %v", err)
	}

	b, err := os.ReadFile(out.OutputPath)
	if err != nil {
		t.Fatalf("read json report: %v", err)
	}
	var parsed struct {
		Framework string              `json:"framework"`
		Rows      []map[string]string `json:"rows"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("parse json report: %v raw=%s", err, string(b))
	}
	if parsed.Framework != "SOC2" {
		t.Fatalf("expected SOC2 framework, got %+v", parsed)
	}
	if len(parsed.Rows) != 1 || parsed.Rows[0]["framework"] != "SOC2" {
		t.Fatalf("expected only SOC2 rows, got %+v", parsed.Rows)
	}
}

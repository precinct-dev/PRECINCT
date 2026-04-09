// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var resolvePythonInterpreterFn = resolvePythonInterpreter

type ReportParams struct {
	Framework    string
	Output       string
	OutputDir    string
	AuditLogPath string
	WorkDir      string
}

type ReportResult struct {
	Framework      string
	Output         string
	ReportDir      string
	CSVPath        string
	XLSXPath       string
	PDFPath        string
	OutputPath     string
	PythonExecPath string
}

func GenerateComplianceReport(p ReportParams) (ReportResult, error) {
	framework := strings.ToLower(strings.TrimSpace(p.Framework))
	if framework == "" {
		return ReportResult{}, fmt.Errorf("framework is required")
	}

	output := strings.ToLower(strings.TrimSpace(p.Output))
	if output == "" {
		output = "pdf"
	}
	if output != "pdf" && output != "json" && output != "markdown" {
		return ReportResult{}, fmt.Errorf("invalid output %q (expected pdf|json|markdown)", output)
	}

	wd := strings.TrimSpace(p.WorkDir)
	if wd == "" {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			return ReportResult{}, err
		}
	}

	projectRoot, err := FindProjectRoot(wd)
	if err != nil {
		return ReportResult{}, err
	}

	pythonExec, err := resolvePythonInterpreterFn(projectRoot)
	if err != nil {
		return ReportResult{}, err
	}

	baseOut := strings.TrimSpace(p.OutputDir)
	if baseOut == "" {
		baseOut = "reports"
	}
	if !filepath.IsAbs(baseOut) {
		baseOut = filepath.Join(projectRoot, baseOut)
	}
	if err := os.MkdirAll(baseOut, 0o755); err != nil {
		return ReportResult{}, err
	}

	ts := time.Now().Format("20060102-150405")
	reportDir := filepath.Join(baseOut, fmt.Sprintf("compliance-report-%s", ts))
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return ReportResult{}, err
	}

	auditLogPath := strings.TrimSpace(p.AuditLogPath)
	if auditLogPath == "" {
		auditLogPath = "/tmp/audit.jsonl"
	}

	scriptPath := filepath.Join(projectRoot, "tools", "compliance", "generate.py")
	args := []string{
		scriptPath,
		"--audit-log", auditLogPath,
		"--project-root", projectRoot,
		"--output-dir", reportDir,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, stderr, err := runExternalCommand(ctx, projectRoot, pythonExec, args...)
	if err != nil {
		return ReportResult{}, fmt.Errorf("generate compliance report: %w (stderr=%s)", err, strings.TrimSpace(stderr))
	}

	csvPath := filepath.Join(reportDir, "compliance-report.csv")
	xlsxPath := filepath.Join(reportDir, "compliance-report.xlsx")
	pdfPath := filepath.Join(reportDir, "compliance-summary.pdf")

	for _, p := range []string{csvPath, xlsxPath, pdfPath} {
		if _, err := os.Stat(p); err != nil {
			return ReportResult{}, fmt.Errorf("expected generated artifact missing: %s", p)
		}
	}

	outPath := pdfPath
	switch output {
	case "json":
		outPath = filepath.Join(reportDir, fmt.Sprintf("compliance-%s.json", framework))
		if err := writeFrameworkJSONReport(csvPath, framework, outPath); err != nil {
			return ReportResult{}, err
		}
	case "markdown":
		outPath = filepath.Join(reportDir, fmt.Sprintf("compliance-%s.md", framework))
		if err := writeFrameworkMarkdownReport(csvPath, framework, outPath); err != nil {
			return ReportResult{}, err
		}
	}

	return ReportResult{
		Framework:      framework,
		Output:         output,
		ReportDir:      reportDir,
		CSVPath:        csvPath,
		XLSXPath:       xlsxPath,
		PDFPath:        pdfPath,
		OutputPath:     outPath,
		PythonExecPath: pythonExec,
	}, nil
}

func resolvePythonInterpreter(projectRoot string) (string, error) {
	venvPython := filepath.Join(projectRoot, "tools", "compliance", ".venv", "bin", "python3")
	if st, err := os.Stat(venvPython); err == nil && !st.IsDir() {
		return venvPython, nil
	}
	return "python3", nil
}

func writeFrameworkJSONReport(csvPath, framework, dstPath string) error {
	rows, err := loadFrameworkRowsFromCSV(csvPath, framework)
	if err != nil {
		return err
	}

	payload := map[string]any{
		"framework": strings.ToUpper(framework),
		"rows":      rows,
	}
	return writeJSON(dstPath, payload)
}

func writeFrameworkMarkdownReport(csvPath, framework, dstPath string) error {
	rows, err := loadFrameworkRowsFromCSV(csvPath, framework)
	if err != nil {
		return err
	}

	columns := []string{
		"control_id",
		"control_name",
		"framework_requirement",
		"status",
		"evidence_reference",
		"recommendation",
	}

	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "# Compliance Report (%s)\n\n", strings.ToUpper(framework))
	_, _ = fmt.Fprintf(&b, "Rows: %d\n\n", len(rows))
	_, _ = fmt.Fprintf(&b, "| %s |\n", strings.Join(columns, " | "))

	divider := make([]string, 0, len(columns))
	for range columns {
		divider = append(divider, "---")
	}
	_, _ = fmt.Fprintf(&b, "| %s |\n", strings.Join(divider, " | "))

	for _, row := range rows {
		vals := make([]string, 0, len(columns))
		for _, col := range columns {
			val := strings.ReplaceAll(row[col], "|", "\\|")
			vals = append(vals, val)
		}
		_, _ = fmt.Fprintf(&b, "| %s |\n", strings.Join(vals, " | "))
	}

	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dstPath, []byte(b.String()), 0o644)
}

func loadFrameworkRowsFromCSV(csvPath, framework string) ([]map[string]string, error) {
	f, err := os.Open(csvPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()

	reader := csv.NewReader(f)
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read csv header: %w", err)
	}
	for i, h := range header {
		header[i] = strings.TrimSpace(h)
	}

	wantFramework := strings.ToUpper(strings.TrimSpace(framework))
	var out []map[string]string
	for {
		rec, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("read csv record: %w", err)
		}
		row := make(map[string]string, len(header))
		for i, key := range header {
			if i < len(rec) {
				row[key] = rec[i]
			}
		}
		if strings.EqualFold(strings.TrimSpace(row["framework"]), wantFramework) {
			out = append(out, row)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i]["control_id"] != out[j]["control_id"] {
			return out[i]["control_id"] < out[j]["control_id"]
		}
		return out[i]["framework_requirement"] < out[j]["framework_requirement"]
	})
	return out, nil
}

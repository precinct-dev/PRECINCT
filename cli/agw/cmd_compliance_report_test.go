package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/agw/compliance"
)

func TestAgwComplianceReport_InvokesGenerator(t *testing.T) {
	orig := complianceGenerateReport
	t.Cleanup(func() { complianceGenerateReport = orig })

	called := false
	complianceGenerateReport = func(p compliance.ReportParams) (compliance.ReportResult, error) {
		called = true
		if p.Framework != "soc2" || p.Output != "pdf" {
			t.Fatalf("unexpected params: %+v", p)
		}
		return compliance.ReportResult{
			Framework:  "soc2",
			Output:     "pdf",
			OutputPath: "/tmp/reports/compliance-report-20260211/compliance-summary.pdf",
		}, nil
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"compliance", "report", "--framework", "soc2", "--output", "pdf"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !called {
		t.Fatalf("expected report generator to be invoked")
	}
	if strings.TrimSpace(stdout.String()) != "/tmp/reports/compliance-report-20260211/compliance-summary.pdf" {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
}

func TestAgwComplianceReport_FrameworkRequired(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"compliance", "report", "--output", "pdf"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--framework is required") {
		t.Fatalf("expected framework required error, got %q", stderr.String())
	}
}

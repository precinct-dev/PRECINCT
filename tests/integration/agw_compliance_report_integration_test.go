//go:build integration
// +build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgwComplianceReportIntegration_SOC2PDF(t *testing.T) {
	projectRoot := pocDir()
	outBase := t.TempDir()

	cmd := exec.Command(
		"go", "run", "./cmd/agw",
		"compliance", "report",
		"--framework", "soc2",
		"--output", "pdf",
		"--output-dir", outBase,
	)
	cmd.Dir = projectRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agw compliance report failed: %v\nOutput:\n%s", err, string(out))
	}

	pdfPath := strings.TrimSpace(string(out))
	if pdfPath == "" {
		t.Fatalf("expected report path in stdout, got empty output")
	}
	if filepath.Ext(pdfPath) != ".pdf" {
		t.Fatalf("expected pdf output path, got %q", pdfPath)
	}
	if _, err := os.Stat(pdfPath); err != nil {
		t.Fatalf("expected PDF report at %s: %v", pdfPath, err)
	}

	reportDir := filepath.Dir(pdfPath)
	for _, name := range []string{"compliance-report.csv", "compliance-report.xlsx", "compliance-summary.pdf"} {
		p := filepath.Join(reportDir, name)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing generated report artifact %s: %v", p, err)
		}
	}
}

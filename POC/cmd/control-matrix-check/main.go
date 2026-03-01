package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/controlmatrix"
)

func main() {
	var (
		matrixPath = flag.String("matrix", "docs/security/artifacts/control-verification-matrix.v1.json", "Path to control verification matrix JSON")
		outputDir  = flag.String("output-dir", "build/security-scan/latest", "Directory where control verification report artifacts are written")
		root       = flag.String("root", ".", "Repository root path")
	)
	flag.Parse()

	result, err := controlmatrix.CheckRepo(*root, *matrixPath, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "control matrix check failed: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "unable to create output directory: %v\n", err)
		os.Exit(1)
	}

	jsonPath := filepath.Join(*outputDir, "control-verification-report.json")
	mdPath := filepath.Join(*outputDir, "control-verification-report.md")

	raw, err := json.MarshalIndent(result.Report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to marshal report JSON: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(jsonPath, raw, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "unable to write report JSON: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(mdPath, []byte(controlmatrix.RenderMarkdown(result.Report)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "unable to write report markdown: %v\n", err)
		os.Exit(1)
	}

	if len(result.Report.Issues) == 0 {
		fmt.Printf("[PASS] control matrix check passed (controls=%d report_json=%s report_md=%s)\n", result.Report.Summary.ControlsTotal, jsonPath, mdPath)
		return
	}

	sort.Slice(result.Report.Issues, func(i, j int) bool {
		if result.Report.Issues[i].ControlID == result.Report.Issues[j].ControlID {
			return result.Report.Issues[i].Code < result.Report.Issues[j].Code
		}
		return result.Report.Issues[i].ControlID < result.Report.Issues[j].ControlID
	})

	fmt.Fprintf(os.Stderr, "[FAIL] control matrix violations detected (count=%d report_json=%s report_md=%s)\n", len(result.Report.Issues), jsonPath, mdPath)
	for _, issue := range result.Report.Issues {
		controlID := issue.ControlID
		if controlID == "" {
			controlID = "GLOBAL"
		}
		target := issue.Target
		if target == "" {
			target = "-"
		}
		fmt.Fprintf(os.Stderr, " - [%s] %s target=%s: %s\n", issue.Code, controlID, target, issue.Message)
	}
	os.Exit(1)
}

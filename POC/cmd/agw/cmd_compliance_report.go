package main

import (
	"fmt"
	"strings"

	"github.com/precinct-dev/PRECINCT/POC/internal/agw/compliance"
	"github.com/spf13/cobra"
)

var complianceGenerateReport = compliance.GenerateComplianceReport

func newComplianceReportCmd() *cobra.Command {
	var framework string
	var output string
	var outputDir string
	var auditLogPath string

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate formatted compliance report artifacts",
		RunE: func(cmd *cobra.Command, args []string) error {
			fw := strings.ToLower(strings.TrimSpace(framework))
			if fw == "" {
				return fmt.Errorf("--framework is required (e.g. --framework soc2)")
			}

			out, err := complianceGenerateReport(compliance.ReportParams{
				Framework:    fw,
				Output:       output,
				OutputDir:    outputDir,
				AuditLogPath: auditLogPath,
			})
			if err != nil {
				return err
			}

			_, _ = fmt.Fprintln(cmd.OutOrStdout(), out.OutputPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&framework, "framework", "", "Framework to report on (e.g. soc2)")
	cmd.Flags().StringVar(&output, "output", "pdf", "Report output type: pdf|json|markdown")
	cmd.Flags().StringVar(&outputDir, "output-dir", "reports", "Base output directory for generated reports")
	cmd.Flags().StringVar(&auditLogPath, "audit-log", "/tmp/audit.jsonl", "Local audit JSONL path")
	return cmd
}

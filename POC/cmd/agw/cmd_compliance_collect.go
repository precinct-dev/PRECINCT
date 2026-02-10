package main

import (
	"fmt"
	"strings"

	"github.com/example/agentic-security-poc/internal/agw/compliance"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newComplianceCollectCmd() *cobra.Command {
	var framework string
	var outputDir string
	var auditLogPath string

	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect evidence into a timestamped package directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			fw := strings.ToLower(strings.TrimSpace(framework))
			if fw == "" {
				return fmt.Errorf("--framework is required (e.g. --framework soc2)")
			}

			// Reuse the gateway URL config (root flag/env) so callers can keep
			// one consistent config surface. (Not required for collection logic,
			// but used by integration tests and future subcommands.)
			_ = viper.GetString(cfgGatewayURL)

			res, err := compliance.CollectEvidencePackage(compliance.CollectParams{
				Framework:    fw,
				OutputDir:    outputDir,
				AuditLogPath: auditLogPath,
			})
			if err != nil {
				return err
			}

			// AC9: demoable. Print the created evidence directory path.
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), res.EvidenceDir)
			return nil
		},
	}

	cmd.Flags().StringVar(&framework, "framework", "", "Framework to collect evidence for (e.g. soc2)")
	cmd.Flags().StringVar(&outputDir, "output-dir", "reports", "Base output directory (timestamped evidence dir created inside)")
	cmd.Flags().StringVar(&auditLogPath, "audit-log", "/tmp/audit.jsonl", "Local audit JSONL path (falls back to docker compose logs if missing)")
	return cmd
}


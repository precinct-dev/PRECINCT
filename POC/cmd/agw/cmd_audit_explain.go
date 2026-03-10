package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/precinct-dev/PRECINCT/POC/internal/agw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newAuditExplainCmd() *cobra.Command {
	var source string
	var auditLogPath string

	cmd := &cobra.Command{
		Use:   "explain <decision-id>",
		Short: "Show a layer-by-layer trace for a decision",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			decisionID := strings.TrimSpace(args[0])
			if decisionID == "" {
				return fmt.Errorf("decision-id is required")
			}

			projectRoot, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("resolve working directory: %w", err)
			}

			if strings.TrimSpace(source) == "" {
				source = strings.TrimSpace(viper.GetString(cfgAuditSource))
			}
			if strings.TrimSpace(source) == "" {
				source = "docker"
			}

			if strings.TrimSpace(auditLogPath) == "" {
				auditLogPath = strings.TrimSpace(viper.GetString(cfgAuditLogPath))
			}
			if strings.TrimSpace(auditLogPath) == "" {
				auditLogPath = "/tmp/audit.jsonl"
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
			defer cancel()

			entries, err := agw.LoadAuditEntries(ctx, source, projectRoot, auditLogPath)
			if err != nil {
				return err
			}

			filtered, err := agw.FilterAuditEntries(entries, agw.AuditSearchFilter{
				DecisionID: decisionID,
			})
			if err != nil {
				return err
			}
			if len(filtered) == 0 {
				return fmt.Errorf("no audit entries found for decision-id %q", decisionID)
			}

			out, err := agw.BuildAuditExplain(filtered, decisionID)
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderAuditExplainTable(out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderAuditExplainJSON(out)
				if err != nil {
					return fmt.Errorf("render json: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write(b)
			default:
				return fmt.Errorf("invalid --format %q (expected json|table)", format)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&source, "source", "", "Audit source: docker|file (default: AGW_AUDIT_SOURCE or docker)")
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "", "Audit JSONL path for --source file (default: AGW_AUDIT_LOG_PATH or /tmp/audit.jsonl)")
	return cmd
}

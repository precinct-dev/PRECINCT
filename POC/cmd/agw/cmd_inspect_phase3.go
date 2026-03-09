package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/example/agentic-security-poc/internal/agw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newInspectIngressCmd() *cobra.Command {
	return newInspectPlaneCmd(
		"ingress",
		"uasgs_plane_ingress",
		"Inspect ingress plane admission decisions from audit events",
	)
}

func newInspectContextCmd() *cobra.Command {
	return newInspectPlaneCmd(
		"context",
		"uasgs_plane_context",
		"Inspect context/memory plane admission decisions from audit events",
	)
}

func newInspectModelCmd() *cobra.Command {
	return newInspectPlaneCmd(
		"model",
		"uasgs_plane_model",
		"Inspect model plane mediation decisions from audit events",
	)
}

func newInspectRuleOpsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ruleops",
		Short: "Inspect DLP RuleOps lifecycle state (draft/approved/active)",
		RunE: func(cmd *cobra.Command, args []string) error {
			gatewayURL := strings.TrimSpace(viper.GetString(cfgGatewayURL))
			if gatewayURL == "" {
				return fmt.Errorf("gateway URL is empty (set --gateway-url or AGW_GATEWAY_URL)")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			client := agw.NewClient(gatewayURL)
			out, err := client.ListDLPRulesets(ctx)
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderDLPRulesetsTable(out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderDLPRulesetsJSON(out)
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
}

func newInspectPlaneCmd(useName, planeAction, short string) *cobra.Command {
	var (
		lastWindow   string
		deniedOnly   bool
		source       string
		auditLogPath string
	)

	cmd := &cobra.Command{
		Use:   useName,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
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
				DeniedOnly: deniedOnly,
				Last:       lastWindow,
				Now:        time.Now(),
			})
			if err != nil {
				return err
			}

			planeEntries := make([]map[string]any, 0, len(filtered))
			for _, entry := range filtered {
				if actionValue(entry) == planeAction {
					planeEntries = append(planeEntries, entry)
				}
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderAuditSearchTable(planeEntries)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderAuditSearchJSON(planeEntries)
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

	cmd.Flags().StringVar(&lastWindow, "last", "1h", "Time window (e.g. 5m, 1h, 24h, 7d)")
	cmd.Flags().BoolVar(&deniedOnly, "denied", false, "Show only denied/failed plane decisions")
	cmd.Flags().StringVar(&source, "source", "", "Audit source: docker|file (default: AGW_AUDIT_SOURCE or docker)")
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "", "Audit JSONL path for --source file (default: AGW_AUDIT_LOG_PATH or /tmp/audit.jsonl)")
	return cmd
}

func actionValue(entry map[string]any) string {
	v, ok := entry["action"]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

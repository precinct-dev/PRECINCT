// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/precinct-dev/precinct/internal/precinctcli"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newAuditSearchCmd() *cobra.Command {
	var decisionID string
	var spiffeID string
	var toolName string
	var lastWindow string
	var deniedOnly bool
	var source string
	var auditLogPath string

	cmd := &cobra.Command{
		Use:   "search",
		Short: "Search gateway audit entries",
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

			entries, err := precinctcli.LoadAuditEntries(ctx, source, projectRoot, auditLogPath)
			if err != nil {
				return err
			}

			filtered, err := precinctcli.FilterAuditEntries(entries, precinctcli.AuditSearchFilter{
				DecisionID: decisionID,
				SPIFFEID:   spiffeID,
				Tool:       toolName,
				DeniedOnly: deniedOnly,
				Last:       lastWindow,
				Now:        time.Now(),
			})
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := precinctcli.RenderAuditSearchTable(filtered)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := precinctcli.RenderAuditSearchJSON(filtered)
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

	cmd.Flags().StringVar(&decisionID, "decision-id", "", "Filter by decision ID")
	cmd.Flags().StringVar(&spiffeID, "spiffe-id", "", "Filter by SPIFFE ID")
	cmd.Flags().StringVar(&toolName, "tool", "", "Filter by tool name")
	cmd.Flags().StringVar(&lastWindow, "last", "", "Time window (e.g. 5m, 1h, 24h, 7d)")
	cmd.Flags().BoolVar(&deniedOnly, "denied", false, "Show only denied/failed requests")
	cmd.Flags().StringVar(&source, "source", "", "Audit source: docker|file (default: PRECINCT_AUDIT_SOURCE or docker)")
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "", "Audit JSONL path for --source file (default: PRECINCT_AUDIT_LOG_PATH or /tmp/audit.jsonl)")
	return cmd
}

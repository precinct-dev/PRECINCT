// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/precinct-dev/precinct/internal/precinctcli"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var gdprExportDSARPackage = precinctcli.ExportGDPRDSAR

func newGDPRAuditCmd() *cobra.Command {
	var source string
	var auditLogPath string
	var projectRoot string
	var reportsDir string

	cmd := &cobra.Command{
		Use:   "audit <spiffe-id>",
		Short: "Export a DSAR package for one SPIFFE identity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spiffeID := strings.TrimSpace(args[0])
			if spiffeID == "" {
				return errors.New("spiffe-id is empty")
			}

			keydbURL := strings.TrimSpace(viper.GetString(cfgKeyDBURL))
			if keydbURL == "" {
				return errors.New("keydb URL is empty (set --keydb-url or PRECINCT_KEYDB_URL)")
			}

			if strings.TrimSpace(source) == "" {
				source = strings.TrimSpace(viper.GetString(cfgAuditSource))
			}
			if strings.TrimSpace(auditLogPath) == "" {
				auditLogPath = strings.TrimSpace(viper.GetString(cfgAuditLogPath))
			}
			if strings.TrimSpace(projectRoot) == "" {
				projectRoot = "."
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()

			result, err := gdprExportDSARPackage(ctx, precinctcli.GDPRAuditParams{
				SPIFFEID:         spiffeID,
				KeyDBURL:         keydbURL,
				AuditSource:      source,
				AuditLogPath:     auditLogPath,
				AuditProjectRoot: projectRoot,
				ReportsDir:       reportsDir,
				OPAPolicyDir:     strings.TrimSpace(viper.GetString(cfgOPAPolicyDir)),
				ToolRegistryPath: strings.TrimSpace(viper.GetString(cfgToolRegistryPath)),
			})
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := precinctcli.RenderDSARExportTable(result)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := precinctcli.RenderDSARExportJSON(result)
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

	cmd.Flags().StringVar(&source, "source", "", "Audit source: docker|file (default: PRECINCT_AUDIT_SOURCE or docker)")
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "", "Audit JSONL path for --source file (default: PRECINCT_AUDIT_LOG_PATH or /tmp/audit.jsonl)")
	cmd.Flags().StringVar(&projectRoot, "project-root", ".", "Project root for docker compose audit log reads")
	cmd.Flags().StringVar(&reportsDir, "output-dir", "reports", "Directory for DSAR package output")
	return cmd
}

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/example/agentic-security-poc/internal/agw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newDLPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dlp",
		Short: "Operate DLP ruleset lifecycle (create/update/approve/promote/rollback)",
	}
	cmd.AddCommand(newDLPListCmd())
	cmd.AddCommand(newDLPActiveCmd())
	cmd.AddCommand(newDLPUpsertCmd())
	cmd.AddCommand(newDLPApproveCmd())
	cmd.AddCommand(newDLPPromoteCmd())
	cmd.AddCommand(newDLPRollbackCmd())
	return cmd
}

func newDLPListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List DLP rulesets and active pin",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDLPCommand(cmd, func(ctx context.Context, client *agw.Client) (agw.DLPRulesetsOutput, error) {
				return client.ListDLPRulesets(ctx)
			})
		},
	}
}

func newDLPActiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "active",
		Short: "Show active DLP ruleset pin (version + digest)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDLPCommand(cmd, func(ctx context.Context, client *agw.Client) (agw.DLPRulesetsOutput, error) {
				return client.GetActiveDLPRuleset(ctx)
			})
		},
	}
}

func newDLPUpsertCmd() *cobra.Command {
	var (
		version            string
		credentialPatterns []string
		piiPatterns        []string
		suspiciousPatterns []string
	)
	cmd := &cobra.Command{
		Use:   "upsert",
		Short: "Create or update a DLP ruleset draft",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(version) == "" {
				return errors.New("--version is required")
			}
			return runDLPCommand(cmd, func(ctx context.Context, client *agw.Client) (agw.DLPRulesetsOutput, error) {
				return client.UpsertDLPRuleset(ctx, agw.DLPRulesetUpsertInput{
					Version:            version,
					CredentialPatterns: credentialPatterns,
					PIIPatterns:        piiPatterns,
					SuspiciousPatterns: suspiciousPatterns,
				})
			})
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Ruleset version (required)")
	cmd.Flags().StringArrayVar(&credentialPatterns, "credential-pattern", nil, "Additional credential regex pattern (repeatable)")
	cmd.Flags().StringArrayVar(&piiPatterns, "pii-pattern", nil, "Additional PII regex pattern (repeatable)")
	cmd.Flags().StringArrayVar(&suspiciousPatterns, "suspicious-pattern", nil, "Additional suspicious regex pattern (repeatable)")
	return cmd
}

func newDLPApproveCmd() *cobra.Command {
	var (
		version   string
		approver  string
		signature string
	)
	cmd := &cobra.Command{
		Use:   "approve",
		Short: "Approve/sign a DLP ruleset",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(version) == "" {
				return errors.New("--version is required")
			}
			if strings.TrimSpace(approver) == "" {
				return errors.New("--approver is required")
			}
			if strings.TrimSpace(signature) == "" {
				return errors.New("--signature is required")
			}
			return runDLPCommand(cmd, func(ctx context.Context, client *agw.Client) (agw.DLPRulesetsOutput, error) {
				return client.ApproveDLPRuleset(ctx, version, approver, signature)
			})
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Ruleset version (required)")
	cmd.Flags().StringVar(&approver, "approver", "", "Approver identity (required)")
	cmd.Flags().StringVar(&signature, "signature", "", "Signature or attestation reference (required)")
	return cmd
}

func newDLPPromoteCmd() *cobra.Command {
	var version string
	cmd := &cobra.Command{
		Use:   "promote",
		Short: "Promote an approved/signed ruleset to active",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(version) == "" {
				return errors.New("--version is required")
			}
			return runDLPCommand(cmd, func(ctx context.Context, client *agw.Client) (agw.DLPRulesetsOutput, error) {
				return client.PromoteDLPRuleset(ctx, version)
			})
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "Ruleset version (required)")
	return cmd
}

func newDLPRollbackCmd() *cobra.Command {
	var targetVersion string
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Rollback to previous (or target) approved ruleset",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDLPCommand(cmd, func(ctx context.Context, client *agw.Client) (agw.DLPRulesetsOutput, error) {
				return client.RollbackDLPRuleset(ctx, targetVersion)
			})
		},
	}
	cmd.Flags().StringVar(&targetVersion, "target-version", "", "Optional explicit target ruleset version")
	return cmd
}

func runDLPCommand(cmd *cobra.Command, fn func(context.Context, *agw.Client) (agw.DLPRulesetsOutput, error)) error {
	gatewayURL := strings.TrimSpace(viper.GetString(cfgGatewayURL))
	if gatewayURL == "" {
		return errors.New("gateway URL is empty (set --gateway-url or AGW_GATEWAY_URL)")
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
	defer cancel()

	client := agw.NewClient(gatewayURL)
	out, err := fn(ctx, client)
	if err != nil {
		return fmt.Errorf("dlp operation failed: %w", err)
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
}

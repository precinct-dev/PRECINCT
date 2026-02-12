package main

import (
	"fmt"
	"strings"

	"github.com/example/agentic-security-poc/internal/agw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newPolicyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list [spiffe-id]",
		Short: "List grants from policy config files",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opaPolicyDir := strings.TrimSpace(viper.GetString(cfgOPAPolicyDir))
			toolRegistryPath := strings.TrimSpace(viper.GetString(cfgToolRegistryPath))

			spiffeID := ""
			if len(args) == 1 {
				spiffeID = strings.TrimSpace(args[0])
			}

			out, err := agw.ListPolicyGrants(opaPolicyDir, toolRegistryPath, spiffeID)
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderPolicyListTable(out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderPolicyListJSON(out)
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

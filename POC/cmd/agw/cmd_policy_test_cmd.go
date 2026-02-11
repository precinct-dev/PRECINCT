package main

import (
	"fmt"
	"strings"

	"github.com/example/agentic-security-poc/internal/agw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newPolicyTestCmd() *cobra.Command {
	var params string

	cmd := &cobra.Command{
		Use:   "test <spiffe-id> <tool>",
		Short: "Dry-run policy checks through offline layers 1-6",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spiffeID := strings.TrimSpace(args[0])
			tool := strings.TrimSpace(args[1])

			opaPolicyDir := strings.TrimSpace(viper.GetString(cfgOPAPolicyDir))
			toolRegistryPath := strings.TrimSpace(viper.GetString(cfgToolRegistryPath))

			out, err := agw.RunPolicyTestOffline(spiffeID, tool, params, opaPolicyDir, toolRegistryPath)
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderPolicyTestOfflineTable(out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderPolicyTestOfflineJSON(out)
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

	cmd.Flags().StringVar(&params, "params", "", "JSON object with request parameters for DLP simulation")
	return cmd
}

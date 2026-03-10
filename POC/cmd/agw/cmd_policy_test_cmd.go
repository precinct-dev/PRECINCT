package main

import (
	"fmt"
	"strings"

	"github.com/precinct-dev/PRECINCT/POC/internal/agw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newPolicyTestCmd() *cobra.Command {
	var params string
	var runtime bool
	var sessionID string

	cmd := &cobra.Command{
		Use:   "test <spiffe-id> <tool>",
		Short: "Dry-run policy checks through offline or full runtime layers",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spiffeID := strings.TrimSpace(args[0])
			tool := strings.TrimSpace(args[1])

			opaPolicyDir := strings.TrimSpace(viper.GetString(cfgOPAPolicyDir))
			toolRegistryPath := strings.TrimSpace(viper.GetString(cfgToolRegistryPath))

			var (
				out agw.PolicyTestOfflineOutput
				err error
			)
			if runtime {
				keydbURL := strings.TrimSpace(viper.GetString(cfgKeyDBURL))
				gatewayURL := strings.TrimSpace(viper.GetString(cfgGatewayURL))
				out, err = agw.RunPolicyTestRuntime(
					spiffeID,
					tool,
					params,
					opaPolicyDir,
					toolRegistryPath,
					keydbURL,
					gatewayURL,
					sessionID,
				)
			} else {
				out, err = agw.RunPolicyTestOffline(spiffeID, tool, params, opaPolicyDir, toolRegistryPath)
			}
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
	cmd.Flags().BoolVar(&runtime, "runtime", false, "Include runtime layers 7-13 (requires running KeyDB and gateway)")
	cmd.Flags().StringVar(&sessionID, "session-id", "", "Session ID for runtime session-risk lookup (layer 7)")
	return cmd
}

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/agw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newPolicyReloadCmd() *cobra.Command {
	var confirm bool

	cmd := &cobra.Command{
		Use:   "reload",
		Short: "Reload gateway tool registry and OPA policies",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirm {
				return errors.New("--confirm is required for policy reload")
			}

			gatewayURL := strings.TrimSpace(viper.GetString(cfgGatewayURL))
			if gatewayURL == "" {
				return errors.New("gateway URL is empty (set --gateway-url or AGW_GATEWAY_URL)")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			client := agw.NewClient(gatewayURL)
			out, err := client.ReloadPolicy(ctx)
			if err != nil {
				reason := policyReloadReason(err)
				if policyReloadLooksLikeCosignError(reason) {
					return fmt.Errorf(
						"ERROR: Policy reload failed\nReason: %s\n\nTo fix: Sign the config file with cosign:\n  cosign sign-blob --key <private-key> config/tool-registry.yaml > config/tool-registry.yaml.sig",
						reason,
					)
				}
				return fmt.Errorf("policy reload failed: %w", err)
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderPolicyReloadTable(out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderPolicyReloadJSON(out)
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

	cmd.Flags().BoolVar(&confirm, "confirm", false, "Confirm policy reload")
	return cmd
}

func policyReloadReason(err error) string {
	msg := strings.TrimSpace(err.Error())
	if idx := strings.Index(msg, ": "); idx >= 0 && strings.HasPrefix(msg, "gateway returned status_code=") {
		return strings.TrimSpace(msg[idx+2:])
	}
	return msg
}

func policyReloadLooksLikeCosignError(reason string) bool {
	s := strings.ToLower(reason)
	return strings.Contains(s, "signature verification failed") ||
		strings.Contains(s, ".sig file") ||
		strings.Contains(s, "failed to read signature file")
}

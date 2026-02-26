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

func newResetCircuitBreakerCmd() *cobra.Command {
	var all bool
	var confirm bool

	cmd := &cobra.Command{
		Use:   "circuit-breaker [tool]",
		Short: "Reset gateway circuit breaker state to closed",
		Args: func(cmd *cobra.Command, args []string) error {
			if all {
				if len(args) != 0 {
					return errors.New("when using --all, do not provide a tool argument")
				}
				return nil
			}
			if len(args) != 1 {
				return errors.New("expected tool argument (or use --all)")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			gatewayURL := strings.TrimSpace(viper.GetString(cfgGatewayURL))
			if gatewayURL == "" {
				return errors.New("gateway URL is empty (set --gateway-url or AGW_GATEWAY_URL)")
			}

			if all && !confirm {
				return errors.New("--all requires --confirm")
			}

			targetTool := "*"
			if !all {
				targetTool = strings.TrimSpace(args[0])
				if targetTool == "" {
					return errors.New("tool is empty")
				}
			}

			if !confirm && !all {
				msg := fmt.Sprintf("This will reset circuit breaker for %s. Continue? [y/N] ", targetTool)
				ok, err := promptYesNo(cmd.InOrStdin(), cmd.ErrOrStderr(), msg)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("aborted")
				}
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			client := agw.NewClient(gatewayURL)
			out, err := client.ResetCircuitBreakers(ctx, targetTool)
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderCircuitBreakerResetTable(out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderCircuitBreakerResetJSON(out)
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

	cmd.Flags().BoolVar(&all, "all", false, "Reset all circuit breakers")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "Confirm reset without prompt")
	return cmd
}

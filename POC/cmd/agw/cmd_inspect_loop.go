package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/example/agentic-security-poc/internal/agw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newInspectLoopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "loop [run-id]",
		Short: "Inspect loop governor run state and immutable limits",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			gatewayURL := strings.TrimSpace(viper.GetString(cfgGatewayURL))
			if gatewayURL == "" {
				return fmt.Errorf("gateway URL is empty (set --gateway-url or AGW_GATEWAY_URL)")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			c := agw.NewClient(gatewayURL)

			var out agw.LoopRunsOutput
			var err error
			if len(args) == 1 {
				out, err = c.GetLoopRun(ctx, strings.TrimSpace(args[0]))
			} else {
				out, err = c.ListLoopRuns(ctx)
			}
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderLoopRunsTable(out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderLoopRunsJSON(out)
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

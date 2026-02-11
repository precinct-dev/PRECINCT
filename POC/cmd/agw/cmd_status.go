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

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show gateway health",
		RunE: func(cmd *cobra.Command, args []string) error {
			gatewayURL := strings.TrimSpace(viper.GetString(cfgGatewayURL))
			if gatewayURL == "" {
				return errors.New("gateway URL is empty (set --gateway-url or AGW_GATEWAY_URL)")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()

			client := agw.NewClient(gatewayURL)
			h, err := client.GetHealth(ctx)
			if err != nil {
				return err
			}

			status := "unknown"
			if h.Status != "" {
				status = strings.ToLower(h.Status)
			}

			out := agw.StatusOutput{
				Components: []agw.ComponentStatus{
					{
						Name:   "gateway",
						Status: status,
						Details: map[string]any{
							"circuit_breaker": map[string]any{"state": h.CircuitBreakerState},
						},
					},
				},
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderTable(out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderJSON(out)
				if err != nil {
					return fmt.Errorf("render json: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write(b)
			default:
				return fmt.Errorf("invalid --format %q (expected json|table)", format)
			}

			// AC6: Exit 0 if healthy.
			if status != "ok" {
				return fmt.Errorf("gateway not ok: status=%s", status)
			}
			return nil
		},
	}
}


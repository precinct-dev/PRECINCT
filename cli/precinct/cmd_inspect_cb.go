// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/precinct-dev/precinct/internal/precinctcli"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newInspectCircuitBreakerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "circuit-breaker [tool]",
		Short: "Inspect gateway circuit breaker state",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			gatewayURL := strings.TrimSpace(viper.GetString(cfgGatewayURL))
			if gatewayURL == "" {
				return fmt.Errorf("gateway URL is empty (set --gateway-url or PRECINCT_GATEWAY_URL)")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			c := precinctcli.NewClient(gatewayURL)

			var out precinctcli.CircuitBreakersOutput
			if len(args) == 1 {
				tool := strings.TrimSpace(args[0])
				entry, err := c.GetCircuitBreaker(ctx, tool)
				if err != nil {
					return err
				}
				out.CircuitBreakers = append(out.CircuitBreakers, *entry)
			} else {
				entries, err := c.GetCircuitBreakers(ctx)
				if err != nil {
					return err
				}
				out.CircuitBreakers = entries
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := precinctcli.RenderCircuitBreakersTable(out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := precinctcli.RenderCircuitBreakersJSON(out)
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

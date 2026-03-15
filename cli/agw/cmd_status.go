package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/precinct-dev/precinct/internal/agw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show health for gateway + supporting infrastructure",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			component := strings.ToLower(strings.TrimSpace(viper.GetString("component")))
			cfg := agw.DefaultConfig()
			cfg.GatewayURL = strings.TrimSpace(viper.GetString(cfgGatewayURL))
			cfg.KeyDBURL = strings.TrimSpace(viper.GetString(cfgKeyDBURL))
			cfg.PhoenixURL = strings.TrimSpace(viper.GetString(cfgPhoenixURL))
			cfg.OtelHealthURL = strings.TrimSpace(viper.GetString(cfgOtelURL))
			cfg.Component = component

			out, allOK, err := agw.CollectStatus(ctx, cfg, agw.DefaultDeps())
			if err != nil {
				return err
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

			// AC5: Exit code 0 when all components are OK; exit code 1 otherwise.
			if !allOK {
				return errors.New("one or more components not OK")
			}
			return nil
		},
	}
	cmd.Flags().String("component", "", "Show health for a single component (gateway|keydb|spire-server|spike-nexus|phoenix|otel-collector)")
	_ = viper.BindPFlag("component", cmd.Flags().Lookup("component"))
	return cmd
}

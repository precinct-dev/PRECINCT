package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/agw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var collectRepaveStatus = agw.CollectRepaveStatus

func newRepaveStatusCmd() *cobra.Command {
	var stateFile string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show last repave time, image hash comparison, and health per container",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
			defer cancel()

			out, err := collectRepaveStatus(ctx, agw.RepaveStatusParams{
				StateFile: stateFile,
			})
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderRepaveStatusTable(out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderRepaveStatusJSON(out)
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

	cmd.Flags().StringVar(&stateFile, "state-file", ".repave-state.json", "Path to repave state JSON")
	return cmd
}

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

func newInspectSessionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sessions [spiffe-id]",
		Short: "Inspect active session state from KeyDB",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keydbURL := strings.TrimSpace(viper.GetString(cfgKeyDBURL))
			if keydbURL == "" {
				return errors.New("KeyDB URL is empty (set --keydb-url or AGW_KEYDB_URL)")
			}

			var spiffeFilter string
			if len(args) == 1 {
				spiffeFilter = strings.TrimSpace(args[0])
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			kdb, err := agw.NewKeyDB(keydbURL)
			if err != nil {
				return err
			}
			defer func() {
				_ = kdb.Close()
			}()

			sessions, err := kdb.ListSessions(ctx, spiffeFilter)
			if err != nil {
				return err
			}
			out := agw.SessionsOutput{Sessions: sessions}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderSessionsTable(out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderSessionsJSON(out)
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

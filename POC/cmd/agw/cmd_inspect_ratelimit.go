package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/example/agentic-security-poc/internal/agw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newInspectRateLimitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rate-limit [spiffe-id]",
		Short: "Inspect KeyDB rate limit state",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keydbURL := strings.TrimSpace(viper.GetString(cfgKeyDBURL))
			if keydbURL == "" {
				return errors.New("KeyDB URL is empty (set --keydb-url or AGW_KEYDB_URL)")
			}

			rpm := envInt("RATE_LIMIT_RPM", 60)
			burst := envInt("RATE_LIMIT_BURST", 10)

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			kdb, err := agw.NewKeyDB(keydbURL)
			if err != nil {
				return err
			}
			defer kdb.Close()

			var out agw.RateLimitOutput
			if len(args) == 1 {
				spiffeID := strings.TrimSpace(args[0])
				entry, err := kdb.GetRateLimit(ctx, spiffeID, rpm, burst)
				if err != nil {
					return err
				}
				if entry != nil {
					out.RateLimits = append(out.RateLimits, *entry)
				}
			} else {
				entries, err := kdb.ListRateLimits(ctx, rpm, burst)
				if err != nil {
					return err
				}
				out.RateLimits = entries
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderRateLimitTable(out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderRateLimitJSON(out)
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

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}


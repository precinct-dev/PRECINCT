package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/precinct-dev/precinct/internal/precinctcli"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// cfgKeyDBURL is declared in root.go

func newResetRateLimitCmd() *cobra.Command {
	var all bool
	var confirm bool

	cmd := &cobra.Command{
		Use:   "rate-limit [spiffe-id]",
		Short: "Clear KeyDB rate limit counters",
		Args: func(cmd *cobra.Command, args []string) error {
			if all {
				if len(args) != 0 {
					return errors.New("when using --all, do not provide a spiffe-id argument")
				}
				return nil
			}
			if len(args) != 1 {
				return errors.New("expected spiffe-id argument (or use --all)")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			keydbURL := strings.TrimSpace(viper.GetString(cfgKeyDBURL))
			if keydbURL == "" {
				return errors.New("keydb URL is empty (set --keydb-url or PRECINCT_KEYDB_URL)")
			}

			if all && !confirm {
				return errors.New("--all requires --confirm")
			}

			var spiffeID string
			if !all {
				spiffeID = strings.TrimSpace(args[0])
				if spiffeID == "" {
					return errors.New("spiffe-id is empty")
				}
			}

			// Safety prompt unless explicitly confirmed.
			if !confirm && !all {
				msg := fmt.Sprintf("This will reset rate limits for %s. Continue? [y/N] ", spiffeID)
				ok, err := promptYesNo(cmd.InOrStdin(), cmd.ErrOrStderr(), msg)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("aborted")
				}
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()

			kdb, err := precinctcli.NewKeyDB(keydbURL)
			if err != nil {
				return err
			}
			defer func() {
				_ = kdb.Close()
			}()

			if all {
				n, err := kdb.DeleteAllRateLimitKeys(ctx)
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted %d rate limit keys (pattern=ratelimit:*)\n", n)
				return nil
			}

			n, keys, err := kdb.DeleteRateLimitKeysForSPIFFEID(ctx, spiffeID)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted %d rate limit keys for %s (keys=%s)\n", n, spiffeID, strings.Join(keys, ","))
			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "Delete all rate limit keys (ratelimit:*)")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "Confirm deletion without prompt")
	return cmd
}

func promptYesNo(in io.Reader, out io.Writer, prompt string) (bool, error) {
	_, _ = out.Write([]byte(prompt))
	br := bufio.NewReader(in)
	line, err := br.ReadString('\n')
	if err != nil {
		// Treat EOF as "no".
		if strings.TrimSpace(line) == "" {
			return false, nil
		}
	}

	v := strings.ToLower(strings.TrimSpace(line))
	return v == "y" || v == "yes", nil
}

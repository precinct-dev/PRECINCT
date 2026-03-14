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

func newResetSessionCmd() *cobra.Command {
	var all bool
	var confirm bool

	cmd := &cobra.Command{
		Use:   "session [spiffe-id]",
		Short: "Clear session state from KeyDB",
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
				return errors.New("keydb URL is empty (set --keydb-url or AGW_KEYDB_URL)")
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

			if !confirm && !all {
				msg := fmt.Sprintf("This will clear sessions for %s. Continue? [y/N] ", spiffeID)
				ok, err := promptYesNo(cmd.InOrStdin(), cmd.ErrOrStderr(), msg)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("aborted")
				}
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 8*time.Second)
			defer cancel()

			kdb, err := agw.NewKeyDB(keydbURL)
			if err != nil {
				return err
			}
			defer func() {
				_ = kdb.Close()
			}()

			var deleted int64
			var keys []string
			mode := "all"
			if all {
				deleted, keys, err = kdb.DeleteAllSessionKeys(ctx)
				if err != nil {
					return err
				}
			} else {
				mode = "spiffe"
				deleted, keys, err = kdb.DeleteSessionKeysForSPIFFEID(ctx, spiffeID)
				if err != nil {
					return err
				}
			}

			out := agw.SessionResetOutput{
				Mode:     mode,
				SPIFFEID: spiffeID,
				Deleted:  deleted,
				Keys:     keys,
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderSessionResetTable(out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderSessionResetJSON(out)
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

	cmd.Flags().BoolVar(&all, "all", false, "Clear all session:* keys")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "Confirm deletion without prompt")
	return cmd
}

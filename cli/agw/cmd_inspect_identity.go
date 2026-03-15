package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/precinct-dev/precinct/internal/agw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newInspectIdentityCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "identity <spiffe-id>",
		Short: "Inspect effective tool permissions for a SPIFFE ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spiffeID := strings.TrimSpace(args[0])
			opaPolicyDir := strings.TrimSpace(viper.GetString(cfgOPAPolicyDir))
			toolRegistryPath := strings.TrimSpace(viper.GetString(cfgToolRegistryPath))

			out, err := agw.InspectIdentity(spiffeID, opaPolicyDir, toolRegistryPath)
			if err != nil {
				if errors.Is(err, agw.ErrNoMatchingGrants) {
					return fmt.Errorf("no matching grants for %s", spiffeID)
				}
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderIdentityTable(*out)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderIdentityJSON(*out)
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

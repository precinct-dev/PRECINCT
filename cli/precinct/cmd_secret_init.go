package main

import (
	"fmt"

	"github.com/precinct-dev/precinct/internal/spike"
	"github.com/spf13/cobra"
)

func newSecretInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Bootstrap SPIKE Nexus with root policy for local dev",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client := spike.NewClient(spike.DefaultConfig())

			fmt.Fprintln(cmd.OutOrStdout(), "Initializing SPIKE Nexus for local development...")

			if err := client.Init(); err != nil {
				return fmt.Errorf("initialization failed: %w", err)
			}

			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "SUCCESS: SPIKE Nexus initialized")
			fmt.Fprintln(out, "  - Root policy created")
			fmt.Fprintln(out, "  - Local development mode enabled")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Next steps:")
			fmt.Fprintln(out, "  1. Use 'precinct secret put' to seed secrets")
			fmt.Fprintln(out, "  2. Use 'precinct secret issue' to generate test tokens")

			return nil
		},
	}
}

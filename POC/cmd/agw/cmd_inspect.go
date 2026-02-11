package main

import "github.com/spf13/cobra"

func newInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect internal state from supporting systems (KeyDB, SPIRE, ...)",
	}
	cmd.AddCommand(newInspectRateLimitCmd())
	cmd.AddCommand(newInspectCircuitBreakerCmd())
	cmd.AddCommand(newInspectIdentityCmd())
	return cmd
}

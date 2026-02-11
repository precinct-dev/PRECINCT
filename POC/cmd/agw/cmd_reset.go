package main

import "github.com/spf13/cobra"

func newResetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset operational state (mutating commands)",
	}
	cmd.AddCommand(newResetRateLimitCmd())
	return cmd
}


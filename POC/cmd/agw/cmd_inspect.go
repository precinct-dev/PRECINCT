package main

import "github.com/spf13/cobra"

func newInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect internal state from supporting systems (KeyDB, SPIRE, ...)",
	}
	cmd.AddCommand(newInspectRateLimitCmd())
	cmd.AddCommand(newInspectCircuitBreakerCmd())
	cmd.AddCommand(newInspectLoopCmd())
	cmd.AddCommand(newInspectIngressCmd())
	cmd.AddCommand(newInspectContextCmd())
	cmd.AddCommand(newInspectModelCmd())
	cmd.AddCommand(newInspectRuleOpsCmd())
	cmd.AddCommand(newInspectIdentityCmd())
	cmd.AddCommand(newInspectSessionsCmd())
	return cmd
}

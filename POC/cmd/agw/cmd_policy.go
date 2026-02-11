package main

import "github.com/spf13/cobra"

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect and test policy configuration",
	}
	cmd.AddCommand(newPolicyListCmd())
	cmd.AddCommand(newPolicyReloadCmd())
	return cmd
}

package main

import "github.com/spf13/cobra"

func newComplianceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Compliance evidence collection",
	}
	cmd.AddCommand(newComplianceCollectCmd())
	return cmd
}


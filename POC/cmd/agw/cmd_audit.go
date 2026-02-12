package main

import "github.com/spf13/cobra"

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Search and analyze gateway audit events",
	}
	cmd.AddCommand(newAuditSearchCmd())
	cmd.AddCommand(newAuditExplainCmd())
	return cmd
}

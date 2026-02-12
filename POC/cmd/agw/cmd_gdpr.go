package main

import "github.com/spf13/cobra"

func newGDPRCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gdpr",
		Short: "GDPR data subject operations",
	}
	cmd.AddCommand(newGDPRDeleteCmd())
	cmd.AddCommand(newGDPRAuditCmd())
	return cmd
}

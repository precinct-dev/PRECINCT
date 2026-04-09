// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

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

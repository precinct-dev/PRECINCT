// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

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
	cmd.AddCommand(newInspectSessionsCmd())
	return cmd
}

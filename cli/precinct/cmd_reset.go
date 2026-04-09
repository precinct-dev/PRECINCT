// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/spf13/cobra"

func newResetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset operational state (mutating commands)",
	}
	cmd.AddCommand(newResetRateLimitCmd())
	cmd.AddCommand(newResetSessionCmd())
	cmd.AddCommand(newResetCircuitBreakerCmd())
	return cmd
}

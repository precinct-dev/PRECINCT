// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/spf13/cobra"

func newRepaveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repave",
		Short: "Inspect container repave state",
	}
	cmd.AddCommand(newRepaveStatusCmd())
	return cmd
}

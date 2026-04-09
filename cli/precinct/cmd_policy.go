// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/spf13/cobra"

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect and test policy configuration",
	}
	cmd.AddCommand(newPolicyListCmd())
	cmd.AddCommand(newPolicyTestCmd())
	cmd.AddCommand(newPolicyReloadCmd())
	return cmd
}

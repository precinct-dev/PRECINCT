// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

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

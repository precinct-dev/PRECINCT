// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/spf13/cobra"

func newComplianceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Compliance evidence collection",
	}
	cmd.AddCommand(newComplianceCollectCmd())
	cmd.AddCommand(newComplianceReportCmd())
	cmd.AddCommand(newComplianceEvidenceCmd())
	return cmd
}

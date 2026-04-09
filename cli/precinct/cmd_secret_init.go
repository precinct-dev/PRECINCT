// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/precinct-dev/precinct/internal/spike"
	"github.com/spf13/cobra"
)

func newSecretInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Bootstrap SPIKE Nexus with root policy for local dev",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client := spike.NewClient(spike.DefaultConfig())
			out := cmd.OutOrStdout()

			if _, err := fmt.Fprintln(out, "Initializing SPIKE Nexus for local development..."); err != nil {
				return err
			}

			if err := client.Init(); err != nil {
				return fmt.Errorf("initialization failed: %w", err)
			}

			lines := []string{
				"SUCCESS: SPIKE Nexus initialized",
				"  - Root policy created",
				"  - Local development mode enabled",
				"",
				"Next steps:",
				"  1. Use 'precinct secret put' to seed secrets",
				"  2. Use 'precinct secret issue' to generate test tokens",
			}
			for _, line := range lines {
				if _, err := fmt.Fprintln(out, line); err != nil {
					return err
				}
			}

			return nil
		},
	}
}

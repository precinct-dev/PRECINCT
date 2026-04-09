// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/precinct-dev/precinct/internal/spike"
	"github.com/spf13/cobra"
)

func newSecretIssueCmd() *cobra.Command {
	var exp int64
	var scope string

	cmd := &cobra.Command{
		Use:   "issue <ref>",
		Short: "Issue a SPIKE token for testing",
		Long: `Issue a SPIKE token for a previously seeded secret reference.

The generated token can be used in agent requests to the gateway,
which will substitute it with the actual secret value.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]

			client := spike.NewClient(spike.DefaultConfig())
			out := cmd.OutOrStdout()

			if _, err := fmt.Fprintf(out, "Issuing token: ref=%s\n", ref); err != nil {
				return err
			}

			token, err := client.Issue(ref, exp, scope)
			if err != nil {
				return fmt.Errorf("failed to issue token: %w", err)
			}

			lines := []string{
				"SUCCESS: Token issued",
				"",
				"Token:",
			}
			for _, line := range lines {
				if _, err := fmt.Fprintln(out, line); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(out, "  %s\n", token); err != nil {
				return err
			}
			lines = []string{
				"",
				"Use this token in your agent requests to the gateway.",
				"The gateway will substitute it with the actual secret.",
			}
			for _, line := range lines {
				if _, err := fmt.Fprintln(out, line); err != nil {
					return err
				}
			}

			return nil
		},
	}

	cmd.Flags().Int64Var(&exp, "exp", 300, "Token expiry in seconds")
	cmd.Flags().StringVar(&scope, "scope", "", "Scope restrictions for the token")

	return cmd
}

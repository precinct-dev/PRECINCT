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

			fmt.Fprintf(cmd.OutOrStdout(), "Issuing token: ref=%s\n", ref)

			token, err := client.Issue(ref, exp, scope)
			if err != nil {
				return fmt.Errorf("failed to issue token: %w", err)
			}

			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "SUCCESS: Token issued")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Token:")
			fmt.Fprintf(out, "  %s\n", token)
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Use this token in your agent requests to the gateway.")
			fmt.Fprintln(out, "The gateway will substitute it with the actual secret.")

			return nil
		},
	}

	cmd.Flags().Int64Var(&exp, "exp", 300, "Token expiry in seconds")
	cmd.Flags().StringVar(&scope, "scope", "", "Scope restrictions for the token")

	return cmd
}

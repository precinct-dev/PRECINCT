// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/precinct-dev/precinct/internal/precinctcli"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type spireManager interface {
	ListEntries(ctx context.Context) ([]precinctcli.SPIREEntry, error)
	RegisterIdentity(ctx context.Context, name string, selectors []string) (precinctcli.SPIRERegisterResult, error)
}

var newSPIREManager = func() spireManager {
	return precinctcli.NewSPIRECLI()
}

func newIdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Manage SPIRE workload identities",
	}
	cmd.AddCommand(newIdentityListCmd())
	cmd.AddCommand(newIdentityRegisterCmd())
	return cmd
}

func newIdentityListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List SPIRE registration entries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
			defer cancel()

			manager := newSPIREManager()
			entries, err := manager.ListEntries(ctx)
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := precinctcli.RenderSPIREEntriesTable(entries)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := precinctcli.RenderSPIREEntriesJSON(entries)
				if err != nil {
					return fmt.Errorf("render json: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write(b)
			default:
				return fmt.Errorf("invalid --format %q (expected json|table)", format)
			}

			return nil
		},
	}
}

func newIdentityRegisterCmd() *cobra.Command {
	var confirm bool
	var selectors []string

	cmd := &cobra.Command{
		Use:   "register <name>",
		Short: "Register a new SPIRE workload identity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirm {
				return errors.New("--confirm is required for identity register")
			}

			name := strings.TrimSpace(args[0])
			if name == "" {
				return errors.New("name cannot be empty")
			}

			normalizedSelectors := normalizeCLISelectors(selectors)
			if len(normalizedSelectors) == 0 {
				defaultSelector := fmt.Sprintf("docker:label:spiffe-id:%s", name)
				prompted, err := promptSelectors(cmd.InOrStdin(), cmd.ErrOrStderr(), defaultSelector)
				if err != nil {
					return err
				}
				normalizedSelectors = normalizeCLISelectors(prompted)
			}
			if len(normalizedSelectors) == 0 {
				return errors.New("at least one selector is required")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
			defer cancel()

			manager := newSPIREManager()
			result, err := manager.RegisterIdentity(ctx, name, normalizedSelectors)
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := precinctcli.RenderSPIRERegisterTable(result)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := precinctcli.RenderSPIRERegisterJSON(result)
				if err != nil {
					return fmt.Errorf("render json: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write(b)
			default:
				return fmt.Errorf("invalid --format %q (expected json|table)", format)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&confirm, "confirm", false, "Confirm SPIRE identity registration")
	cmd.Flags().StringSliceVar(&selectors, "selector", nil, "Selector to attach (repeatable), e.g. docker:label:spiffe-id:my-workload")
	return cmd
}

func promptSelectors(in io.Reader, out io.Writer, defaultSelector string) ([]string, error) {
	_, _ = fmt.Fprintf(out, "Selectors (comma-separated) [default: %s]: ", defaultSelector)
	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil {
		line = strings.TrimSpace(line)
		if line == "" {
			return []string{defaultSelector}, nil
		}
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return []string{defaultSelector}, nil
	}
	return strings.Split(line, ","), nil
}

func normalizeCLISelectors(selectors []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		selector = strings.TrimSpace(selector)
		if selector == "" {
			continue
		}
		if _, exists := seen[selector]; exists {
			continue
		}
		seen[selector] = struct{}{}
		out = append(out, selector)
	}
	return out
}

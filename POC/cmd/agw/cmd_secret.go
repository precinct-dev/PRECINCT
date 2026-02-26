package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/agw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type spikeManager interface {
	ListSecretRefs(ctx context.Context) ([]agw.SPIKESecretRef, error)
	PutSecret(ctx context.Context, ref, value string) (agw.SPIKESecretPutResult, error)
}

var newSPIKEManager = func() spikeManager {
	return agw.NewSPIKECLI()
}

func newSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage SPIKE secret references",
	}
	cmd.AddCommand(newSecretListCmd())
	cmd.AddCommand(newSecretPutCmd())
	return cmd
}

func newSecretListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List SPIKE secret references (never values)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
			defer cancel()

			manager := newSPIKEManager()
			refs, err := manager.ListSecretRefs(ctx)
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderSecretListTable(refs)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderSecretListJSON(refs)
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

func newSecretPutCmd() *cobra.Command {
	var confirm bool

	cmd := &cobra.Command{
		Use:   "put <ref> <value>",
		Short: "Store a SPIKE secret value by reference",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirm {
				return errors.New("--confirm is required for secret put")
			}

			ref := strings.TrimSpace(args[0])
			value := strings.TrimSpace(args[1])
			if ref == "" {
				return errors.New("ref cannot be empty")
			}
			if value == "" {
				return errors.New("value cannot be empty")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
			defer cancel()

			manager := newSPIKEManager()
			result, err := manager.PutSecret(ctx, ref, value)
			if err != nil {
				return err
			}

			format := strings.ToLower(strings.TrimSpace(viper.GetString(cfgFormat)))
			switch format {
			case "", "table":
				s, err := agw.RenderSecretPutTable(result)
				if err != nil {
					return fmt.Errorf("render table: %w", err)
				}
				_, _ = cmd.OutOrStdout().Write([]byte(s))
			case "json":
				b, err := agw.RenderSecretPutJSON(result)
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

	cmd.Flags().BoolVar(&confirm, "confirm", false, "Confirm secret write")
	return cmd
}

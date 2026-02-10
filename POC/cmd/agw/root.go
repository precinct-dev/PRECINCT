package main

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	cfgGatewayURL = "gateway_url"
	cfgFormat     = "format"
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "agw",
		Short:         "Agentic Gateway operator CLI",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	rootCmd.PersistentFlags().String("gateway-url", "http://localhost:9090", "Gateway base URL")
	rootCmd.PersistentFlags().String("format", "table", "Output format: json|table")

	// Config via flags + env. We keep explicit env bindings to match the story's
	// required variable name (AGW_GATEWAY_URL).
	viper.SetEnvPrefix("AGW")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	_ = viper.BindEnv(cfgGatewayURL, "AGW_GATEWAY_URL")
	_ = viper.BindPFlag(cfgGatewayURL, rootCmd.PersistentFlags().Lookup("gateway-url"))
	_ = viper.BindPFlag(cfgFormat, rootCmd.PersistentFlags().Lookup("format"))

	rootCmd.AddCommand(newStatusCmd())
	return rootCmd
}


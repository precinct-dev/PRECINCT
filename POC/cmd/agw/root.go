package main

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	cfgGatewayURL = "gateway_url"
	cfgKeyDBURL   = "keydb_url"
	cfgPhoenixURL = "phoenix_url"
	cfgOtelURL    = "otel_health_url"
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
	rootCmd.PersistentFlags().String("keydb-url", "redis://localhost:6379", "KeyDB URL (redis://...)")
	rootCmd.PersistentFlags().String("phoenix-url", "http://localhost:6006", "Phoenix base URL")
	rootCmd.PersistentFlags().String("otel-health-url", "http://localhost:13133", "OpenTelemetry Collector health URL")
	rootCmd.PersistentFlags().String("format", "table", "Output format: json|table")

	// Config via flags + env. We keep explicit env bindings to match the story's
	// required variable name (AGW_GATEWAY_URL).
	viper.SetEnvPrefix("AGW")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	_ = viper.BindEnv(cfgGatewayURL, "AGW_GATEWAY_URL")
	_ = viper.BindEnv(cfgKeyDBURL, "AGW_KEYDB_URL")
	_ = viper.BindEnv(cfgPhoenixURL, "AGW_PHOENIX_URL")
	_ = viper.BindEnv(cfgOtelURL, "AGW_OTEL_HEALTH_URL")
	_ = viper.BindPFlag(cfgGatewayURL, rootCmd.PersistentFlags().Lookup("gateway-url"))
	_ = viper.BindPFlag(cfgKeyDBURL, rootCmd.PersistentFlags().Lookup("keydb-url"))
	_ = viper.BindPFlag(cfgPhoenixURL, rootCmd.PersistentFlags().Lookup("phoenix-url"))
	_ = viper.BindPFlag(cfgOtelURL, rootCmd.PersistentFlags().Lookup("otel-health-url"))
	_ = viper.BindPFlag(cfgFormat, rootCmd.PersistentFlags().Lookup("format"))

	rootCmd.AddCommand(newStatusCmd())
	rootCmd.AddCommand(newInspectCmd())
	return rootCmd
}

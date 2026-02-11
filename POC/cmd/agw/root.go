package main

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	cfgGatewayURL       = "gateway_url"
	cfgKeyDBURL         = "keydb_url"
	cfgPhoenixURL       = "phoenix_url"
	cfgOtelURL          = "otel_health_url"
	cfgOPAPolicyDir     = "opa_policy_dir"
	cfgToolRegistryPath = "tool_registry"
	cfgAuditSource      = "audit_source"
	cfgAuditLogPath     = "audit_log_path"
	cfgFormat           = "format"
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
	rootCmd.PersistentFlags().String("opa-policy-dir", "config/opa", "Path to OPA policy directory")
	rootCmd.PersistentFlags().String("tool-registry", "config/tool-registry.yaml", "Path to tool registry YAML")
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
	_ = viper.BindEnv(cfgOPAPolicyDir, "AGW_OPA_POLICY_DIR")
	_ = viper.BindEnv(cfgToolRegistryPath, "AGW_TOOL_REGISTRY")
	_ = viper.BindEnv(cfgAuditSource, "AGW_AUDIT_SOURCE")
	_ = viper.BindEnv(cfgAuditLogPath, "AGW_AUDIT_LOG_PATH")
	_ = viper.BindPFlag(cfgGatewayURL, rootCmd.PersistentFlags().Lookup("gateway-url"))
	_ = viper.BindPFlag(cfgKeyDBURL, rootCmd.PersistentFlags().Lookup("keydb-url"))
	_ = viper.BindPFlag(cfgPhoenixURL, rootCmd.PersistentFlags().Lookup("phoenix-url"))
	_ = viper.BindPFlag(cfgOtelURL, rootCmd.PersistentFlags().Lookup("otel-health-url"))
	_ = viper.BindPFlag(cfgOPAPolicyDir, rootCmd.PersistentFlags().Lookup("opa-policy-dir"))
	_ = viper.BindPFlag(cfgToolRegistryPath, rootCmd.PersistentFlags().Lookup("tool-registry"))
	_ = viper.BindPFlag(cfgFormat, rootCmd.PersistentFlags().Lookup("format"))

	rootCmd.AddCommand(newStatusCmd())
	rootCmd.AddCommand(newComplianceCmd())
	rootCmd.AddCommand(newInspectCmd())
	rootCmd.AddCommand(newAuditCmd())
	rootCmd.AddCommand(newPolicyCmd())
	rootCmd.AddCommand(newResetCmd())
	rootCmd.AddCommand(newSecretCmd())
	return rootCmd
}

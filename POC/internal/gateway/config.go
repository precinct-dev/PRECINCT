package gateway

import (
	"os"
	"strconv"
)

// Config holds gateway configuration
type Config struct {
	Port                   int
	UpstreamURL            string
	OPAEndpoint            string
	ToolRegistryURL        string
	ToolRegistryConfigPath string
	AuditLogPath           string
	OPAPolicyPath          string
	MaxRequestSizeBytes    int64
	SPIFFEMode             string // "dev" or "prod"
	LogLevel               string
	GroqAPIKey             string
	DeepScanTimeout        int // in seconds
}

// ConfigFromEnv loads configuration from environment variables
func ConfigFromEnv() *Config {
	port := 9090
	if p := os.Getenv("PORT"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			port = parsed
		}
	}

	maxRequestSize := int64(10 * 1024 * 1024) // 10MB default
	if s := os.Getenv("MAX_REQUEST_SIZE_BYTES"); s != "" {
		if parsed, err := strconv.ParseInt(s, 10, 64); err == nil {
			maxRequestSize = parsed
		}
	}

	deepScanTimeout := 5 // 5 seconds default
	if t := os.Getenv("DEEP_SCAN_TIMEOUT"); t != "" {
		if parsed, err := strconv.Atoi(t); err == nil {
			deepScanTimeout = parsed
		}
	}

	return &Config{
		Port:                   port,
		UpstreamURL:            getEnvOrDefault("UPSTREAM_URL", "http://host.docker.internal:8080/mcp"),
		OPAEndpoint:            getEnvOrDefault("OPA_ENDPOINT", "http://opa:8181"),
		ToolRegistryURL:        getEnvOrDefault("TOOL_REGISTRY_URL", "http://tool-registry:8080"),
		ToolRegistryConfigPath: getEnvOrDefault("TOOL_REGISTRY_CONFIG_PATH", "/config/tool-registry.yaml"),
		AuditLogPath:           getEnvOrDefault("AUDIT_LOG_PATH", "/var/log/gateway/audit.jsonl"),
		OPAPolicyPath:          getEnvOrDefault("OPA_POLICY_PATH", "/config/opa/mcp_policy.rego"),
		MaxRequestSizeBytes:    maxRequestSize,
		SPIFFEMode:             getEnvOrDefault("SPIFFE_MODE", "dev"),
		LogLevel:               getEnvOrDefault("LOG_LEVEL", "info"),
		GroqAPIKey:             getEnvOrDefault("GROQ_API_KEY", ""),
		DeepScanTimeout:        deepScanTimeout,
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

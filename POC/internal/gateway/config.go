package gateway

import (
	"os"
	"strconv"
)

// Config holds gateway configuration
type Config struct {
	Port                    int
	UpstreamURL             string
	OPAPolicyDir            string
	ToolRegistryConfigPath  string
	AuditLogPath            string
	OPAPolicyPath           string
	MaxRequestSizeBytes     int64
	SPIFFEMode              string // "dev" or "prod"
	LogLevel                string
	GroqAPIKey              string
	DeepScanTimeout         int       // in seconds
	RateLimitRPM            int       // requests per minute per agent
	RateLimitBurst          int       // burst allowance
	CircuitFailureThreshold int       // consecutive failures before opening circuit
	CircuitResetTimeout     int       // seconds in Open before trying Half-Open
	CircuitSuccessThreshold int       // consecutive successes in Half-Open before closing
	HandleTTL               int       // TTL in seconds for response firewall data handles (default 300)
	DestinationsConfigPath  string    // Path to destinations allowlist YAML
	RiskThresholdsPath      string    // Path to risk thresholds YAML
	AllowedBasePath         string    // Base directory for OPA path-based access control (RFA-2jl)
	UIConfigPath            string    // Path to MCP-UI config YAML (RFA-j2d.9)
	UI                      *UIConfig // MCP-UI configuration (RFA-j2d.9)
	UICapabilityGrantsPath  string    // Path to UI capability grants YAML (RFA-j2d.1)
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

	rateLimitRPM := 100 // 100 requests/min default
	if rpm := os.Getenv("RATE_LIMIT_RPM"); rpm != "" {
		if parsed, err := strconv.Atoi(rpm); err == nil {
			rateLimitRPM = parsed
		}
	}

	rateLimitBurst := 20 // 20 burst default
	if burst := os.Getenv("RATE_LIMIT_BURST"); burst != "" {
		if parsed, err := strconv.Atoi(burst); err == nil {
			rateLimitBurst = parsed
		}
	}

	circuitFailureThreshold := 5 // 5 consecutive failures default
	if ft := os.Getenv("CIRCUIT_FAILURE_THRESHOLD"); ft != "" {
		if parsed, err := strconv.Atoi(ft); err == nil {
			circuitFailureThreshold = parsed
		}
	}

	circuitResetTimeout := 30 // 30 seconds default
	if rt := os.Getenv("CIRCUIT_RESET_TIMEOUT"); rt != "" {
		if parsed, err := strconv.Atoi(rt); err == nil {
			circuitResetTimeout = parsed
		}
	}

	circuitSuccessThreshold := 2 // 2 consecutive successes default
	if st := os.Getenv("CIRCUIT_SUCCESS_THRESHOLD"); st != "" {
		if parsed, err := strconv.Atoi(st); err == nil {
			circuitSuccessThreshold = parsed
		}
	}

	handleTTL := 300 // 300 seconds (5 minutes) default per Section 7.8
	if ht := os.Getenv("HANDLE_TTL"); ht != "" {
		if parsed, err := strconv.Atoi(ht); err == nil {
			handleTTL = parsed
		}
	}

	// RFA-2jl: Discover allowed base path from environment or working directory.
	// ALLOWED_BASE_PATH is the single source of truth for OPA path-based access control.
	// Defaults to the current working directory if not set.
	allowedBasePath := os.Getenv("ALLOWED_BASE_PATH")
	if allowedBasePath == "" {
		if wd, err := os.Getwd(); err == nil {
			allowedBasePath = wd
		}
	}

	// RFA-j2d.9: Load MCP-UI config from YAML file (if path set), then apply env overrides.
	uiConfigPath := getEnvOrDefault("UI_CONFIG_PATH", "/config/ui.yaml")
	uiConfig := UIConfigDefaults()
	if uiConfigPath != "" {
		if loaded, err := LoadUIConfig(uiConfigPath); err == nil {
			uiConfig = loaded
		}
		// If file doesn't exist or fails to parse, fall back to defaults (same pattern as destinations/risk config)
	}
	uiConfig.ApplyEnvOverrides()

	return &Config{
		Port:                    port,
		UpstreamURL:             getEnvOrDefault("UPSTREAM_URL", "http://host.docker.internal:8081/mcp"),
		OPAPolicyDir:            getEnvOrDefault("OPA_POLICY_DIR", "/config/opa"),
		ToolRegistryConfigPath:  getEnvOrDefault("TOOL_REGISTRY_CONFIG_PATH", "/config/tool-registry.yaml"),
		AuditLogPath:            getEnvOrDefault("AUDIT_LOG_PATH", "/var/log/gateway/audit.jsonl"),
		OPAPolicyPath:           getEnvOrDefault("OPA_POLICY_PATH", "/config/opa/mcp_policy.rego"),
		MaxRequestSizeBytes:     maxRequestSize,
		SPIFFEMode:              getEnvOrDefault("SPIFFE_MODE", "dev"),
		LogLevel:                getEnvOrDefault("LOG_LEVEL", "info"),
		GroqAPIKey:              getEnvOrDefault("GROQ_API_KEY", ""),
		DeepScanTimeout:         deepScanTimeout,
		RateLimitRPM:            rateLimitRPM,
		RateLimitBurst:          rateLimitBurst,
		CircuitFailureThreshold: circuitFailureThreshold,
		CircuitResetTimeout:     circuitResetTimeout,
		CircuitSuccessThreshold: circuitSuccessThreshold,
		HandleTTL:               handleTTL,
		DestinationsConfigPath:  getEnvOrDefault("DESTINATIONS_CONFIG_PATH", "/config/destinations.yaml"),
		RiskThresholdsPath:      getEnvOrDefault("RISK_THRESHOLDS_PATH", "/config/risk_thresholds.yaml"),
		AllowedBasePath:         allowedBasePath,
		UIConfigPath:            uiConfigPath,
		UI:                      uiConfig,
		UICapabilityGrantsPath:  getEnvOrDefault("UI_CAPABILITY_GRANTS_PATH", "/config/opa/ui_capability_grants.yaml"),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

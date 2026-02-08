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
	DeepScanFallback        string    // "fail_closed" or "fail_open" (default: fail_closed)
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
	SPIKENexusURL           string    // SPIKE Nexus URL for secret redemption via mTLS (RFA-a2y.1)
	SPIFFETrustDomain       string    // SPIFFE trust domain (default: poc.local) (RFA-8z8.1)
	SPIFFEListenPort        int       // Port for HTTPS when SPIFFE_MODE=prod (default: 9443) (RFA-8z8.1)
	OTelEndpoint            string    // OTLP gRPC endpoint for trace export (RFA-m6j.1)
	OTelServiceName         string    // OTel service name (RFA-m6j.1)
	KeyDBURL                string    // KeyDB/Redis URL for session persistence (RFA-hh5.1)
	KeyDBPoolMin            int       // Minimum idle connections in KeyDB pool (default 5)
	KeyDBPoolMax            int       // Maximum connections in KeyDB pool (default 20)
	SessionTTL              int       // Session TTL in seconds (default 3600)
	ToolRegistryPublicKey   string    // RFA-lo1.4: Path to PEM public key for registry attestation (empty = dev mode)
	MCPTransportMode       string    // RFA-9ol: "mcp" (default) or "proxy" (backward compat reverse proxy)
	MCPProbeTimeout        int       // RFA-xhr: per-probe timeout in seconds for transport detection (default: 5)
	MCPDetectTimeout       int       // RFA-xhr: overall detection timeout in seconds (default: 15)
	MCPRequestTimeout      int       // RFA-xhr: per-request timeout in seconds for MCP calls (default: 30)
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

	deepScanFallback := "fail_closed" // default: fail_closed per AC5
	if fb := os.Getenv("DEEP_SCAN_FALLBACK"); fb == "fail_open" || fb == "fail_closed" {
		deepScanFallback = fb
	}

	rateLimitRPM := 600 // 10 req/sec sustained -- protective but won't choke legitimate traffic
	if rpm := os.Getenv("RATE_LIMIT_RPM"); rpm != "" {
		if parsed, err := strconv.Atoi(rpm); err == nil {
			rateLimitRPM = parsed
		}
	}

	rateLimitBurst := 100 // allows brief spikes without immediate throttling
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

	// RFA-hh5.1: KeyDB connection pool configuration
	keyDBPoolMin := 5 // default minimum idle connections
	if pm := os.Getenv("KEYDB_POOL_MIN"); pm != "" {
		if parsed, err := strconv.Atoi(pm); err == nil {
			keyDBPoolMin = parsed
		}
	}

	keyDBPoolMax := 20 // default maximum connections
	if pm := os.Getenv("KEYDB_POOL_MAX"); pm != "" {
		if parsed, err := strconv.Atoi(pm); err == nil {
			keyDBPoolMax = parsed
		}
	}

	sessionTTL := 3600 // default 1 hour
	if ttl := os.Getenv("SESSION_TTL"); ttl != "" {
		if parsed, err := strconv.Atoi(ttl); err == nil {
			sessionTTL = parsed
		}
	}

	// RFA-8z8.1: SPIFFE listen port for HTTPS in prod mode
	spiffeListenPort := 9443
	if sp := os.Getenv("SPIFFE_LISTEN_PORT"); sp != "" {
		if parsed, err := strconv.Atoi(sp); err == nil {
			spiffeListenPort = parsed
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

	// RFA-xhr: MCP transport timeout configuration
	mcpProbeTimeout := 5 // 5 seconds default per AC1
	if pt := os.Getenv("MCP_PROBE_TIMEOUT"); pt != "" {
		if parsed, err := strconv.Atoi(pt); err == nil && parsed > 0 {
			mcpProbeTimeout = parsed
		}
	}

	mcpDetectTimeout := 15 // 15 seconds default per AC2
	if dt := os.Getenv("MCP_DETECT_TIMEOUT"); dt != "" {
		if parsed, err := strconv.Atoi(dt); err == nil && parsed > 0 {
			mcpDetectTimeout = parsed
		}
	}

	mcpRequestTimeout := 30 // 30 seconds default per AC3
	if rt := os.Getenv("MCP_REQUEST_TIMEOUT"); rt != "" {
		if parsed, err := strconv.Atoi(rt); err == nil && parsed > 0 {
			mcpRequestTimeout = parsed
		}
	}

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
		DeepScanFallback:        deepScanFallback,
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
		SPIKENexusURL:           getEnvOrDefault("SPIKE_NEXUS_URL", ""),
		SPIFFETrustDomain:       getEnvOrDefault("SPIFFE_TRUST_DOMAIN", "poc.local"),
		SPIFFEListenPort:        spiffeListenPort,
		OTelEndpoint:            os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), // empty = no-op (AC6)
		OTelServiceName:         getEnvOrDefault("OTEL_SERVICE_NAME", "mcp-security-gateway"),
		KeyDBURL:                getEnvOrDefault("KEYDB_URL", ""),
		KeyDBPoolMin:            keyDBPoolMin,
		KeyDBPoolMax:            keyDBPoolMax,
		SessionTTL:              sessionTTL,
		ToolRegistryPublicKey:   getEnvOrDefault("TOOL_REGISTRY_PUBLIC_KEY", ""),
		MCPTransportMode:       getEnvOrDefault("MCP_TRANSPORT_MODE", "mcp"),
		MCPProbeTimeout:        mcpProbeTimeout,
		MCPDetectTimeout:       mcpDetectTimeout,
		MCPRequestTimeout:      mcpRequestTimeout,
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

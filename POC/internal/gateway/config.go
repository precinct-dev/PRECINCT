package gateway

import (
	"os"
	"strconv"
	"strings"
)

// Config holds gateway configuration
type Config struct {
	Port                   int
	UpstreamURL            string
	OPAPolicyDir           string
	ToolRegistryConfigPath string
	// CapabilityRegistryV2Path is a placeholder for Phase 3 "tool plane" evolution.
	// The POC does not require a V2 registry file to exist; the engine may treat it
	// as optional. (RFA-owgw.6)
	CapabilityRegistryV2Path string
	AuditLogPath             string
	OPAPolicyPath            string
	MaxRequestSizeBytes      int64
	SPIFFEMode               string // "dev" or "prod"
	LogLevel                 string
	GroqAPIKey               string
	GuardModelEndpoint       string // base URL for guard model API (default: Groq)
	GuardModelName           string // model identifier for guard model (default: llama-prompt-guard-2-86m)
	GuardAPIKey              string // API key for guard model (default: falls back to GroqAPIKey)
	// DLP_INJECTION_POLICY env var overrides dlp.injection YAML config (RFA-sd7).
	// Only injection gets an env var override:
	//   - credentials=block is a security invariant (must not be easily toggled via env var)
	//   - pii=flag is rarely changed (deliberate YAML edit required)
	DLPInjectionPolicy              string    // "block" or "flag" (empty = use YAML config)
	DeepScanTimeout                 int       // in seconds
	DeepScanFallback                string    // "fail_closed" or "fail_open" (default: fail_closed)
	RateLimitRPM                    int       // requests per minute per agent
	RateLimitBurst                  int       // burst allowance
	CircuitFailureThreshold         int       // consecutive failures before opening circuit
	CircuitResetTimeout             int       // seconds in Open before trying Half-Open
	CircuitSuccessThreshold         int       // consecutive successes in Half-Open before closing
	HandleTTL                       int       // TTL in seconds for response firewall data handles (default 300)
	DestinationsConfigPath          string    // Path to destinations allowlist YAML
	RiskThresholdsPath              string    // Path to risk thresholds YAML
	ApprovalSigningKey              string    // HMAC signing key for approval capability tokens
	ApprovalDefaultTTL              int       // default approval capability TTL in seconds
	ApprovalMaxTTL                  int       // maximum approval capability TTL in seconds
	AllowedBasePath                 string    // Base directory for OPA path-based access control (RFA-2jl)
	UIConfigPath                    string    // Path to MCP-UI config YAML (RFA-j2d.9)
	UI                              *UIConfig // MCP-UI configuration (RFA-j2d.9)
	UICapabilityGrantsPath          string    // Path to UI capability grants YAML (RFA-j2d.1)
	SPIKENexusURL                   string    // SPIKE Nexus URL for secret redemption via mTLS (RFA-a2y.1)
	SPIFFETrustDomain               string    // SPIFFE trust domain (default: poc.local) (RFA-8z8.1)
	SPIFFEListenPort                int       // Port for HTTPS when SPIFFE_MODE=prod (default: 9443) (RFA-8z8.1)
	OTelEndpoint                    string    // OTLP gRPC endpoint for trace export (RFA-m6j.1)
	OTelServiceName                 string    // OTel service name (RFA-m6j.1)
	KeyDBURL                        string    // KeyDB/Redis URL for session persistence (RFA-hh5.1)
	KeyDBPoolMin                    int       // Minimum idle connections in KeyDB pool (default 5)
	KeyDBPoolMax                    int       // Maximum connections in KeyDB pool (default 20)
	SessionTTL                      int       // Session TTL in seconds (default 3600)
	ToolRegistryPublicKey           string    // RFA-lo1.4: Path to PEM public key for registry attestation (empty = dev mode)
	ModelProviderCatalogPath        string    // RFA-l6h6.2.6: versioned model provider catalog path
	ModelProviderCatalogPublicKey   string    // RFA-l6h6.2.6: PEM public key path for provider catalog signature
	GuardArtifactPath               string    // RFA-l6h6.2.6: local guard artifact path for integrity verification
	GuardArtifactSHA256             string    // RFA-l6h6.2.6: expected SHA-256 digest for guard artifact
	GuardArtifactSignaturePath      string    // RFA-l6h6.2.6: optional signature file path for guard artifact
	GuardArtifactPublicKey          string    // RFA-l6h6.2.6: optional PEM public key path for guard artifact signature
	MCPTransportMode                string    // RFA-9ol: "mcp" (default) or "proxy" (backward compat reverse proxy)
	MCPProbeTimeout                 int       // RFA-xhr: per-probe timeout in seconds for transport detection (default: 5)
	MCPDetectTimeout                int       // RFA-xhr: overall detection timeout in seconds (default: 15)
	MCPRequestTimeout               int       // RFA-xhr: per-request timeout in seconds for MCP calls (default: 30)
	EnforcementProfile              string    // RFA-l6h6.1.6: runtime enforcement profile (dev|prod_standard|prod_regulated_hipaa)
	EnforceModelMediationGate       bool      // RFA-l6h6.1.6: deny direct model egress/bypass when true
	EnforceHIPAAPromptSafetyGate    bool      // RFA-l6h6.1.6: enable HIPAA prompt safety deny gate when true
	ModelPolicyIntentPrependEnabled bool      // RFA-l6h6.9.5: prepend compact policy-intent guidance for OpenAI-compatible model calls
	ProfileMetadataExportPath       string    // RFA-l6h6.1.6: optional JSON export path for active profile metadata
	// EnforcementControlOverrides indicates enforcement control booleans are
	// explicitly set by configuration parsing (for example ConfigFromEnv) and
	// should not fall back to compatibility defaults.
	EnforcementControlOverrides bool
	// Demo-only: allow the gateway to mediate upstream rugpull toggles via
	// /__demo__/rugpull/{on|off}. Disabled by default.
	DemoRugpullAdminEnabled bool
	// Explicit SPIFFE identity allowlist for /admin/* endpoints. Requests from
	// principals outside this list are denied with 403.
	AdminAuthzAllowedSPIFFEIDs []string
	// Path to extension registry YAML for pluggable extension slots.
	// When empty, no extension slots are activated (zero overhead).
	ExtensionRegistryPath string
	// Explicit SPIFFE identity allowlist for upstream mTLS peer pinning.
	// When empty in strict profiles, secure defaults are applied.
	UpstreamAuthzAllowedSPIFFEIDs []string
	// Explicit SPIFFE identity allowlist for KeyDB mTLS peer pinning.
	// When empty in strict profiles, secure defaults are applied.
	KeyDBAuthzAllowedSPIFFEIDs []string
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

	approvalDefaultTTL := 600 // 10 minutes
	if ttl := os.Getenv("APPROVAL_DEFAULT_TTL_SECONDS"); ttl != "" {
		if parsed, err := strconv.Atoi(ttl); err == nil && parsed > 0 {
			approvalDefaultTTL = parsed
		}
	}
	approvalMaxTTL := 3600 // 1 hour
	if ttl := os.Getenv("APPROVAL_MAX_TTL_SECONDS"); ttl != "" {
		if parsed, err := strconv.Atoi(ttl); err == nil && parsed > 0 {
			approvalMaxTTL = parsed
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
	spiffeTrustDomain := getEnvOrDefault("SPIFFE_TRUST_DOMAIN", "poc.local")

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

	demoRugpullAdminEnabled := false
	if v := strings.TrimSpace(os.Getenv("DEMO_RUGPULL_ADMIN_ENABLED")); v != "" {
		if v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") {
			demoRugpullAdminEnabled = true
		}
	}

	adminAuthzAllowedSPIFFEIDs := parseListEnv("ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS")
	if len(adminAuthzAllowedSPIFFEIDs) == 0 {
		adminAuthzAllowedSPIFFEIDs = defaultAdminAuthzAllowedSPIFFEIDs()
	}
	enforcementProfile := getEnvOrDefault("ENFORCEMENT_PROFILE", enforcementProfileDev)

	upstreamAuthzAllowedSPIFFEIDs := parseListEnv("UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS")
	keyDBAuthzAllowedSPIFFEIDs := parseListEnv("KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS")
	if isStrictEnforcementProfileName(enforcementProfile) {
		if len(upstreamAuthzAllowedSPIFFEIDs) == 0 {
			upstreamAuthzAllowedSPIFFEIDs = defaultUpstreamAuthzAllowedSPIFFEIDs(spiffeTrustDomain)
		}
		if len(keyDBAuthzAllowedSPIFFEIDs) == 0 {
			keyDBAuthzAllowedSPIFFEIDs = defaultKeyDBAuthzAllowedSPIFFEIDs(spiffeTrustDomain)
		}
	}

	enforceModelMediationGate := parseEnvBool("ENFORCE_MODEL_MEDIATION_GATE", true)
	enforceHIPAAPromptSafetyGate := parseEnvBool("ENFORCE_HIPAA_PROMPT_SAFETY_GATE", true)
	modelPolicyIntentPrependEnabled := parseEnvBool("MODEL_POLICY_INTENT_PREPEND_ENABLED", false)

	return &Config{
		Port:                            port,
		UpstreamURL:                     getEnvOrDefault("UPSTREAM_URL", "http://host.docker.internal:8081/mcp"),
		OPAPolicyDir:                    getEnvOrDefault("OPA_POLICY_DIR", "/config/opa"),
		ToolRegistryConfigPath:          getEnvOrDefault("TOOL_REGISTRY_CONFIG_PATH", "/config/tool-registry.yaml"),
		CapabilityRegistryV2Path:        getEnvOrDefault("CAPABILITY_REGISTRY_V2_PATH", ""),
		AuditLogPath:                    getEnvOrDefault("AUDIT_LOG_PATH", "/var/log/gateway/audit.jsonl"),
		OPAPolicyPath:                   getEnvOrDefault("OPA_POLICY_PATH", "/config/opa/mcp_policy.rego"),
		MaxRequestSizeBytes:             maxRequestSize,
		SPIFFEMode:                      getEnvOrDefault("SPIFFE_MODE", "dev"),
		LogLevel:                        getEnvOrDefault("LOG_LEVEL", "info"),
		GroqAPIKey:                      getEnvOrDefault("GROQ_API_KEY", ""),
		GuardModelEndpoint:              getEnvOrDefault("GUARD_MODEL_ENDPOINT", "https://api.groq.com/openai/v1"),
		GuardModelName:                  getEnvOrDefault("GUARD_MODEL_NAME", "meta-llama/llama-prompt-guard-2-86m"),
		GuardAPIKey:                     getEnvOrDefault("GUARD_API_KEY", getEnvOrDefault("GROQ_API_KEY", "")),
		DLPInjectionPolicy:              getEnvOrDefault("DLP_INJECTION_POLICY", ""),
		DeepScanTimeout:                 deepScanTimeout,
		DeepScanFallback:                deepScanFallback,
		RateLimitRPM:                    rateLimitRPM,
		RateLimitBurst:                  rateLimitBurst,
		CircuitFailureThreshold:         circuitFailureThreshold,
		CircuitResetTimeout:             circuitResetTimeout,
		CircuitSuccessThreshold:         circuitSuccessThreshold,
		HandleTTL:                       handleTTL,
		DestinationsConfigPath:          getEnvOrDefault("DESTINATIONS_CONFIG_PATH", "/config/destinations.yaml"),
		RiskThresholdsPath:              getEnvOrDefault("RISK_THRESHOLDS_PATH", "/config/risk_thresholds.yaml"),
		ApprovalSigningKey:              getEnvOrDefault("APPROVAL_SIGNING_KEY", ""),
		ApprovalDefaultTTL:              approvalDefaultTTL,
		ApprovalMaxTTL:                  approvalMaxTTL,
		AllowedBasePath:                 allowedBasePath,
		UIConfigPath:                    uiConfigPath,
		UI:                              uiConfig,
		UICapabilityGrantsPath:          getEnvOrDefault("UI_CAPABILITY_GRANTS_PATH", "/config/opa/ui_capability_grants.yaml"),
		SPIKENexusURL:                   getEnvOrDefault("SPIKE_NEXUS_URL", ""),
		SPIFFETrustDomain:               spiffeTrustDomain,
		SPIFFEListenPort:                spiffeListenPort,
		OTelEndpoint:                    os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), // empty = no-op (AC6)
		OTelServiceName:                 getEnvOrDefault("OTEL_SERVICE_NAME", "mcp-security-gateway"),
		KeyDBURL:                        getEnvOrDefault("KEYDB_URL", ""),
		KeyDBPoolMin:                    keyDBPoolMin,
		KeyDBPoolMax:                    keyDBPoolMax,
		SessionTTL:                      sessionTTL,
		ToolRegistryPublicKey:           getEnvOrDefault("TOOL_REGISTRY_PUBLIC_KEY", ""),
		ModelProviderCatalogPath:        strings.TrimSpace(os.Getenv("MODEL_PROVIDER_CATALOG_PATH")),
		ModelProviderCatalogPublicKey:   strings.TrimSpace(os.Getenv("MODEL_PROVIDER_CATALOG_PUBLIC_KEY")),
		GuardArtifactPath:               strings.TrimSpace(os.Getenv("GUARD_ARTIFACT_PATH")),
		GuardArtifactSHA256:             strings.TrimSpace(os.Getenv("GUARD_ARTIFACT_SHA256")),
		GuardArtifactSignaturePath:      strings.TrimSpace(os.Getenv("GUARD_ARTIFACT_SIGNATURE_PATH")),
		GuardArtifactPublicKey:          strings.TrimSpace(os.Getenv("GUARD_ARTIFACT_PUBLIC_KEY")),
		MCPTransportMode:                getEnvOrDefault("MCP_TRANSPORT_MODE", "mcp"),
		MCPProbeTimeout:                 mcpProbeTimeout,
		MCPDetectTimeout:                mcpDetectTimeout,
		MCPRequestTimeout:               mcpRequestTimeout,
		EnforcementProfile:              enforcementProfile,
		EnforceModelMediationGate:       enforceModelMediationGate,
		EnforceHIPAAPromptSafetyGate:    enforceHIPAAPromptSafetyGate,
		ModelPolicyIntentPrependEnabled: modelPolicyIntentPrependEnabled,
		ProfileMetadataExportPath:       strings.TrimSpace(os.Getenv("PROFILE_METADATA_EXPORT_PATH")),
		EnforcementControlOverrides:     true,
		ExtensionRegistryPath:           getEnvOrDefault("EXTENSION_REGISTRY_PATH", ""),
		DemoRugpullAdminEnabled:         demoRugpullAdminEnabled,
		AdminAuthzAllowedSPIFFEIDs:      adminAuthzAllowedSPIFFEIDs,
		UpstreamAuthzAllowedSPIFFEIDs:   upstreamAuthzAllowedSPIFFEIDs,
		KeyDBAuthzAllowedSPIFFEIDs:      keyDBAuthzAllowedSPIFFEIDs,
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func parseEnvBool(key string, defaultValue bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return defaultValue
	}
	if v, err := strconv.ParseBool(raw); err == nil {
		return v
	}
	switch strings.ToLower(raw) {
	case "yes", "y", "on":
		return true
	case "no", "n", "off":
		return false
	default:
		return defaultValue
	}
}

func parseListEnv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		normalized = append(normalized, value)
	}
	return normalized
}

func defaultAdminAuthzAllowedSPIFFEIDs() []string {
	// Keep defaults explicit and minimal for local/dev workflows.
	return []string{
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"spiffe://poc.local/gateways/mcp-security-gateway/dev",
		"spiffe://poc.local/agents/test",
		"spiffe://poc.local/agents/test/dev",
	}
}

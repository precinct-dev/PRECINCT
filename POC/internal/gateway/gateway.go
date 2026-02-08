package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/mcpclient"
	"github.com/example/agentic-security-poc/internal/gateway/middleware"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Gateway represents the MCP security gateway
type Gateway struct {
	config               *Config
	proxy                *httputil.ReverseProxy
	auditor              *middleware.Auditor
	opa                  *middleware.OPAEngine
	registry             *middleware.ToolRegistry
	dlpScanner           middleware.DLPScanner
	deepScanner          *middleware.DeepScanner
	sessionContext       *middleware.SessionContext
	rateLimiter          *middleware.RateLimiter
	circuitBreaker       *middleware.CircuitBreaker
	handleStore          *HandleStore                     // RFA-qq0.16: response firewall data handle cache
	groqGuardClient      middleware.GroqGuardClient       // RFA-qq0.17: guard model client for step-up gating
	destinationAllowlist *middleware.DestinationAllowlist // RFA-qq0.17: destination allowlist
	riskConfig           *middleware.RiskConfig           // RFA-qq0.17: risk scoring thresholds
	uiCapabilityGating   *UICapabilityGating              // RFA-j2d.1: MCP-UI capability gating
	uiResourceControls   *UIResourceControls              // RFA-j2d.2: UI resource content controls
	uiResponseProcessor  *UIResponseProcessor             // RFA-j2d.6: UI response processing pipeline
	spikeRedeemer        middleware.SecretRedeemer        // RFA-a2y.1: SPIKE Nexus or POC secret redeemer
	sessionStore         middleware.SessionStore          // RFA-hh5.1: session persistence store (InMemory or KeyDB)
	spiffeTLS            *SPIFFETLSConfig                 // RFA-8z8.1: SPIFFE mTLS config (nil in dev mode)
	registryStop         func()                           // RFA-dh9: stop function for registry fsnotify watcher
	mcpTransport         mcpclient.Transport              // RFA-0dz: MCP transport (lazy init, auto-detected: Streamable HTTP or Legacy SSE)
	mcpTransportMu       sync.Mutex                       // RFA-9ol: protects lazy initialization of mcpTransport
}

// New creates a new gateway instance
func New(cfg *Config) (*Gateway, error) {
	// Parse upstream URL
	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	// Create components
	auditor, err := middleware.NewAuditor(cfg.AuditLogPath, cfg.OPAPolicyPath, cfg.ToolRegistryConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create auditor: %w", err)
	}
	opa, err := middleware.NewOPAEngine(cfg.OPAPolicyDir, middleware.OPAEngineConfig{
		AllowedBasePath: cfg.AllowedBasePath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA engine: %w", err)
	}
	registry, err := middleware.NewToolRegistry(cfg.ToolRegistryConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create tool registry: %w", err)
	}
	dlpScanner := middleware.NewBuiltInScanner()
	deepScanner := middleware.NewDeepScannerWithConfig(middleware.DeepScannerConfig{
		APIKey:       cfg.GuardAPIKey,
		Timeout:      time.Duration(cfg.DeepScanTimeout) * time.Second,
		FallbackMode: cfg.DeepScanFallback,
		Auditor:      auditor,
		Endpoint:     cfg.GuardModelEndpoint,
		ModelName:    cfg.GuardModelName,
	})
	// RFA-hh5.1: Select session store based on KeyDB availability.
	// RFA-hh5.2: Also select rate limit store. Both share the same redis client
	// when KeyDB is available, enabling distributed session persistence and
	// distributed rate limiting from a single connection pool.
	// RFA-8z8.2: In SPIFFE_MODE=prod, the KeyDB client uses TLS on port 6380.
	// The URL is converted from redis:// to rediss:// and port 6379 to 6380.
	// TLS config uses the same SPIRE X509Source as the gateway's server TLS
	// (set later by EnableSPIFFETLS). In New(), we use the converted URL; the
	// TLS config is applied in EnableKeyDBTLS() after SPIRE is connected.
	var sessionStore middleware.SessionStore
	var rateLimitStore middleware.RateLimitStore
	if cfg.KeyDBURL != "" {
		keyDBURL := KeyDBURLForMode(cfg.KeyDBURL, cfg.SPIFFEMode)
		redisClient := middleware.NewKeyDBClient(keyDBURL, cfg.KeyDBPoolMin, cfg.KeyDBPoolMax)
		sessionStore = middleware.NewKeyDBStoreFromClient(redisClient, cfg.SessionTTL)
		rateLimitStore = middleware.NewKeyDBRateLimitStore(redisClient)
	} else {
		sessionStore = middleware.NewInMemoryStore()
		rateLimitStore = middleware.NewInMemoryRateLimitStore()
	}
	sessionContext := middleware.NewSessionContext(sessionStore)
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimitRPM, cfg.RateLimitBurst, rateLimitStore)

	// Create circuit breaker with audit logging for state transitions
	circuitBreaker := middleware.NewCircuitBreaker(middleware.CircuitBreakerConfig{
		FailureThreshold: cfg.CircuitFailureThreshold,
		ResetTimeout:     time.Duration(cfg.CircuitResetTimeout) * time.Second,
		SuccessThreshold: cfg.CircuitSuccessThreshold,
	}, func(from, to middleware.CircuitState) {
		auditor.Log(middleware.AuditEvent{
			Action: "circuit_breaker_transition",
			Result: fmt.Sprintf("%s->%s", from, to),
		})
	})

	// RFA-qq0.16: Create handle store for response firewall
	handleStore := NewHandleStore(time.Duration(cfg.HandleTTL) * time.Second)

	// RFA-qq0.17: Create step-up gating components
	groqGuardClient := middleware.NewGroqGuardClient(cfg.GroqAPIKey, time.Duration(cfg.DeepScanTimeout)*time.Second)

	// Load destination allowlist (fall back to defaults if file not found)
	var destinationAllowlist *middleware.DestinationAllowlist
	if cfg.DestinationsConfigPath != "" {
		dal, err := middleware.LoadDestinationAllowlist(cfg.DestinationsConfigPath)
		if err != nil {
			// Fall back to defaults if config file not found
			destinationAllowlist = middleware.DefaultDestinationAllowlist()
		} else {
			destinationAllowlist = dal
		}
	} else {
		destinationAllowlist = middleware.DefaultDestinationAllowlist()
	}

	// Load risk thresholds (fall back to defaults if file not found)
	var riskConfig *middleware.RiskConfig
	if cfg.RiskThresholdsPath != "" {
		rc, err := middleware.LoadRiskConfig(cfg.RiskThresholdsPath)
		if err != nil {
			// Fall back to defaults if config file not found
			riskConfig = middleware.DefaultRiskConfig()
		} else {
			riskConfig = rc
		}
	} else {
		riskConfig = middleware.DefaultRiskConfig()
	}

	// RFA-j2d.1: Ensure UIConfig exists (default to secure defaults if nil)
	uiConfig := cfg.UI
	if uiConfig == nil {
		uiConfig = UIConfigDefaults()
	}

	// RFA-j2d.1: Create UI capability gating
	uiCapabilityGating := NewUICapabilityGating(uiConfig, cfg.UICapabilityGrantsPath)

	// RFA-j2d.2: Create UI resource controls
	uiResourceControls := NewUIResourceControls(uiConfig)

	// RFA-j2d.6: Create UI response processor (integrates j2d.1, j2d.2, j2d.3, j2d.5)
	uiResponseProcessor := NewUIResponseProcessor(
		uiCapabilityGating,
		uiResourceControls,
		registry,
		uiConfig,
		auditor,
	)

	// RFA-a2y.1 + RFA-uln: Create secret redeemer (SPIKE Nexus for production, POC for dev/test).
	// SPIKE Nexus requires mTLS for ALL endpoints (including secret get/put).
	// When SPIFFE_ENDPOINT_SOCKET is set (Docker Compose), we create an X509Source
	// from the SPIRE Workload API so the redeemer presents a valid client cert.
	// In dev mode without SPIRE, we fall back to InsecureSkipVerify (no client cert).
	var spikeRedeemer middleware.SecretRedeemer
	if cfg.SPIKENexusURL != "" {
		var spikeX509 *workloadapi.X509Source
		if os.Getenv("SPIFFE_ENDPOINT_SOCKET") != "" {
			// SPIRE agent socket available -- obtain X509Source for mTLS to SPIKE Nexus.
			spikeCtx, spikeCancel := context.WithTimeout(context.Background(), 15*time.Second)
			x509Src, err := workloadapi.NewX509Source(spikeCtx)
			spikeCancel()
			if err != nil {
				log.Printf("WARNING: Failed to create X509Source for SPIKE Nexus mTLS: %v (falling back to InsecureSkipVerify)", err)
			} else {
				spikeX509 = x509Src
				log.Printf("SPIKE Nexus: mTLS configured via SPIRE X509Source")
			}
		}
		// devMode=true when x509Source is nil (no SPIRE agent) -- auto-populate OwnerID.
		// Even with mTLS, SPIKE Nexus v0.8.0 may not return owner metadata,
		// so devMode is always true in the Docker Compose POC.
		spikeRedeemer = middleware.NewSPIKENexusRedeemer(cfg.SPIKENexusURL, spikeX509, true)
	} else {
		// Fallback to POC redeemer (Phase 1 behavior with deterministic mock secrets).
		// NOTE (RFA-7ct): Without SPIKE Nexus, the POC redeemer does not populate
		// OwnerID, so ValidateTokenOwnership will reject tokens with empty OwnerID.
		// This is intentional - production deployments MUST configure SPIKE_NEXUS_URL.
		spikeRedeemer = middleware.NewPOCSecretRedeemer()
	}

	// RFA-lo1.4: Configure cosign-blob attestation for registry hot-reload.
	// When TOOL_REGISTRY_PUBLIC_KEY is set, it should be a path to a PEM file
	// containing an Ed25519 public key. Registry updates will require a valid
	// companion .sig file. When empty (default for dev), updates are accepted
	// without signature verification.
	if cfg.ToolRegistryPublicKey != "" {
		pemData, err := os.ReadFile(cfg.ToolRegistryPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read registry public key from %s: %w", cfg.ToolRegistryPublicKey, err)
		}
		if err := registry.SetPublicKey(pemData); err != nil {
			return nil, fmt.Errorf("failed to set registry public key: %w", err)
		}
		log.Printf("[tool-registry] attestation configured with public key from %s", cfg.ToolRegistryPublicKey)
	}

	// RFA-dh9: Start fsnotify watcher on tool registry YAML for hot-reload.
	// The watcher runs in a background goroutine and reloads the registry
	// atomically when the file changes. Stop function is stored for Close().
	registryStop, err := registry.Watch()
	if err != nil {
		return nil, fmt.Errorf("failed to start tool registry watcher: %w", err)
	}

	// RFA-m6j.3: Wrap the reverse proxy transport with trace context propagation.
	// This injects traceparent/tracestate headers into every outbound request
	// to the MCP server, enabling cross-service distributed tracing.
	// The base transport is either the default or will be replaced later by
	// EnableSPIFFETLS (which re-wraps with TracingTransport -- see below).
	proxy.Transport = NewTracingTransport(proxy.Transport)

	// RFA-8z8.1: Log which SPIFFE mode is active at startup (AC5)
	log.Printf("SPIFFE mode: %s", cfg.SPIFFEMode)

	// Start deep scan result processor in background
	go deepScanner.ResultProcessor(context.Background())

	// RFA-0dz: MCP transport creation is deferred to first request (lazy init).
	// DetectTransport will try Streamable HTTP first, then fall back to
	// Legacy SSE, with a deprecation warning for SSE.
	// No transport is created at startup to handle Docker Compose ordering
	// where upstream may not be ready yet.

	return &Gateway{
		config:               cfg,
		proxy:                proxy,
		auditor:              auditor,
		opa:                  opa,
		registry:             registry,
		dlpScanner:           dlpScanner,
		deepScanner:          deepScanner,
		sessionContext:       sessionContext,
		rateLimiter:          rateLimiter,
		circuitBreaker:       circuitBreaker,
		handleStore:          handleStore,
		groqGuardClient:      groqGuardClient,
		destinationAllowlist: destinationAllowlist,
		riskConfig:           riskConfig,
		uiCapabilityGating:   uiCapabilityGating,
		uiResourceControls:   uiResourceControls,
		uiResponseProcessor:  uiResponseProcessor,
		spikeRedeemer:        spikeRedeemer,
		sessionStore:         sessionStore,
		registryStop:         registryStop,
	}, nil
}

// Handler returns the HTTP handler with middleware chain
func (g *Gateway) Handler() http.Handler {
	// Build middleware chain in order:
	// 1. Request size limit
	// 2. Body capture
	// 3. SPIFFE auth
	// 4. Audit log
	// 5. Tool registry verify
	// 6. OPA policy
	// 7. DLP scanning
	// 8. Session context (RFA-qq0.15)
	// 9. Step-up gating (RFA-qq0.17: risk scoring + destination check + guard model)
	// 10. Deep scan dispatch (async, after step-up gating)
	// 11. Rate limiting (per-agent token bucket)
	// 12. Circuit breaker (protect upstream from cascading failures)
	// 13. Token substitution hook (SECURITY: LAST before proxy - no middleware sees real secrets)
	// 14. Response firewall (RFA-qq0.16: wraps proxy, intercepts responses before return)
	// 15. Proxy to upstream

	// RFA-qq0.16: Wrap proxy handler with response firewall
	// The response firewall intercepts responses AFTER they come back from upstream
	// but BEFORE they flow back through the middleware chain to the agent
	proxyWithResponseFirewall := middleware.ResponseFirewall(
		g.proxyHandler(),
		g.registry,
		g.handleStore,
		g.config.HandleTTL,
	)

	handler := http.Handler(proxyWithResponseFirewall)

	// Apply middleware in reverse order (innermost first)
	handler = middleware.TokenSubstitution(handler, g.spikeRedeemer, g.auditor, middleware.NewToolRegistryScopeResolver(g.registry)) // 13 - LAST before proxy (RFA-0gr: dynamic scope)
	handler = middleware.CircuitBreakerMiddleware(handler, g.circuitBreaker)                                                         // 12
	handler = middleware.RateLimitMiddleware(handler, g.rateLimiter)                                                                 // 11
	handler = middleware.DeepScanMiddleware(handler, g.deepScanner)                                                                  // 10
	handler = middleware.StepUpGating(handler, g.groqGuardClient, g.destinationAllowlist, g.riskConfig, g.registry, g.auditor)       // 9
	handler = middleware.SessionContextMiddleware(handler, g.sessionContext)                                                         // 8
	handler = middleware.DLPMiddleware(handler, g.dlpScanner, g.dlpPolicy())                                                         // 7
	handler = middleware.OPAPolicy(handler, g.opa)                                                                                   // 6
	handler = middleware.ToolRegistryVerify(handler, g.registry)                                                                     // 5
	handler = middleware.AuditLog(handler, g.auditor)                                                                                // 4
	handler = middleware.SPIFFEAuth(handler, g.config.SPIFFEMode)                                                                    // 3
	handler = middleware.BodyCapture(handler)                                                                                        // 2
	handler = middleware.RequestSizeLimit(handler, g.config.MaxRequestSizeBytes)                                                     // 1

	// Add endpoints
	mux := http.NewServeMux()
	mux.Handle("/health", http.HandlerFunc(g.healthHandler))
	// RFA-qq0.16: Handle dereference endpoint
	mux.Handle("/data/dereference", g.dataHandleDereferenceHandler())
	mux.Handle("/", handler)

	return mux
}

// proxyHandler proxies requests to upstream MCP server with UI response processing.
// RFA-j2d.1: Capability gating (strip _meta.ui for denied/unapproved servers/tools)
// RFA-j2d.3: CSP and permissions mediation (rewrite _meta.ui.csp and _meta.ui.permissions)
// RFA-j2d.2: Resource controls (content-type, size, scan, hash verification)
// RFA-j2d.5: Registry verification for ui:// resources
// RFA-j2d.6: Unified response processing pipeline (processUpstreamResponse)
//
// This handler intercepts MCP traffic based on request type:
//   - tools/list responses: captured after upstream returns, then processed through
//     processUpstreamResponse which applies capability gating + CSP/permissions mediation
//   - resources/read for ui:// URIs: checked BEFORE proxying via checkUIResourceReadAllowed;
//     on the response path, resource controls and registry verification are applied
//   - all other requests: proxied unchanged
//
// Server and tenant are identified via X-MCP-Server and X-Tenant request headers.
// If not set, "default" is used for both (fail-closed: no grant match = deny mode).
func (g *Gateway) proxyHandler() http.Handler {
	// RFA-m6j.2: Create tracer for proxy span (gateway package)
	proxyTracer := otel.Tracer("mcp-security-gateway", trace.WithInstrumentationVersion("2.0.0"))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.2: Create OTel span for proxy
		ctx, span := proxyTracer.Start(r.Context(), "gateway.proxy",
			trace.WithAttributes(
				attribute.String("mcp.gateway.middleware", "proxy"),
				attribute.String("upstream_url", g.config.UpstreamURL),
			),
		)
		defer span.End()

		// Extract MCP method from request body (already captured by BodyCapture middleware)
		mcpMethod, mcpParams := g.extractMCPMethodAndParams(ctx)
		reqInfo := NewMCPRequestInfo(mcpMethod, mcpParams)

		server := r.Header.Get("X-MCP-Server")
		if server == "" {
			server = "default"
		}
		tenant := r.Header.Get("X-Tenant")
		if tenant == "" {
			tenant = "default"
		}

		// Wrap response writer to capture status code for span
		proxyRW := &proxyResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// RFA-9ol: Branch on transport mode.
		// "mcp" uses the MCP Streamable HTTP transport for JSON-RPC.
		// Any other value (including "proxy" and empty string) uses the legacy
		// httputil.ReverseProxy path with full UI processing for backward compat.
		if g.config.MCPTransportMode == "mcp" {
			// MCP path: translate SDK request -> MCP JSON-RPC -> upstream -> response
			g.handleMCPRequest(proxyRW, r.WithContext(ctx), mcpMethod, mcpParams)
		} else {
			// Legacy path: full UI response processing pipeline
			g.processUpstreamResponse(proxyRW, r.WithContext(ctx), reqInfo, server, tenant)
		}

		span.SetAttributes(
			attribute.Int("status_code", proxyRW.statusCode),
			attribute.String("mcp.result", "allowed"),
			attribute.String("mcp.reason", "proxied"),
		)
	})
}

// proxyResponseWriter wraps http.ResponseWriter to capture status code for proxy span
type proxyResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (prw *proxyResponseWriter) WriteHeader(code int) {
	if !prw.written {
		prw.statusCode = code
		prw.written = true
	}
	prw.ResponseWriter.WriteHeader(code)
}

func (prw *proxyResponseWriter) Write(b []byte) (int, error) {
	if !prw.written {
		prw.statusCode = http.StatusOK
		prw.written = true
	}
	return prw.ResponseWriter.Write(b)
}

// handleMCPRequest translates an SDK-format request into an MCP JSON-RPC request,
// sends it via the auto-detected Transport, and writes the response back as JSON.
// RFA-9ol: Walking skeleton -- handles tools/call and any other MCP method.
// RFA-0dz: Uses Transport interface (Streamable HTTP or Legacy SSE).
// RFA-xhr: Adds per-request timeouts, retry with backoff on session loss,
// response validation, and size limits.
//
// Lazy initialization: the MCP transport is initialized on the first request,
// not at startup, to handle Docker Compose ordering where upstream may not be
// ready yet.
//
// ALL errors use middleware.WriteGatewayError() with proper GatewayError structs.
func (g *Gateway) handleMCPRequest(w http.ResponseWriter, r *http.Request, method string, params map[string]interface{}) {
	ctx := r.Context()

	// Lazy init: ensure MCP transport is initialized
	if err := g.ensureMCPTransportInitialized(ctx); err != nil {
		middleware.WriteGatewayError(w, r, http.StatusBadGateway, middleware.GatewayError{
			Code:        middleware.ErrMCPTransportFailed,
			Message:     fmt.Sprintf("MCP transport initialization failed: %v", err),
			Middleware:  "mcp_transport",
			Remediation: "Ensure the upstream MCP server is running and accessible at " + g.config.UpstreamURL,
		})
		return
	}

	// Build JSON-RPC request from the extracted method and params
	rpcReq := &mcpclient.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1, // Walking skeleton uses a fixed ID; session story will add proper ID tracking
		Method:  method,
		Params:  params,
	}

	// RFA-xhr: Apply per-request timeout (default 30s when config is zero)
	requestTimeoutSec := g.config.MCPRequestTimeout
	if requestTimeoutSec <= 0 {
		requestTimeoutSec = 30
	}
	requestTimeout := time.Duration(requestTimeoutSec) * time.Second
	sendCtx, sendCancel := context.WithTimeout(ctx, requestTimeout)
	defer sendCancel()

	// RFA-xhr: Send with retry and backoff on session loss.
	// The reinitFn re-initializes the transport after session loss.
	retryCfg := mcpclient.DefaultRetryConfig()
	reinitFn := func(retryCtx context.Context) error {
		g.mcpTransportMu.Lock()
		g.mcpTransport = nil
		g.mcpTransportMu.Unlock()
		return g.ensureMCPTransportInitialized(retryCtx)
	}

	rpcResp, err := mcpclient.SendWithRetry(sendCtx, g.mcpTransport, rpcReq, retryCfg, reinitFn)
	if err != nil {
		middleware.WriteGatewayError(w, r, http.StatusBadGateway, middleware.GatewayError{
			Code:        middleware.ErrMCPTransportFailed,
			Message:     fmt.Sprintf("MCP request failed: %v", err),
			Middleware:  "mcp_transport",
			Remediation: "Check upstream MCP server availability and network connectivity.",
		})
		return
	}

	// RFA-xhr: Validate response structure
	if validationErr := mcpclient.ValidateResponse(rpcReq, rpcResp); validationErr != nil {
		middleware.WriteGatewayError(w, r, http.StatusBadGateway, middleware.GatewayError{
			Code:        middleware.ErrMCPInvalidResponse,
			Message:     fmt.Sprintf("Invalid MCP response: %v", validationErr),
			Middleware:  "mcp_transport",
			Remediation: "The upstream MCP server returned an invalid JSON-RPC response.",
		})
		return
	}

	// Check for JSON-RPC error in the response
	if rpcResp.Error != nil {
		middleware.WriteGatewayError(w, r, http.StatusBadGateway, middleware.GatewayError{
			Code:    middleware.ErrMCPRequestFailed,
			Message: fmt.Sprintf("MCP server error: code=%d message=%s", rpcResp.Error.Code, rpcResp.Error.Message),
			Details: map[string]any{
				"jsonrpc_error_code": rpcResp.Error.Code,
				"jsonrpc_error_msg":  rpcResp.Error.Message,
			},
			Middleware:  "mcp_transport",
			Remediation: "The upstream MCP server returned an error. Check the error details.",
		})
		return
	}

	// RFA-xhr: Enforce response size limit using MaxRequestSizeBytes
	if rpcResp.Result != nil && int64(len(rpcResp.Result)) > g.config.MaxRequestSizeBytes {
		middleware.WriteGatewayError(w, r, http.StatusBadGateway, middleware.GatewayError{
			Code:    middleware.ErrMCPInvalidResponse,
			Message: fmt.Sprintf("MCP response result exceeds maximum size of %d bytes (got %d bytes)", g.config.MaxRequestSizeBytes, len(rpcResp.Result)),
			Details: map[string]any{
				"max_bytes":    g.config.MaxRequestSizeBytes,
				"actual_bytes": len(rpcResp.Result),
			},
			Middleware:  "mcp_transport",
			Remediation: "The upstream MCP server returned a response larger than MAX_REQUEST_SIZE_BYTES.",
		})
		return
	}

	// Write the JSON-RPC response back to the client
	w.Header().Set("Content-Type", "application/json")
	respBytes, err := json.Marshal(rpcResp)
	if err != nil {
		middleware.WriteGatewayError(w, r, http.StatusInternalServerError, middleware.GatewayError{
			Code:        middleware.ErrMCPInvalidResponse,
			Message:     fmt.Sprintf("Failed to serialize MCP response: %v", err),
			Middleware:  "mcp_transport",
			Remediation: "This is an internal error. Check gateway logs for details.",
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

// ensureMCPTransportInitialized performs lazy initialization of the MCP transport.
// Thread-safe: only the first caller initializes; subsequent callers wait.
//
// RFA-0dz: Uses DetectTransport for auto-detection. On first request, tries
// Streamable HTTP first, falls back to Legacy SSE with deprecation warning.
// RFA-xhr: Uses DetectTransportWithConfig for per-probe and overall timeouts.
func (g *Gateway) ensureMCPTransportInitialized(ctx context.Context) error {
	if g.config.MCPTransportMode != "mcp" {
		return fmt.Errorf("MCP transport not configured (MCPTransportMode=%q)", g.config.MCPTransportMode)
	}

	// Fast path: already initialized
	if g.mcpTransport != nil {
		return nil
	}

	g.mcpTransportMu.Lock()
	defer g.mcpTransportMu.Unlock()

	// Double-check after acquiring lock
	if g.mcpTransport != nil {
		return nil
	}

	// RFA-xhr: Use configured timeouts for detection, with safe defaults
	// when config values are zero (e.g., tests that create Config{} directly).
	detectCfg := mcpclient.DefaultDetectConfig()
	if g.config.MCPProbeTimeout > 0 {
		detectCfg.ProbeTimeout = time.Duration(g.config.MCPProbeTimeout) * time.Second
	}
	if g.config.MCPDetectTimeout > 0 {
		detectCfg.OverallTimeout = time.Duration(g.config.MCPDetectTimeout) * time.Second
	}

	transport, err := mcpclient.DetectTransportWithConfig(ctx, g.config.UpstreamURL, nil, detectCfg)
	if err != nil {
		return err
	}

	g.mcpTransport = transport
	return nil
}

// processUpstreamResponse routes MCP responses through the appropriate UI
// control pipeline based on request type. This is the central dispatch for
// UI-specific response processing (Reference Architecture Section 7.9.7).
//
// Routing:
//   - tools/list -> capability gating + CSP/permissions mediation
//   - resources/read + ui:// -> request-side capability check + response-side resource controls
//   - everything else -> proxy unchanged
func (g *Gateway) processUpstreamResponse(
	w http.ResponseWriter,
	r *http.Request,
	reqInfo MCPRequestInfo,
	server, tenant string,
) {
	switch {
	case reqInfo.IsResourceRead() && reqInfo.IsUIResource():
		g.handleUIResourceRead(w, r, reqInfo, server, tenant)

	case reqInfo.IsToolsList():
		g.handleToolsListResponse(w, r, server, tenant)

	default:
		// Standard request - proxy unchanged
		g.proxy.ServeHTTP(w, r)
	}
}

// handleToolsListResponse captures the upstream tools/list response and applies
// the full UI processing pipeline: capability gating + CSP/permissions mediation.
func (g *Gateway) handleToolsListResponse(
	w http.ResponseWriter,
	r *http.Request,
	server, tenant string,
) {
	// Capture upstream response for processing
	capture := &uiResponseCapture{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		statusCode:     http.StatusOK,
	}
	g.proxy.ServeHTTP(capture, r)

	responseBody := capture.body.Bytes()

	// RFA-j2d.6: Apply full tools/list processing pipeline
	// (capability gating from j2d.1 + CSP/permissions mediation from j2d.3)
	processedBody := g.uiResponseProcessor.ProcessToolsListResponse(responseBody, server, tenant)

	// Forward captured headers, then write the processed body
	w.Header().Del("Content-Length") // Body size may have changed
	w.WriteHeader(capture.statusCode)
	_, _ = w.Write(processedBody)
}

// handleUIResourceRead handles ui:// resource reads with both request-side
// capability checks and response-side resource controls.
func (g *Gateway) handleUIResourceRead(
	w http.ResponseWriter,
	r *http.Request,
	reqInfo MCPRequestInfo,
	server, tenant string,
) {
	resourceURI := reqInfo.ResourceURI()

	// RFA-j2d.1: Block ui:// resource reads for denied servers BEFORE proxying
	if !g.checkUIResourceReadAllowed(server, tenant, resourceURI) {
		middleware.WriteGatewayError(w, r, http.StatusForbidden, middleware.GatewayError{
			Code:        middleware.ErrUICapabilityDenied,
			Message:     "UI resource reads are not permitted for this server/tenant.",
			Middleware:  "ui_capability_gating",
			Remediation: "Grant UI capabilities for this server/tenant in ui_capability_grants.yaml.",
		})
		return
	}

	// Proxy to upstream and capture the response for resource controls
	capture := &uiResponseCapture{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		statusCode:     http.StatusOK,
	}
	g.proxy.ServeHTTP(capture, r)

	responseContent := capture.body.Bytes()
	contentType := capture.Header().Get("Content-Type")

	// RFA-j2d.6: Apply resource controls (j2d.2) + registry verification (j2d.5)
	allowed, reason, _ := g.uiResponseProcessor.ProcessUIResourceResponse(
		responseContent, contentType, server, tenant, resourceURI,
	)

	if !allowed {
		// Resource blocked by controls - return error instead of upstream content
		middleware.WriteGatewayError(w, r, http.StatusForbidden, middleware.GatewayError{
			Code:        middleware.ErrUIResourceBlocked,
			Message:     fmt.Sprintf("UI resource blocked: %s", reason),
			Middleware:  "ui_resource_controls",
			Details:     map[string]any{"reason": reason},
			Remediation: "Ensure the resource passes content-type, size, scan, and hash verification.",
		})
		return
	}

	// Resource passed all controls - forward the upstream response
	w.Header().Del("Content-Length")
	w.WriteHeader(capture.statusCode)
	_, _ = w.Write(responseContent)
}

// uiResponseCapture captures the upstream response so UI capability gating can
// modify it before sending to the client. Follows the same pattern as
// responseCapture in the response firewall (middleware/response_firewall.go).
type uiResponseCapture struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	written    bool
}

func (c *uiResponseCapture) WriteHeader(code int) {
	c.statusCode = code
	c.written = true
	// Capture status but do not forward yet -- we may modify the body
}

func (c *uiResponseCapture) Write(b []byte) (int, error) {
	if !c.written {
		c.statusCode = http.StatusOK
		c.written = true
	}
	return c.body.Write(b)
}

// extractMCPMethodAndParams parses the MCP JSON-RPC method and params from the
// request body already captured in context by BodyCapture middleware.
func (g *Gateway) extractMCPMethodAndParams(ctx context.Context) (string, map[string]interface{}) {
	body := middleware.GetRequestBody(ctx)
	if len(body) == 0 {
		return "", nil
	}
	var req struct {
		Method string                 `json:"method"`
		Params map[string]interface{} `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "", nil
	}
	return req.Method, req.Params
}

// dataHandleDereferenceHandler returns approved views of handle-ized data (RFA-qq0.16)
// POST /data/dereference with JSON body: {"handle_ref": "<ref>"}
// Validates:
//   - Handle exists and hasn't expired (410 Gone if expired/missing)
//   - SPIFFE ID matches the original requester (403 Forbidden if mismatch)
//
// Returns approved views only (for POC: the raw data wrapped in an approved_view envelope)
func (g *Gateway) dataHandleDereferenceHandler() http.Handler {
	// Wrap with SPIFFE auth so we can validate the caller's identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request body
		var req struct {
			HandleRef string `json:"handle_ref"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.HandleRef == "" {
			http.Error(w, "Missing handle_ref", http.StatusBadRequest)
			return
		}

		// Look up handle
		entry := g.handleStore.Get(req.HandleRef)
		if entry == nil {
			// Handle not found or expired
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGone)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":  "handle_expired_or_not_found",
				"detail": "The data handle has expired or does not exist.",
			})
			return
		}

		// Validate SPIFFE ID matches
		callerSPIFFEID := middleware.GetSPIFFEID(r.Context())
		if callerSPIFFEID != entry.SPIFFEID {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":  "spiffe_id_mismatch",
				"detail": "You are not authorized to dereference this handle.",
			})
			return
		}

		// Return approved view
		// In production, this would apply view transformations:
		// aggregates, top-N, redacted rows, etc.
		// For POC, we return the raw data wrapped in an approved_view envelope.
		approvedView := map[string]interface{}{
			"view_type":  "approved_view",
			"tool":       entry.ToolName,
			"created_at": entry.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			"data":       json.RawMessage(entry.RawData),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(approvedView)
	})

	// Apply SPIFFE auth middleware to the dereference endpoint
	return middleware.SPIFFEAuth(inner, g.config.SPIFFEMode)
}

// healthHandler returns gateway health status including circuit breaker state
func (g *Gateway) healthHandler(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status": "ok",
		"circuit_breaker": map[string]interface{}{
			"state": g.circuitBreaker.State().String(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(health)
}

// checkUIResourceReadAllowed checks whether a ui:// resource read is permitted.
// RFA-j2d.1: Called from the response processing path for resources/read of ui:// URIs.
// RFA-j2d.8: Emits UI audit events via EmitUIEvent for hash chain integration.
// Returns true if the read should proceed, false if it should be blocked with 403.
func (g *Gateway) checkUIResourceReadAllowed(server, tenant, resourceURI string) bool {
	allowed, event := g.uiCapabilityGating.CheckUIResourceReadAllowed(server, tenant, resourceURI)

	if event != nil {
		// RFA-j2d.8: Emit structured UI audit event
		g.auditor.EmitUIEvent(middleware.UIAuditEventParams{
			EventType: event.EventType,
			UI: &middleware.UIAuditData{
				ResourceURI:         resourceURI,
				CapabilityGrantMode: event.Mode,
			},
		})
	}

	return allowed
}

// dlpPolicy returns the effective DLP policy by merging the YAML config with
// the DLP_INJECTION_POLICY env var override. The env var takes precedence over
// the YAML value for the injection category only.
func (g *Gateway) dlpPolicy() middleware.DLPPolicy {
	p := g.riskConfig.DLP
	// RFA-sd7: DLP_INJECTION_POLICY env var overrides dlp.injection YAML config.
	if g.config.DLPInjectionPolicy == "block" || g.config.DLPInjectionPolicy == "flag" {
		p.Injection = g.config.DLPInjectionPolicy
	}
	return p
}

// Close cleans up gateway resources
func (g *Gateway) Close() error {
	// RFA-9ol: Close MCP transport session
	if g.mcpTransport != nil {
		_ = g.mcpTransport.Close(context.Background())
	}
	// RFA-dh9: Stop the registry file watcher
	if g.registryStop != nil {
		g.registryStop()
	}
	if g.handleStore != nil {
		g.handleStore.Close()
	}
	// RFA-j2d.6: Clean up UI resource controls cache
	if g.uiResourceControls != nil {
		g.uiResourceControls.Close()
	}
	// RFA-a2y.1: Close SPIKE Nexus redeemer (releases X.509 source if present)
	if closer, ok := g.spikeRedeemer.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	// RFA-hh5.1: Close KeyDB session store if applicable
	if closer, ok := g.sessionStore.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	// RFA-8z8.1: Close SPIFFE TLS config (releases X509Source)
	if g.spiffeTLS != nil {
		_ = g.spiffeTLS.Close()
	}
	if g.opa != nil {
		return g.opa.Close()
	}
	return nil
}

// EnableSPIFFETLS initializes SPIFFE-based mTLS for the gateway (RFA-8z8.1).
// In prod mode, this connects to the SPIRE Agent, obtains an X.509 SVID, and
// configures both the server's TLS listener and the reverse proxy's upstream
// transport for mutual TLS.
//
// RFA-8z8.2: Also configures the KeyDB client for TLS when KeyDB is in use.
// The same X509Source provides mTLS for KeyDB, upstream proxy, and server TLS.
//
// This method must be called AFTER New() and BEFORE starting the HTTP server.
// It is separated from New() because SPIRE connectivity is an infrastructure
// dependency that should fail loudly at startup, not silently during config.
func (g *Gateway) EnableSPIFFETLS(ctx context.Context) error {
	spiffeTLS, err := NewSPIFFETLSConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize SPIFFE TLS: %w", err)
	}

	g.spiffeTLS = spiffeTLS

	// RFA-8z8.1 AC3: Configure the reverse proxy transport for mTLS to upstream.
	// This replaces the default HTTP transport with one that presents the
	// gateway's SVID and validates the upstream's certificate.
	// RFA-m6j.3: Wrap with TracingTransport to propagate trace context
	// over the mTLS connection to upstream MCP servers.
	g.proxy.Transport = NewTracingTransport(spiffeTLS.UpstreamTransport)

	// RFA-8z8.2 AC2: Configure the KeyDB client for TLS if KeyDB is in use.
	// The KeyDB client needs the same X509Source for mTLS to KeyDB.
	if g.config.KeyDBURL != "" {
		if err := g.enableKeyDBTLS(spiffeTLS); err != nil {
			log.Printf("WARNING: Failed to enable KeyDB TLS: %v (KeyDB may not support TLS yet)", err)
			// Non-fatal: KeyDB TLS is best-effort during transition. The URL was
			// already converted to rediss:// in New(), but the TLS config was not
			// applied because the X509Source was not yet available. If this fails,
			// the connection will fail at first use, which is the correct behavior
			// (fail loudly, not silently).
		}
	}

	log.Printf("SPIFFE mTLS: server TLS configured, upstream proxy transport set to mTLS")

	return nil
}

// enableKeyDBTLS configures the KeyDB session store and rate limiter clients
// with TLS from the SPIRE X509Source. This replaces the plain redis client
// created in New() with a TLS-enabled one.
//
// RFA-8z8.2: KeyDB does not speak SPIRE Workload API natively. It receives
// filesystem-based certs via an init script (scripts/keydb-svid-refresh.sh).
// The gateway connects to it using the same X509Source as other mTLS connections.
func (g *Gateway) enableKeyDBTLS(spiffeTLS *SPIFFETLSConfig) error {
	keyDBTLSCfg, err := NewKeyDBTLSConfigFromSPIRE(spiffeTLS.x509Source)
	if err != nil {
		return fmt.Errorf("failed to create KeyDB TLS config: %w", err)
	}

	// Create a new TLS-enabled redis client and replace the stores
	keyDBURL := KeyDBURLForMode(g.config.KeyDBURL, g.config.SPIFFEMode)
	redisClient := NewKeyDBClientTLS(keyDBURL, g.config.KeyDBPoolMin, g.config.KeyDBPoolMax, keyDBTLSCfg.TLSConfig)

	// Close old stores before replacing
	if closer, ok := g.sessionStore.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	// Create new stores with TLS client
	g.sessionStore = middleware.NewKeyDBStoreFromClient(redisClient, g.config.SessionTTL)
	rateLimitStore := middleware.NewKeyDBRateLimitStore(redisClient)

	// Update the session context and rate limiter with new stores
	g.sessionContext = middleware.NewSessionContext(g.sessionStore)
	g.rateLimiter = middleware.NewRateLimiter(g.config.RateLimitRPM, g.config.RateLimitBurst, rateLimitStore)

	log.Printf("SPIFFE mTLS: KeyDB client configured with TLS (URL: %s)", keyDBURL)

	return nil
}

// SPIFFETLSEnabled returns true if the gateway is configured for SPIFFE mTLS.
func (g *Gateway) SPIFFETLSEnabled() bool {
	return g.spiffeTLS != nil
}

// ServerTLSConfig returns the TLS configuration for the HTTPS listener.
// Returns nil when in dev mode (HTTP only).
func (g *Gateway) ServerTLSConfig() *tls.Config {
	if g.spiffeTLS != nil {
		return g.spiffeTLS.ServerTLS
	}
	return nil
}

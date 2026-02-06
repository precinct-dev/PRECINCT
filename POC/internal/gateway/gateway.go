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
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
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
		APIKey:       cfg.GroqAPIKey,
		Timeout:      time.Duration(cfg.DeepScanTimeout) * time.Second,
		FallbackMode: cfg.DeepScanFallback,
		Auditor:      auditor,
	})
	// RFA-hh5.1: Select session store based on KeyDB availability.
	// RFA-hh5.2: Also select rate limit store. Both share the same redis client
	// when KeyDB is available, enabling distributed session persistence and
	// distributed rate limiting from a single connection pool.
	var sessionStore middleware.SessionStore
	var rateLimitStore middleware.RateLimitStore
	if cfg.KeyDBURL != "" {
		redisClient := middleware.NewKeyDBClient(cfg.KeyDBURL, cfg.KeyDBPoolMin, cfg.KeyDBPoolMax)
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

	// RFA-a2y.1: Create secret redeemer (SPIKE Nexus for production, POC for dev/test)
	var spikeRedeemer middleware.SecretRedeemer
	if cfg.SPIKENexusURL != "" {
		// SPIKE Nexus mode: use mTLS via SPIRE to redeem secrets from Nexus.
		// x509Source is nil here because the SPIRE agent socket connection is
		// established at runtime via the SPIFFE_ENDPOINT_SOCKET env var.
		// In a full production setup, we would create an X509Source here.
		// For Docker Compose POC, we pass nil and the redeemer uses
		// InsecureSkipVerify (acceptable for POC per ADR-001).
		spikeRedeemer = middleware.NewSPIKENexusRedeemer(cfg.SPIKENexusURL, nil)
	} else {
		// Fallback to POC redeemer (Phase 1 behavior with deterministic mock secrets)
		spikeRedeemer = middleware.NewPOCSecretRedeemer()
	}

	// RFA-8z8.1: Log which SPIFFE mode is active at startup (AC5)
	log.Printf("SPIFFE mode: %s", cfg.SPIFFEMode)

	// Start deep scan result processor in background
	go deepScanner.ResultProcessor(context.Background())

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
	handler = middleware.TokenSubstitution(handler, g.spikeRedeemer)                                                           // 13 - LAST before proxy
	handler = middleware.CircuitBreakerMiddleware(handler, g.circuitBreaker)                                                   // 12
	handler = middleware.RateLimitMiddleware(handler, g.rateLimiter)                                                           // 11
	handler = middleware.DeepScanMiddleware(handler, g.deepScanner)                                                            // 10
	handler = middleware.StepUpGating(handler, g.groqGuardClient, g.destinationAllowlist, g.riskConfig, g.registry, g.auditor) // 9
	handler = middleware.SessionContextMiddleware(handler, g.sessionContext)                                                   // 8
	handler = middleware.DLPMiddleware(handler, g.dlpScanner)                                                                  // 7
	handler = middleware.OPAPolicy(handler, g.opa)                                                                             // 6
	handler = middleware.ToolRegistryVerify(handler, g.registry)                                                               // 5
	handler = middleware.AuditLog(handler, g.auditor)                                                                          // 4
	handler = middleware.SPIFFEAuth(handler, g.config.SPIFFEMode)                                                              // 3
	handler = middleware.BodyCapture(handler)                                                                                  // 2
	handler = middleware.RequestSizeLimit(handler, g.config.MaxRequestSizeBytes)                                               // 1

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

		// RFA-j2d.6: Route through processUpstreamResponse based on request type
		g.processUpstreamResponse(proxyRW, r.WithContext(ctx), reqInfo, server, tenant)

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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":  "ui_capability_denied",
			"detail": "UI resource reads are not permitted for this server/tenant.",
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(NewUIResourceBlockedError(reason))
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

// Close cleans up gateway resources
func (g *Gateway) Close() error {
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
	g.proxy.Transport = spiffeTLS.UpstreamTransport

	log.Printf("SPIFFE mTLS: server TLS configured, upstream proxy transport set to mTLS")

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

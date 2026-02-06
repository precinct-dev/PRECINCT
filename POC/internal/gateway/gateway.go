package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
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
	deepScanner := middleware.NewDeepScanner(cfg.GroqAPIKey, time.Duration(cfg.DeepScanTimeout)*time.Second)
	sessionContext := middleware.NewSessionContext()
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimitRPM, cfg.RateLimitBurst)

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

	// RFA-j2d.1: Create UI capability gating
	uiCapabilityGating := NewUICapabilityGating(cfg.UI, cfg.UICapabilityGrantsPath)

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
	handler = middleware.TokenSubstitution(handler)                                                                            // 13 - LAST before proxy
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

// proxyHandler proxies requests to upstream MCP server with UI capability gating.
// RFA-j2d.1: This handler intercepts two types of MCP traffic:
//   - tools/list responses: captured after upstream returns, then processed through
//     applyUICapabilityGating to strip _meta.ui for denied/unapproved servers/tools
//   - resources/read for ui:// URIs: checked BEFORE proxying via checkUIResourceReadAllowed;
//     blocked with HTTP 403 if the server/tenant is not in allow mode
//
// Server and tenant are identified via X-MCP-Server and X-Tenant request headers.
// If not set, "default" is used for both (fail-closed: no grant match = deny mode).
func (g *Gateway) proxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract MCP method from request body (already captured by BodyCapture middleware)
		mcpMethod, mcpParams := g.extractMCPMethodAndParams(r.Context())

		server := r.Header.Get("X-MCP-Server")
		if server == "" {
			server = "default"
		}
		tenant := r.Header.Get("X-Tenant")
		if tenant == "" {
			tenant = "default"
		}

		switch {
		case mcpMethod == "resources/read" && g.isUIResourceRequest(mcpParams):
			// RFA-j2d.1: Block ui:// resource reads for denied servers BEFORE proxying
			resourceURI := g.extractResourceURI(mcpParams)
			if !g.checkUIResourceReadAllowed(server, tenant, resourceURI) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":  "ui_capability_denied",
					"detail": "UI resource reads are not permitted for this server/tenant.",
				})
				return
			}
			// Allowed - proxy the request
			g.proxy.ServeHTTP(w, r)

		case mcpMethod == "tools/list":
			// RFA-j2d.1: Capture tools/list response, apply UI capability gating,
			// then return the (potentially modified) response to the caller.
			capture := &uiResponseCapture{
				ResponseWriter: w,
				body:           &bytes.Buffer{},
				statusCode:     http.StatusOK,
			}
			g.proxy.ServeHTTP(capture, r)

			responseBody := capture.body.Bytes()

			// Apply UI capability gating to strip _meta.ui as needed
			processedBody := g.applyUICapabilityGating(responseBody, server, tenant)

			// Forward captured headers, then write the processed body
			w.Header().Del("Content-Length") // Body size may have changed
			w.WriteHeader(capture.statusCode)
			_, _ = w.Write(processedBody)

		default:
			// Standard request - proxy unchanged
			g.proxy.ServeHTTP(w, r)
		}
	})
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

// isUIResourceRequest checks whether the MCP params contain a ui:// resource URI,
// indicating a UI resource read that must pass capability gating.
func (g *Gateway) isUIResourceRequest(params map[string]interface{}) bool {
	uri := g.extractResourceURI(params)
	return IsUIResourceURI(uri)
}

// extractResourceURI extracts the resource URI from resources/read params.
// MCP resources/read requests use params.uri for the resource identifier.
func (g *Gateway) extractResourceURI(params map[string]interface{}) string {
	if params == nil {
		return ""
	}
	if uri, ok := params["uri"].(string); ok {
		return uri
	}
	return ""
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

// applyUICapabilityGating processes a tools/list response through UI capability gating.
// RFA-j2d.1: Called from the response processing path for tools/list responses.
// RFA-j2d.8: Emits UI audit events via EmitUIEvent for hash chain integration.
//
// This method delegates to UICapabilityGating.ApplyUICapabilityGating and emits
// structured UI audit events for any gating decisions made.
//
// Parameters:
//   - responseBody: the raw JSON-RPC response body from upstream
//   - server: the MCP server name
//   - tenant: the tenant identifier
//
// Returns the processed response body with _meta.ui stripped as appropriate.
func (g *Gateway) applyUICapabilityGating(responseBody []byte, server, tenant string) []byte {
	processed, events, err := g.uiCapabilityGating.ApplyUICapabilityGating(responseBody, server, tenant)
	if err != nil {
		log.Printf("[ERROR] UI capability gating failed: %v", err)
		return responseBody
	}

	// RFA-j2d.8: Emit structured UI audit events via EmitUIEvent
	for _, evt := range events {
		g.auditor.EmitUIEvent(middleware.UIAuditEventParams{
			EventType: evt.EventType,
			UI: &middleware.UIAuditData{
				CapabilityGrantMode: evt.Mode,
			},
		})
	}

	return processed
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
	if g.opa != nil {
		return g.opa.Close()
	}
	return nil
}

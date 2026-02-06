package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

// Gateway represents the MCP security gateway
type Gateway struct {
	config         *Config
	proxy          *httputil.ReverseProxy
	auditor        *middleware.Auditor
	opa            *middleware.OPAEngine
	registry       *middleware.ToolRegistry
	dlpScanner     middleware.DLPScanner
	deepScanner    *middleware.DeepScanner
	sessionContext *middleware.SessionContext
	rateLimiter    *middleware.RateLimiter
	circuitBreaker *middleware.CircuitBreaker
	handleStore    *HandleStore // RFA-qq0.16: response firewall data handle cache
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
	opa, err := middleware.NewOPAEngine(cfg.OPAPolicyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA engine: %w", err)
	}
	registry, err := middleware.NewToolRegistry(cfg.ToolRegistryURL, cfg.ToolRegistryConfigPath)
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

	// Start deep scan result processor in background
	go deepScanner.ResultProcessor(context.Background())

	return &Gateway{
		config:         cfg,
		proxy:          proxy,
		auditor:        auditor,
		opa:            opa,
		registry:       registry,
		dlpScanner:     dlpScanner,
		deepScanner:    deepScanner,
		sessionContext: sessionContext,
		rateLimiter:    rateLimiter,
		circuitBreaker: circuitBreaker,
		handleStore:    handleStore,
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
	// 9. Step-up gating hook (no-op for skeleton)
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
	handler = middleware.TokenSubstitution(handler)                              // 13 - LAST before proxy
	handler = middleware.CircuitBreakerMiddleware(handler, g.circuitBreaker)     // 12
	handler = middleware.RateLimitMiddleware(handler, g.rateLimiter)             // 11
	handler = middleware.DeepScanMiddleware(handler, g.deepScanner)              // 10
	handler = middleware.StepUpGating(handler)                                   // 9
	handler = middleware.SessionContextMiddleware(handler, g.sessionContext)     // 8
	handler = middleware.DLPMiddleware(handler, g.dlpScanner)                    // 7
	handler = middleware.OPAPolicy(handler, g.opa)                               // 6
	handler = middleware.ToolRegistryVerify(handler, g.registry)                 // 5
	handler = middleware.AuditLog(handler, g.auditor)                            // 4
	handler = middleware.SPIFFEAuth(handler, g.config.SPIFFEMode)                // 3
	handler = middleware.BodyCapture(handler)                                    // 2
	handler = middleware.RequestSizeLimit(handler, g.config.MaxRequestSizeBytes) // 1

	// Add endpoints
	mux := http.NewServeMux()
	mux.Handle("/health", http.HandlerFunc(g.healthHandler))
	// RFA-qq0.16: Handle dereference endpoint
	mux.Handle("/data/dereference", g.dataHandleDereferenceHandler())
	mux.Handle("/", handler)

	return mux
}

// proxyHandler proxies requests to upstream MCP server
func (g *Gateway) proxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.proxy.ServeHTTP(w, r)
	})
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

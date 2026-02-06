package gateway

import (
	"context"
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
	// 12. [Reserved for future middleware]
	// 13. Token substitution hook (SECURITY: LAST before proxy - no middleware sees real secrets)
	// 14. Proxy to upstream

	handler := g.proxyHandler()

	// Apply middleware in reverse order (innermost first)
	handler = middleware.TokenSubstitution(handler)                              // 13 - LAST before proxy
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

	// Add health check endpoint
	mux := http.NewServeMux()
	mux.Handle("/health", http.HandlerFunc(g.healthHandler))
	mux.Handle("/", handler)

	return mux
}

// proxyHandler proxies requests to upstream MCP server
func (g *Gateway) proxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.proxy.ServeHTTP(w, r)
	})
}

// healthHandler returns gateway health status
func (g *Gateway) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK\n"))
}

// Close cleans up gateway resources
func (g *Gateway) Close() error {
	if g.opa != nil {
		return g.opa.Close()
	}
	return nil
}

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

// Gateway represents the MCP security gateway
type Gateway struct {
	config     *Config
	proxy      *httputil.ReverseProxy
	auditor    *middleware.Auditor
	opa        *middleware.OPAClient
	registry   *middleware.ToolRegistry
	dlpScanner middleware.DLPScanner
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
	opa := middleware.NewOPAClient(cfg.OPAEndpoint)
	registry, err := middleware.NewToolRegistry(cfg.ToolRegistryURL, cfg.ToolRegistryConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create tool registry: %w", err)
	}
	dlpScanner := middleware.NewBuiltInScanner()

	return &Gateway{
		config:     cfg,
		proxy:      proxy,
		auditor:    auditor,
		opa:        opa,
		registry:   registry,
		dlpScanner: dlpScanner,
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
	// 7. DLP scanning (after OPA, before session context)
	// 8. Step-up gating hook (no-op for skeleton)
	// 9. Token substitution hook (no-op for skeleton)
	// 10. Proxy to upstream

	handler := g.proxyHandler()

	// Apply middleware in reverse order (innermost first)
	handler = middleware.TokenSubstitution(handler)                              // 9
	handler = middleware.StepUpGating(handler)                                   // 8
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

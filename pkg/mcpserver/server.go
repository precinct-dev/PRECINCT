package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Server is an MCP server that exposes registered tools over HTTP using
// JSON-RPC 2.0. Create one with New, register tools with Tool, and start
// it with Run.
type Server struct {
	name            string
	version         string
	port            int
	address         string
	logger          *slog.Logger
	shutdownTimeout time.Duration
	readTimeout     time.Duration
	writeTimeout    time.Duration

	// Middleware configuration.
	cachingDisabled      bool
	cacheTTL             time.Duration
	rateLimitDisabled    bool
	rateRPS              float64
	rateBurst            int
	customMiddleware     []Middleware
	roleVisibilityFilter func(ctx context.Context, toolName string) bool

	// OTel configuration.
	otelDisabled   bool
	tracerProvider trace.TracerProvider

	// pipeline is the composed middleware chain, built lazily on the first
	// tools/call request. It wraps ToolHandler, not http.Handler.
	pipelineOnce sync.Once
	pipeline     Middleware

	// Session configuration.
	sessionTimeout  time.Duration
	serialExecution bool

	mu       sync.RWMutex
	tools    []toolEntry
	store    *sessionStore
	ln       net.Listener
}

// New creates a new MCP server with the given name. The name is required and
// must be non-empty; New panics otherwise. Configure the server further with
// Option values.
func New(name string, opts ...Option) *Server {
	if name == "" {
		panic("mcpserver: name must not be empty")
	}
	s := &Server{
		name:            name,
		version:         "0.0.0-dev",
		port:            8080,
		logger:          slog.Default(),
		shutdownTimeout: 10 * time.Second,
		readTimeout:     30 * time.Second,
		writeTimeout:    30 * time.Second,
		store:           newSessionStore(),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// ServeHTTP implements http.Handler. It dispatches POST / to the JSON-RPC
// handler and GET /health to the health endpoint. All other method/path
// combinations return 404 or 405.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		switch r.Method {
		case http.MethodPost:
			s.handleJSONRPC(w, r)
		case http.MethodDelete:
			s.handleDelete(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	case "/health":
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleHealth(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleJSONRPC reads a JSON-RPC 2.0 request from the HTTP body, dispatches
// it, and writes the response.
func (s *Server) handleJSONRPC(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, nil, codeParseError, "failed to read request body")
		return
	}

	var req jsonrpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, nil, codeParseError, "parse error: invalid JSON")
		return
	}

	if req.JSONRPC != jsonrpcVersion {
		s.writeError(w, req.ID, codeInvalidRequest, "invalid jsonrpc version")
		return
	}

	if req.Method == "" {
		s.writeError(w, req.ID, codeInvalidRequest, "method is required")
		return
	}

	// Extract W3C trace context (traceparent header) from the incoming
	// HTTP request so that downstream spans are linked to the caller's
	// trace. Uses the global propagator by default.
	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

	// Session validation: initialize creates a session; all other methods
	// require a valid Mcp-Session-Id header.
	if req.Method == "initialize" {
		sess := s.store.create()
		resp := s.dispatch(ctx, &req)
		w.Header().Set("Mcp-Session-Id", sess.id)
		s.writeResponse(w, resp)
		return
	}

	// All non-initialize requests require a valid session.
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	sess, ok := s.store.get(sessionID)
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Check for idle expiry.
	if sess.isExpired(s.sessionTimeout) {
		s.store.delete(sessionID)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Handle notifications/initialized: transition to active state.
	if req.Method == "notifications/initialized" {
		s.store.markActive(sessionID)
		sess.touch()
		w.WriteHeader(http.StatusOK)
		return
	}

	// tools/list and tools/call require session in "active" state.
	if sess.state != stateActive {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Refresh lastAccess on every successful request.
	sess.touch()

	// If serial execution is enabled, acquire the per-session mutex.
	if s.serialExecution {
		sess.mu.Lock()
		defer sess.mu.Unlock()
	}

	// Inject session ID into context so the middleware pipeline can access it.
	ctx = withToolCallContext(ctx, "", sessionID)
	resp := s.dispatch(ctx, &req)
	if resp == nil {
		// Notification -- return 200 with empty body.
		w.WriteHeader(http.StatusOK)
		return
	}
	s.writeResponse(w, resp)
}

// writeResponse marshals a JSON-RPC response and writes it to the client.
func (s *Server) writeResponse(w http.ResponseWriter, resp *jsonrpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("failed to write response", "error", err)
	}
}

// writeError sends a JSON-RPC error response.
func (s *Server) writeError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	resp := &jsonrpcResponse{
		JSONRPC: jsonrpcVersion,
		ID:      id,
		Error:   &jsonrpcError{Code: code, Message: msg},
	}
	s.writeResponse(w, resp)
}

// handleDelete handles DELETE / requests for session termination.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if _, ok := s.store.get(sessionID); !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	s.store.delete(sessionID)
	w.WriteHeader(http.StatusOK)
}

// Run starts the HTTP server and blocks until SIGINT or SIGTERM is received.
// It performs a graceful shutdown, waiting up to ShutdownTimeout for
// in-flight requests to complete.
func (s *Server) Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return s.RunContext(ctx)
}

// defaultCleanupInterval is the interval between session cleanup sweeps.
const defaultCleanupInterval = 60 * time.Second

// defaultSessionTimeout is the default idle timeout for sessions.
const defaultSessionTimeout = 30 * time.Minute

// RunContext starts the HTTP server and blocks until the provided context is
// cancelled. It performs a graceful shutdown, waiting up to ShutdownTimeout
// for in-flight requests to complete. The actual listener address is stored
// and can be retrieved via Addr after the server has started.
func (s *Server) RunContext(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.address, s.port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      s,
		ReadTimeout:  s.readTimeout,
		WriteTimeout: s.writeTimeout,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("mcpserver: listen: %w", err)
	}

	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()

	// Start the session cleanup goroutine. It stops when cleanupCtx is
	// cancelled during shutdown.
	cleanupCtx, cleanupCancel := context.WithCancel(ctx)
	defer cleanupCancel()

	timeout := s.sessionTimeout
	if timeout == 0 {
		timeout = defaultSessionTimeout
	}
	s.store.startCleanup(cleanupCtx, defaultCleanupInterval, timeout)

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("server started", "name", s.name, "address", ln.Addr().String())
		errCh <- srv.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("context cancelled, shutting down")
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			cleanupCancel()
			return fmt.Errorf("mcpserver: serve: %w", err)
		}
	}

	// Stop the cleanup goroutine before shutting down the HTTP server.
	cleanupCancel()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("mcpserver: shutdown: %w", err)
	}

	s.logger.Info("server stopped")
	return nil
}

// Addr returns the listener's network address once the server has started
// via Run or RunContext. It returns nil if the server has not started.
func (s *Server) Addr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// initPipeline builds the middleware pipeline according to the fixed
// ordering defined in ADR-003:
//
//  1. Rate Limiting
//  2. Context Injection
//  3. Role Visibility (if enabled)
//  4. OTel (creates per-call spans; disable with WithoutOTel)
//  5. Caching
//  6. Custom Middleware
//  7. Logging
//
// The pipeline is built once and reused for all subsequent tool calls.
func (s *Server) initPipeline() {
	s.pipelineOnce.Do(func() {
		var mws []Middleware

		// Resolve tracer once for middleware that optionally emit spans.
		var tracer trace.Tracer
		if !s.otelDisabled {
			tracer = s.tracer()
		}

		// 1. Rate Limiting (outermost -- rejects before any work).
		if !s.rateLimitDisabled {
			rps := s.rateRPS
			burst := s.rateBurst
			if rps == 0 {
				rps = defaultRateLimit
			}
			if burst == 0 {
				burst = defaultRateBurst
			}
			var rlOpts []rateLimitOption
			if tracer != nil {
				rlOpts = append(rlOpts, withRateLimitTracer(tracer))
			}
			mws = append(mws, newRateLimitMiddleware(rps, burst, rlOpts...))
		}

		// 2. Context Injection (always on).
		mws = append(mws, newContextMiddleware(s.name))

		// 3. Role Visibility (off by default).
		if s.roleVisibilityFilter != nil {
			filter := s.roleVisibilityFilter
			mws = append(mws, newRoleVisibilityMiddleware(filter))
		}

		// 4. OTel (on by default -- creates spans per tools/call).
		if !s.otelDisabled {
			mws = append(mws, newOTelMiddleware(s.tracer()))
		}

		// 5. Caching.
		if !s.cachingDisabled {
			ttl := s.cacheTTL
			if ttl == 0 {
				ttl = defaultCacheTTL
			}
			var cOpts []cacheOption
			if tracer != nil {
				cOpts = append(cOpts, withCacheTracer(tracer))
			}
			mws = append(mws, newCacheMiddleware(ttl, cOpts...))
		}

		// 6. Custom Middleware.
		mws = append(mws, s.customMiddleware...)

		// 7. Logging (innermost -- captures duration of everything above).
		mws = append(mws, newLoggingMiddleware(s.logger))

		s.pipeline = buildPipeline(mws)
	})
}

// wrappedHandler returns the raw ToolHandler wrapped by the middleware
// pipeline. This is called for every tools/call dispatch.
func (s *Server) wrappedHandler(handler ToolHandler) ToolHandler {
	s.initPipeline()
	return s.pipeline(handler)
}

// Package mcpserver provides a minimal MCP (Model Context Protocol) server
// framework. It exposes a JSON-RPC 2.0 interface over HTTP, implementing the
// core MCP handshake (initialize / notifications/initialized) and tool
// dispatch (tools/list, tools/call).
//
// Usage:
//
//	server := mcpserver.New("my-server",
//	    mcpserver.WithPort(8082),
//	    mcpserver.WithVersion("1.0.0"),
//	)
//
//	server.Tool("echo", "Echoes input", mcpserver.Schema{
//	    Type:     "object",
//	    Required: []string{"message"},
//	    Properties: map[string]mcpserver.Property{
//	        "message": {Type: "string", Description: "Message to echo"},
//	    },
//	}, func(ctx context.Context, args map[string]any) (any, error) {
//	    return args["message"], nil
//	})
//
//	server.Run() // blocks until SIGINT/SIGTERM
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
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

	mu       sync.RWMutex
	tools    []toolEntry
	sessions sync.Map // sessionID (string) -> struct{}
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
		version:         "0.0.0",
		port:            8080,
		logger:          slog.Default(),
		shutdownTimeout: 5 * time.Second,
		readTimeout:     10 * time.Second,
		writeTimeout:    10 * time.Second,
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
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleJSONRPC(w, r)
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

	// Session validation: initialize creates a session; all other methods
	// require a valid Mcp-Session-Id header.
	if req.Method == "initialize" {
		sessionID := uuid.New().String()
		s.sessions.Store(sessionID, struct{}{})
		resp := s.dispatch(r.Context(), &req)
		w.Header().Set("Mcp-Session-Id", sessionID)
		s.writeResponse(w, resp)
		return
	}

	// All non-initialize requests require a valid session.
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if _, ok := s.sessions.Load(sessionID); !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	resp := s.dispatch(r.Context(), &req)
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

// Run starts the HTTP server and blocks until SIGINT or SIGTERM is received.
// It performs a graceful shutdown, waiting up to ShutdownTimeout for
// in-flight requests to complete.
func (s *Server) Run() error {
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

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("server started", "name", s.name, "address", addr)
		errCh <- srv.Serve(ln)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		s.logger.Info("received signal, shutting down", "signal", sig)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("mcpserver: serve: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("mcpserver: shutdown: %w", err)
	}

	s.logger.Info("server stopped")
	return nil
}

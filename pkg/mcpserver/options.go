package mcpserver

import (
	"log/slog"
	"time"
)

// Option configures a Server via functional options passed to New.
type Option func(*Server)

// WithVersion sets the server version reported in initialize responses and
// health checks. Defaults to "0.0.0-dev".
func WithVersion(v string) Option {
	return func(s *Server) {
		s.version = v
	}
}

// WithPort sets the TCP port the server listens on. Defaults to 8080.
func WithPort(port int) Option {
	return func(s *Server) {
		s.port = port
	}
}

// WithAddress sets the bind address. Defaults to "" (all interfaces).
func WithAddress(addr string) Option {
	return func(s *Server) {
		s.address = addr
	}
}

// WithLogger sets a structured logger. Defaults to slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(s *Server) {
		s.logger = l
	}
}

// WithShutdownTimeout sets the graceful shutdown deadline. Defaults to 10s.
func WithShutdownTimeout(d time.Duration) Option {
	return func(s *Server) {
		s.shutdownTimeout = d
	}
}

// WithReadTimeout sets the HTTP server read timeout. Defaults to 30s.
func WithReadTimeout(d time.Duration) Option {
	return func(s *Server) {
		s.readTimeout = d
	}
}

// WithWriteTimeout sets the HTTP server write timeout. Defaults to 30s.
func WithWriteTimeout(d time.Duration) Option {
	return func(s *Server) {
		s.writeTimeout = d
	}
}

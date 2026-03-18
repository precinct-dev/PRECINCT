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

// WithoutCaching disables the response cache middleware. By default,
// caching is enabled with a 5-minute TTL.
func WithoutCaching() Option {
	return func(s *Server) {
		s.cachingDisabled = true
	}
}

// WithCacheTTL sets the TTL for the response cache. Implies caching is
// enabled. Defaults to 5 minutes.
func WithCacheTTL(d time.Duration) Option {
	return func(s *Server) {
		s.cacheTTL = d
	}
}

// WithoutRateLimiting disables the rate-limiting middleware. By default,
// rate limiting is enabled at 100 requests per second with a burst of 10.
func WithoutRateLimiting() Option {
	return func(s *Server) {
		s.rateLimitDisabled = true
	}
}

// WithRateLimit configures the rate limiter with a custom sustained rate
// (requests per second) and burst size. Implies rate limiting is enabled.
func WithRateLimit(rps float64, burst int) Option {
	return func(s *Server) {
		s.rateRPS = rps
		s.rateBurst = burst
	}
}

// WithMiddleware appends custom middleware to the pipeline. Custom
// middleware runs after caching and before logging, allowing it to
// observe cache-resolved results while still being logged.
func WithMiddleware(mw ...Middleware) Option {
	return func(s *Server) {
		s.customMiddleware = append(s.customMiddleware, mw...)
	}
}

// WithRoleVisibility enables role-visibility filtering for tool calls.
// When enabled, the role visibility middleware is inserted into the
// pipeline at its designated position (after context injection, before
// caching). The filter function receives the context and tool name, and
// should return true if the tool is visible to the current caller.
func WithRoleVisibility(filter func(toolName string, role string) bool) Option {
	return func(s *Server) {
		s.roleVisibilityFilter = filter
	}
}

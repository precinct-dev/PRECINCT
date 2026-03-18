package mcpserver

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/trace"
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
// should return true if the tool is visible to the current caller. The
// caller's role can be extracted from the context via Role(ctx).
func WithRoleVisibility(filter func(ctx context.Context, toolName string) bool) Option {
	return func(s *Server) {
		s.roleVisibilityFilter = filter
	}
}

// WithSessionTimeout sets the idle timeout for sessions. Sessions that
// have not received a request within this duration are considered expired
// and will be cleaned up. Defaults to 30 minutes.
func WithSessionTimeout(d time.Duration) Option {
	return func(s *Server) {
		s.sessionTimeout = d
	}
}

// WithSerialExecution enables per-session serial execution for tools/call
// requests. When enabled, concurrent tools/call requests on the same
// session are serialized via a per-session mutex. Different sessions
// still execute concurrently.
func WithSerialExecution() Option {
	return func(s *Server) {
		s.serialExecution = true
	}
}

// WithTracerProvider sets a custom OpenTelemetry TracerProvider for span
// creation. When not set, the server uses otel.GetTracerProvider() (the
// global provider). The framework creates spans but never creates
// exporters -- the caller owns the TracerProvider lifecycle.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(s *Server) {
		s.tracerProvider = tp
	}
}

// WithoutOTel disables OpenTelemetry span creation. By default, the OTel
// middleware is enabled and creates spans per tools/call invocation.
func WithoutOTel() Option {
	return func(s *Server) {
		s.otelDisabled = true
	}
}

// WithSPIRE enables SPIRE-based mTLS. The server will connect to the SPIRE
// Agent via the Workload API at the given Unix socket path, obtain an X.509
// SVID, and serve TLS with RequireAndVerifyClientCert. Without this option,
// the server runs in dev mode (plaintext HTTP).
//
// The SPIRE_AGENT_SOCKET environment variable, if set, overrides socketPath.
func WithSPIRE(socketPath string) Option {
	return func(s *Server) {
		s.spireSocketPath = socketPath
	}
}

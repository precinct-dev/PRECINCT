package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
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

// applyEnvOverrides reads well-known environment variables and applies them
// to the server configuration. Environment variables take precedence over
// functional options. Invalid values produce errors with the standard
// "mcpserver: <message>" format.
//
// Supported variables:
//
//	PORT                -> s.port
//	SPIRE_AGENT_SOCKET  -> s.spireSocketPath (already handled by resolveSpireSocketPath)
//	LOG_LEVEL           -> s.logger level (debug, info, warn, error)
//	CACHE_ENABLED       -> s.cachingDisabled (false disables)
//	CACHE_TTL           -> s.cacheTTL
//	RATE_LIMIT_ENABLED  -> s.rateLimitDisabled (false disables)
//	RATE_LIMIT_RPS      -> s.rateRPS
//	RATE_LIMIT_BURST    -> s.rateBurst
//	SHUTDOWN_TIMEOUT    -> s.shutdownTimeout
func applyEnvOverrides(s *Server) error {
	var errs []error

	// PORT
	if v, ok := os.LookupEnv("PORT"); ok && v != "" {
		port, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("mcpserver: invalid PORT %q: %w", v, err))
		} else {
			s.port = port
		}
	}

	// SPIRE_AGENT_SOCKET -- resolved at validation/run time via
	// resolveSpireSocketPath, but we also set it directly so that
	// validate() picks it up.
	if v, ok := os.LookupEnv("SPIRE_AGENT_SOCKET"); ok && v != "" {
		s.spireSocketPath = v
	}

	// LOG_LEVEL
	if v, ok := os.LookupEnv("LOG_LEVEL"); ok && v != "" {
		lower := strings.ToLower(v)
		if !validLogLevels[lower] {
			errs = append(errs, fmt.Errorf("mcpserver: invalid LOG_LEVEL %q: must be one of debug, info, warn, error", v))
		} else {
			var level slog.Level
			switch lower {
			case "debug":
				level = slog.LevelDebug
			case "info":
				level = slog.LevelInfo
			case "warn":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			}
			s.logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
		}
	}

	// CACHE_ENABLED
	if v, ok := os.LookupEnv("CACHE_ENABLED"); ok && v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("mcpserver: invalid CACHE_ENABLED %q: %w", v, err))
		} else {
			s.cachingDisabled = !b
		}
	}

	// CACHE_TTL
	if v, ok := os.LookupEnv("CACHE_TTL"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("mcpserver: invalid CACHE_TTL %q: %w", v, err))
		} else {
			s.cacheTTL = d
		}
	}

	// RATE_LIMIT_ENABLED
	if v, ok := os.LookupEnv("RATE_LIMIT_ENABLED"); ok && v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("mcpserver: invalid RATE_LIMIT_ENABLED %q: %w", v, err))
		} else {
			s.rateLimitDisabled = !b
		}
	}

	// RATE_LIMIT_RPS
	if v, ok := os.LookupEnv("RATE_LIMIT_RPS"); ok && v != "" {
		rps, err := strconv.ParseFloat(v, 64)
		if err != nil {
			errs = append(errs, fmt.Errorf("mcpserver: invalid RATE_LIMIT_RPS %q: %w", v, err))
		} else {
			s.rateRPS = rps
		}
	}

	// RATE_LIMIT_BURST
	if v, ok := os.LookupEnv("RATE_LIMIT_BURST"); ok && v != "" {
		burst, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("mcpserver: invalid RATE_LIMIT_BURST %q: %w", v, err))
		} else {
			s.rateBurst = burst
		}
	}

	// SHUTDOWN_TIMEOUT
	if v, ok := os.LookupEnv("SHUTDOWN_TIMEOUT"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("mcpserver: invalid SHUTDOWN_TIMEOUT %q: %w", v, err))
		} else {
			s.shutdownTimeout = d
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%w", joinErrors(errs))
}

// joinErrors combines multiple errors into a single error using errors.Join.
func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	// Use a simple newline-separated format for batch errors.
	var msgs []string
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	return fmt.Errorf("%s", strings.Join(msgs, "\n"))
}

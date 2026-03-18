package mcpserver

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"
)

// defaultRateLimit is the default sustained rate (requests per second).
const defaultRateLimit = 100

// defaultRateBurst is the default burst size for the token bucket.
const defaultRateBurst = 10

// newRateLimitMiddleware returns a Middleware that enforces a token-bucket
// rate limit using golang.org/x/time/rate. When the limiter cannot
// immediately grant a token, the handler returns an error rather than
// blocking. If a non-nil tracer is provided, each evaluation creates a
// child span "middleware.rate_limit" with an mcp.rate_limit.allowed bool
// attribute.
func newRateLimitMiddleware(rps float64, burst int, opts ...rateLimitOption) Middleware {
	cfg := rateLimitConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	limiter := rate.NewLimiter(rate.Limit(rps), burst)
	return func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args map[string]any) (any, error) {
			allowed := limiter.Allow()

			if cfg.tracer != nil {
				var span trace.Span
				ctx, span = cfg.tracer.Start(ctx, "middleware.rate_limit",
					trace.WithSpanKind(trace.SpanKindInternal))
				span.SetAttributes(attribute.Bool("mcp.rate_limit.allowed", allowed))
				span.End()
			}

			if !allowed {
				return nil, fmt.Errorf("rate limit exceeded")
			}
			return next(ctx, args)
		}
	}
}

// rateLimitConfig holds optional configuration for the rate limit middleware.
type rateLimitConfig struct {
	tracer trace.Tracer
}

// rateLimitOption configures the rate limit middleware.
type rateLimitOption func(*rateLimitConfig)

// withRateLimitTracer sets the OTel tracer for the rate limit middleware.
func withRateLimitTracer(t trace.Tracer) rateLimitOption {
	return func(c *rateLimitConfig) {
		c.tracer = t
	}
}

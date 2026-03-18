package mcpserver

import (
	"context"
	"fmt"

	"golang.org/x/time/rate"
)

// defaultRateLimit is the default sustained rate (requests per second).
const defaultRateLimit = 100

// defaultRateBurst is the default burst size for the token bucket.
const defaultRateBurst = 10

// newRateLimitMiddleware returns a Middleware that enforces a token-bucket
// rate limit using golang.org/x/time/rate. When the limiter cannot
// immediately grant a token, the handler returns an error rather than
// blocking.
func newRateLimitMiddleware(rps float64, burst int) Middleware {
	limiter := rate.NewLimiter(rate.Limit(rps), burst)
	return func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args map[string]any) (any, error) {
			if !limiter.Allow() {
				return nil, fmt.Errorf("rate limit exceeded")
			}
			return next(ctx, args)
		}
	}
}

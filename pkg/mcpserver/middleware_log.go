package mcpserver

import (
	"context"
	"log/slog"
	"sort"
	"time"
)

// newLoggingMiddleware returns a Middleware that logs every tool call
// using the provided structured logger. It records the tool name,
// duration, outcome (success/error), and a redacted representation of
// the arguments (keys only, values replaced with "[REDACTED]").
func newLoggingMiddleware(logger *slog.Logger) Middleware {
	return func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args map[string]any) (any, error) {
			start := time.Now()
			toolName := ToolNameFromContext(ctx)

			result, err := next(ctx, args)
			duration := time.Since(start)

			attrs := []slog.Attr{
				slog.String("tool", toolName),
				slog.Duration("duration", duration),
				slog.Any("args", redactArgs(args)),
			}

			if err != nil {
				attrs = append(attrs, slog.String("outcome", "error"), slog.String("error", err.Error()))
				logger.LogAttrs(ctx, slog.LevelError, "tool call failed", attrs...)
			} else {
				attrs = append(attrs, slog.String("outcome", "success"))
				logger.LogAttrs(ctx, slog.LevelInfo, "tool call completed", attrs...)
			}

			return result, err
		}
	}
}

// redactArgs returns a map with the same keys as the input but all values
// replaced with "[REDACTED]". This prevents sensitive data from leaking
// into logs. Keys are sorted for deterministic output.
func redactArgs(args map[string]any) map[string]string {
	if len(args) == 0 {
		return nil
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	redacted := make(map[string]string, len(keys))
	for _, k := range keys {
		redacted[k] = "[REDACTED]"
	}
	return redacted
}

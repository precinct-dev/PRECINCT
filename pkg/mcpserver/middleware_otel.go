package mcpserver

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// newOTelMiddleware returns a Middleware that creates a span for every
// tools/call invocation. The span records the tool name, duration in
// milliseconds, and outcome (success or error). On error, the span status
// is set to codes.Error with the error message.
//
// The middleware reads the tool name from the context (set by the context
// injection middleware) and constructs a span named
// "mcpserver.tools/call.<toolName>".
func newOTelMiddleware(tracer trace.Tracer) Middleware {
	return func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args map[string]any) (any, error) {
			toolName := ToolNameFromContext(ctx)
			spanName := "mcpserver.tools/call." + toolName

			ctx, span := tracer.Start(ctx, spanName, trace.WithSpanKind(trace.SpanKindServer))
			defer span.End()

			span.SetAttributes(attribute.String("tool.name", toolName))

			start := time.Now()
			result, err := next(ctx, args)
			durationMs := float64(time.Since(start).Milliseconds())

			span.SetAttributes(attribute.Float64("tool.duration_ms", durationMs))

			if err != nil {
				span.SetAttributes(attribute.String("tool.outcome", "error"))
				span.SetStatus(codes.Error, err.Error())
				span.RecordError(err)
			} else {
				span.SetAttributes(attribute.String("tool.outcome", "success"))
				span.SetStatus(codes.Ok, "")
			}

			return result, err
		}
	}
}

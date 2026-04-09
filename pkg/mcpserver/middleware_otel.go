// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// newOTelMiddleware returns a Middleware that creates a span for every
// tools/call invocation. The span records the tool name, server name,
// session ID, duration in milliseconds, and outcome (success or error).
// On error, the span status is set to codes.Error with the error message.
//
// The middleware reads the tool name, server name, and session ID from
// the context (set by the context injection middleware) and constructs a
// span named "mcpserver.tools/call.<toolName>".
//
// Attribute names follow the mcp.* namespace convention:
//   - mcp.tool.name: the tool being invoked
//   - mcp.server.name: the MCP server name
//   - mcp.session.id: the MCP session identifier
//   - mcp.tool.duration_ms: wall-clock execution time
//   - mcp.tool.outcome: "success" or "error"
func newOTelMiddleware(tracer trace.Tracer) Middleware {
	return func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args map[string]any) (any, error) {
			toolName := ToolNameFromContext(ctx)
			spanName := "mcpserver.tools/call." + toolName

			ctx, span := tracer.Start(ctx, spanName, trace.WithSpanKind(trace.SpanKindServer))
			defer span.End()

			span.SetAttributes(
				attribute.String("mcp.tool.name", toolName),
				attribute.String("mcp.server.name", ServerNameFromContext(ctx)),
				attribute.String("mcp.session.id", SessionIDFromContext(ctx)),
			)

			start := time.Now()
			result, err := next(ctx, args)
			durationMs := float64(time.Since(start).Milliseconds())

			span.SetAttributes(attribute.Float64("mcp.tool.duration_ms", durationMs))

			if err != nil {
				span.SetAttributes(attribute.String("mcp.tool.outcome", "error"))
				span.SetStatus(codes.Error, err.Error())
				span.RecordError(err)
			} else {
				span.SetAttributes(attribute.String("mcp.tool.outcome", "success"))
				span.SetStatus(codes.Ok, "")
			}

			return result, err
		}
	}
}

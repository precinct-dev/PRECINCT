// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// tracerName is the instrumentation scope name used for all spans created
// by this package.
const tracerName = "github.com/precinct-dev/precinct/pkg/mcpserver"

// tracer returns the trace.Tracer for this server. If a custom
// TracerProvider was injected via WithTracerProvider, that provider is
// used; otherwise it falls back to otel.GetTracerProvider() (the global).
func (s *Server) tracer() trace.Tracer {
	tp := s.tracerProvider
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	return tp.Tracer(tracerName)
}

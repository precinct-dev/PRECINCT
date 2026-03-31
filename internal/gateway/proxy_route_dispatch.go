package gateway

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type proxyRouteDispatch struct {
	reason     string
	middleware string
	step       int
	try        func(*Gateway, *proxyResponseWriter, *http.Request) bool
}

func (g *Gateway) tryInternalProxyRoutes(proxyRW *proxyResponseWriter, r *http.Request, span trace.Span) bool {
	if allowed, contractID := g.enforceOPABypassCompensatingChecks(proxyRW, r); !allowed {
		result := proxyDispatchResult(proxyRW.statusCode)
		attrs := []attribute.KeyValue{
			attribute.Int("status_code", proxyRW.statusCode),
			attribute.String("mcp.result", result),
			attribute.String("mcp.reason", "opa_bypass_compensating_check"),
		}
		if contractID != "" {
			attrs = append(attrs, attribute.String("mcp.contract_id", contractID))
		}
		span.SetAttributes(attrs...)
		return true
	}

	if g.tryDemoProxyRoute(proxyRW, r, span) {
		return true
	}

	if handled, portName := g.tryPortAdapterRoute(proxyRW, r); handled {
		g.setProxyRouteSpanAttributes(
			span,
			proxyRW,
			"port_adapter_"+portName,
			"port_"+portName,
			v24MiddlewareStep,
			r.URL.Path,
		)
		return true
	}

	for _, route := range g.internalProxyRoutes() {
		if route.try(g, proxyRW, r) {
			g.setProxyRouteSpanAttributes(span, proxyRW, route.reason, route.middleware, route.step, r.URL.Path)
			return true
		}
	}

	return false
}

func (g *Gateway) internalProxyRoutes() []proxyRouteDispatch {
	return []proxyRouteDispatch{
		{
			reason:     "connector_conformance_entry",
			middleware: v24MiddlewareConnectorAuth,
			step:       v24MiddlewareStep,
			try: func(g *Gateway, proxyRW *proxyResponseWriter, r *http.Request) bool {
				return g.handleConnectorAuthorityEntry(proxyRW, r)
			},
		},
		{
			reason: "v24_admin_entry",
			step:   v24MiddlewareStep,
			try: func(g *Gateway, proxyRW *proxyResponseWriter, r *http.Request) bool {
				return g.handleV24AdminEntry(proxyRW, r)
			},
		},
		{
			reason:     "phase3_plane_entry",
			middleware: v24MiddlewarePhase3Plane,
			step:       v24MiddlewareStep,
			try: func(g *Gateway, proxyRW *proxyResponseWriter, r *http.Request) bool {
				return g.handlePhase3PlaneEntry(proxyRW, r)
			},
		},
		{
			reason:     "phase3_model_egress",
			middleware: v24MiddlewareModelCompat,
			step:       v24MiddlewareStep,
			try: func(g *Gateway, proxyRW *proxyResponseWriter, r *http.Request) bool {
				return g.handleModelCompatEntry(proxyRW, r)
			},
		},
	}
}

func (g *Gateway) tryPortAdapterRoute(proxyRW *proxyResponseWriter, r *http.Request) (bool, string) {
	for _, port := range g.portAdapters {
		if port.TryServeHTTP(proxyRW, r) {
			return true, port.Name()
		}
	}
	return false, ""
}

func (g *Gateway) tryDemoProxyRoute(proxyRW *proxyResponseWriter, r *http.Request, span trace.Span) bool {
	switch r.URL.Path {
	case "/__demo__/rugpull/on", "/__demo__/rugpull/off":
		enable := r.URL.Path == "/__demo__/rugpull/on"
		g.handleDemoRugpullToggle(proxyRW, r, enable)
		g.setProxyRouteSpanAttributes(span, proxyRW, "demo rugpull endpoint", "", 0, "")
		return true
	case "/__demo__/ratelimit":
		if g.config == nil || !g.config.DemoRugpullAdminEnabled || g.config.SPIFFEMode != "dev" {
			http.NotFound(proxyRW, r)
			span.SetAttributes(
				attribute.String("mcp.result", "denied"),
				attribute.String("mcp.reason", "demo endpoints disabled"),
			)
			return true
		}
		if r.Method != http.MethodGet {
			proxyRW.WriteHeader(http.StatusMethodNotAllowed)
			span.SetAttributes(
				attribute.String("mcp.result", "denied"),
				attribute.String("mcp.reason", "method not allowed"),
			)
			return true
		}
		proxyRW.Header().Set("Content-Type", "application/json")
		proxyRW.WriteHeader(http.StatusOK)
		_, _ = proxyRW.Write([]byte(`{"ok":true}`))
		g.setProxyRouteSpanAttributes(span, proxyRW, "demo ratelimit endpoint", "", 0, "")
		return true
	default:
		return false
	}
}

func (g *Gateway) setProxyRouteSpanAttributes(span trace.Span, proxyRW *proxyResponseWriter, reason, middleware string, step int, endpoint string) {
	attrs := []attribute.KeyValue{
		attribute.Int("status_code", proxyRW.statusCode),
		attribute.String("mcp.result", proxyDispatchResult(proxyRW.statusCode)),
		attribute.String("mcp.reason", reason),
	}
	if middleware == "" && reason == "v24_admin_entry" {
		middleware = adminMiddlewareForPath(endpoint)
	}
	if middleware != "" {
		attrs = append(attrs, attribute.String("mcp.gateway.middleware", middleware))
	}
	if step > 0 {
		attrs = append(attrs, attribute.Int("mcp.gateway.step", step))
	}
	if endpoint != "" {
		attrs = append(attrs, attribute.String("mcp.v24.endpoint", endpoint))
	}
	span.SetAttributes(attrs...)
}

func proxyDispatchResult(statusCode int) string {
	if statusCode >= http.StatusBadRequest {
		return "denied"
	}
	return "allowed"
}

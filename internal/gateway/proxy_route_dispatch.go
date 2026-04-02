package gateway

import (
	"net/http"

	"github.com/precinct-dev/precinct/internal/precinctcontrol"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func (g *Gateway) tryGatewayProxyRoutes(proxyRW *proxyResponseWriter, r *http.Request, span trace.Span) bool {
	return precinctcontrol.DispatchInternalProxyRoutes(
		proxyRW,
		r,
		span,
		precinctcontrol.DispatchConfig{
			EnforceOPABypass: g.enforceOPABypassCompensatingChecks,
			TryDemoRoute: func(w http.ResponseWriter, req *http.Request, routeSpan trace.Span) bool {
				proxyResponseWriter, ok := w.(*proxyResponseWriter)
				if !ok {
					return false
				}
				return g.tryDemoProxyRoute(proxyResponseWriter, req, routeSpan)
			},
			TryPortAdapterRoute: func(w http.ResponseWriter, req *http.Request) (bool, string) {
				proxyResponseWriter, ok := w.(*proxyResponseWriter)
				if !ok {
					return false, ""
				}
				return g.tryPortAdapterRoute(proxyResponseWriter, req)
			},
			PortAdapterRouteStep: v24MiddlewareStep,
			InternalRoutes:       g.gatewayInternalRoutes(),
			OnRouteMatched:       g.setProxyRouteSpanAttributes,
		},
	)
}

func (g *Gateway) tryControlProxyRoutes(proxyRW *proxyResponseWriter, r *http.Request, span trace.Span) bool {
	return precinctcontrol.DispatchInternalProxyRoutes(
		proxyRW,
		r,
		span,
		precinctcontrol.DispatchConfig{
			EnforceOPABypass: g.enforceOPABypassCompensatingChecks,
			InternalRoutes:   g.controlServiceRoutes(),
			OnRouteMatched:   g.setProxyRouteSpanAttributes,
		},
	)
}

func (g *Gateway) gatewayInternalRoutes() []precinctcontrol.ControlRoute {
	return []precinctcontrol.ControlRoute{
		{
			Reason:     "phase3_plane_entry",
			Middleware: v24MiddlewarePhase3Plane,
			Step:       v24MiddlewareStep,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				return g.handlePhase3PlaneEntry(w, r)
			},
		},
		{
			Reason:     "phase3_model_egress",
			Middleware: v24MiddlewareModelCompat,
			Step:       v24MiddlewareStep,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				return g.handleModelCompatEntry(w, r)
			},
		},
	}
}

func (g *Gateway) controlServiceRoutes() []precinctcontrol.ControlRoute {
	return []precinctcontrol.ControlRoute{
		{
			Reason:     "connector_authority_entry",
			Middleware: v24MiddlewareConnectorAuth,
			Step:       v24MiddlewareStep,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				return g.handleConnectorAuthorityEntry(w, r)
			},
		},
		{
			Reason: "v24_admin_entry",
			Step:   v24MiddlewareStep,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				return g.handleV24AdminEntry(w, r)
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
		g.setProxyRouteSpanAttributes(span, proxyRW.statusCode, "demo rugpull endpoint", "", 0, "", "")
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
		g.setProxyRouteSpanAttributes(span, proxyRW.statusCode, "demo ratelimit endpoint", "", 0, "", "")
		return true
	}
	return false
}

func (g *Gateway) setProxyRouteSpanAttributes(span trace.Span, statusCode int, reason, middleware string, step int, endpoint, contractID string) {
	attrs := []attribute.KeyValue{
		attribute.Int("status_code", statusCode),
		attribute.String("mcp.result", proxyDispatchResult(statusCode)),
		attribute.String("mcp.reason", reason),
	}
	if contractID != "" {
		attrs = append(attrs, attribute.String("mcp.contract_id", contractID))
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

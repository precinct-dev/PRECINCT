package precinctcontrol

import (
	"net/http"

	"go.opentelemetry.io/otel/trace"
)

type RouteDispatchResponseWriter interface {
	http.ResponseWriter
	StatusCode() int
}

type ControlRoute struct {
	Reason     string
	Middleware string
	Step       int
	Try        func(http.ResponseWriter, *http.Request) bool
}

type DispatchConfig struct {
	EnforceOPABypass     func(http.ResponseWriter, *http.Request) (bool, string)
	TryDemoRoute         func(http.ResponseWriter, *http.Request, trace.Span) bool
	TryPortAdapterRoute  func(http.ResponseWriter, *http.Request) (bool, string)
	PortAdapterRouteStep int
	InternalRoutes       []ControlRoute
	OnRouteMatched       func(trace.Span, int, string, string, int, string, string)
}

func DispatchInternalProxyRoutes(w RouteDispatchResponseWriter, r *http.Request, span trace.Span, cfg DispatchConfig) bool {
	if cfg.EnforceOPABypass != nil {
		allowed, contractID := cfg.EnforceOPABypass(w, r)
		if !allowed {
			if cfg.OnRouteMatched != nil {
				cfg.OnRouteMatched(
					span,
					w.StatusCode(),
					"opa_bypass_compensating_check",
					"",
					0,
					"",
					contractID,
				)
			}
			return true
		}
	}

	if cfg.TryDemoRoute != nil && cfg.TryDemoRoute(w, r, span) {
		return true
	}

	if cfg.TryPortAdapterRoute != nil {
		if handled, portName := cfg.TryPortAdapterRoute(w, r); handled {
			if cfg.OnRouteMatched != nil {
				cfg.OnRouteMatched(
					span,
					w.StatusCode(),
					"port_adapter_"+portName,
					"port_"+portName,
					cfg.PortAdapterRouteStep,
					r.URL.Path,
					"",
				)
			}
			return true
		}
	}

	for _, route := range cfg.InternalRoutes {
		if route.Try != nil && route.Try(w, r) {
			if cfg.OnRouteMatched != nil {
				cfg.OnRouteMatched(
					span,
					w.StatusCode(),
					route.Reason,
					route.Middleware,
					route.Step,
					r.URL.Path,
					"",
				)
			}
			return true
		}
	}

	return false
}

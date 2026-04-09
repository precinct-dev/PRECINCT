// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcontrol

import "net/http"

type InternalGatewayControlRoutes struct {
	HandleConnectorAuthorityEntry func(http.ResponseWriter, *http.Request) bool
	HandleV24AdminEntry           func(http.ResponseWriter, *http.Request) bool
	HandlePhase3PlaneEntry        func(http.ResponseWriter, *http.Request) bool
	HandleModelCompatEntry        func(http.ResponseWriter, *http.Request) bool
}

type ControlRouteConfig struct {
	MiddlewareStep        int
	ConnectorMiddleware   string
	Phase3Middleware      string
	ModelCompatMiddleware string
}

func BuildInternalControlRoutes(cfg ControlRouteConfig, handlers InternalGatewayControlRoutes) []ControlRoute {
	connectorMiddleware := cfg.ConnectorMiddleware
	if connectorMiddleware == "" {
		connectorMiddleware = "v24_connector_authority"
	}
	phase3Middleware := cfg.Phase3Middleware
	if phase3Middleware == "" {
		phase3Middleware = "v24_phase3_plane"
	}
	modelCompatMiddleware := cfg.ModelCompatMiddleware
	if modelCompatMiddleware == "" {
		modelCompatMiddleware = "v24_model_compat"
	}
	return []ControlRoute{
		{
			Reason:     "connector_conformance_entry",
			Middleware: connectorMiddleware,
			Step:       cfg.MiddlewareStep,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if handlers.HandleConnectorAuthorityEntry == nil {
					return false
				}
				return handlers.HandleConnectorAuthorityEntry(w, r)
			},
		},
		{
			Reason: "v24_admin_entry",
			Step:   cfg.MiddlewareStep,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if handlers.HandleV24AdminEntry == nil {
					return false
				}
				return handlers.HandleV24AdminEntry(w, r)
			},
		},
		{
			Reason:     "phase3_plane_entry",
			Middleware: phase3Middleware,
			Step:       cfg.MiddlewareStep,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if handlers.HandlePhase3PlaneEntry == nil {
					return false
				}
				return handlers.HandlePhase3PlaneEntry(w, r)
			},
		},
		{
			Reason:     "phase3_model_egress",
			Middleware: modelCompatMiddleware,
			Step:       cfg.MiddlewareStep,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if handlers.HandleModelCompatEntry == nil {
					return false
				}
				return handlers.HandleModelCompatEntry(w, r)
			},
		},
	}
}

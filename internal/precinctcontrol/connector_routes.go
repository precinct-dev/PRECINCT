// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcontrol

import "net/http"

const (
	connectorRegisterPath = "/v1/connectors/register"
	connectorValidatePath = "/v1/connectors/validate"
	connectorApprovePath  = "/v1/connectors/approve"
	connectorActivatePath = "/v1/connectors/activate"
	connectorRevokePath   = "/v1/connectors/revoke"
	connectorStatusPath   = "/v1/connectors/status"
	connectorReportPath   = "/v1/connectors/report"
)

type ConnectorAuthorityRoutes struct {
	HandleRegister func(http.ResponseWriter, *http.Request) bool
	HandleValidate func(http.ResponseWriter, *http.Request) bool
	HandleApprove  func(http.ResponseWriter, *http.Request) bool
	HandleActivate func(http.ResponseWriter, *http.Request) bool
	HandleRevoke   func(http.ResponseWriter, *http.Request) bool
	HandleStatus   func(http.ResponseWriter, *http.Request) bool
	HandleReport   func(http.ResponseWriter, *http.Request) bool
}

type ConnectorAuthorityRouteConfig struct {
	MiddlewareStep  int
	ConnectorAuthMW string
}

func BuildConnectorAuthorityRoutes(cfg ConnectorAuthorityRouteConfig, routes ConnectorAuthorityRoutes) []ControlRoute {
	middleware := cfg.ConnectorAuthMW
	if middleware == "" {
		middleware = "v24_connector_authority"
	}
	step := cfg.MiddlewareStep
	if step == 0 {
		step = 16
	}

	return []ControlRoute{
		{
			Reason:     "connector_authority_entry",
			Middleware: middleware,
			Step:       step,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleRegister == nil || r.URL.Path != connectorRegisterPath {
					return false
				}
				return routes.HandleRegister(w, r)
			},
		},
		{
			Reason:     "connector_authority_entry",
			Middleware: middleware,
			Step:       step,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleValidate == nil || r.URL.Path != connectorValidatePath {
					return false
				}
				return routes.HandleValidate(w, r)
			},
		},
		{
			Reason:     "connector_authority_entry",
			Middleware: middleware,
			Step:       step,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleApprove == nil || r.URL.Path != connectorApprovePath {
					return false
				}
				return routes.HandleApprove(w, r)
			},
		},
		{
			Reason:     "connector_authority_entry",
			Middleware: middleware,
			Step:       step,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleActivate == nil || r.URL.Path != connectorActivatePath {
					return false
				}
				return routes.HandleActivate(w, r)
			},
		},
		{
			Reason:     "connector_authority_entry",
			Middleware: middleware,
			Step:       step,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleRevoke == nil || r.URL.Path != connectorRevokePath {
					return false
				}
				return routes.HandleRevoke(w, r)
			},
		},
		{
			Reason:     "connector_authority_entry",
			Middleware: middleware,
			Step:       step,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleStatus == nil || r.URL.Path != connectorStatusPath {
					return false
				}
				return routes.HandleStatus(w, r)
			},
		},
		{
			Reason:     "connector_authority_entry",
			Middleware: middleware,
			Step:       step,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleReport == nil || r.URL.Path != connectorReportPath {
					return false
				}
				return routes.HandleReport(w, r)
			},
		},
	}
}

func IsConnectorAuthorityPath(path string) bool {
	return path == connectorRegisterPath || path == connectorValidatePath || path == connectorApprovePath ||
		path == connectorActivatePath || path == connectorRevokePath || path == connectorStatusPath || path == connectorReportPath
}

func DispatchConnectorAuthorityRoutes(w http.ResponseWriter, r *http.Request, cfg ConnectorAuthorityRouteConfig, routes ConnectorAuthorityRoutes) bool {
	for _, route := range BuildConnectorAuthorityRoutes(cfg, routes) {
		if route.Try != nil && route.Try(w, r) {
			return true
		}
	}
	return false
}

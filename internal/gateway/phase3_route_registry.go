// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import "net/http"

type phase3RouteHandler func(http.ResponseWriter, *http.Request)

const (
	phase3IngressSubmitPath = "/v1/ingress/submit"
	phase3IngressAdmitPath  = "/v1/ingress/admit"
	phase3ContextAdmitPath  = "/v1/context/admit"
	phase3ModelCallPath     = "/v1/model/call"
	phase3ToolExecutePath   = "/v1/tool/execute"
	phase3LoopCheckPath     = "/v1/loop/check"
)

func (g *Gateway) phase3RouteHandlers() map[string]phase3RouteHandler {
	return map[string]phase3RouteHandler{
		phase3IngressSubmitPath: g.handleIngressAdmit,
		phase3IngressAdmitPath:  g.handleIngressAdmit,
		phase3ContextAdmitPath:  g.handleContextAdmit,
		phase3ModelCallPath:     g.handleModelCall,
		phase3ToolExecutePath:   g.handleToolExecute,
		phase3LoopCheckPath:     g.handleLoopCheck,
	}
}

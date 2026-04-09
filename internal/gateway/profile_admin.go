// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

const profileAdminPath = "/admin/profiles"

func (g *Gateway) adminProfilesHandler(w http.ResponseWriter, r *http.Request) {
	if g == nil {
		writeV24GatewayError(
			w, r, http.StatusServiceUnavailable,
			middleware.ErrMCPTransportFailed,
			"profile control plane unavailable",
			v24MiddlewareProfileAdmin,
			ReasonContractInvalid,
			nil,
		)
		return
	}

	pathSuffix := strings.TrimPrefix(r.URL.Path, profileAdminPath)
	if pathSuffix == r.URL.Path {
		http.NotFound(w, r)
		return
	}

	switch pathSuffix {
	case "", "/":
		if r.Method != http.MethodGet {
			writeProfileMethodNotAllowed(w, r, http.MethodGet)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"paths": []string{
				"GET /admin/profiles/status",
				"GET /admin/profiles/export",
			},
		})
		return
	case "/status", "/export":
		if r.Method != http.MethodGet {
			writeProfileMethodNotAllowed(w, r, http.MethodGet)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"profile": g.profileSnapshot(),
		})
		return
	default:
		http.NotFound(w, r)
		return
	}
}

func (g *Gateway) profileSnapshot() enforcementProfileRuntime {
	if g == nil || g.enforcementProfile == nil {
		return (*enforcementProfileRuntime)(nil).snapshot()
	}
	return g.enforcementProfile.snapshot()
}

func writeProfileMethodNotAllowed(w http.ResponseWriter, r *http.Request, allowed string) {
	w.Header().Set("Allow", allowed)
	writeV24GatewayError(
		w, r, http.StatusMethodNotAllowed,
		middleware.ErrMCPInvalidRequest,
		"method not allowed",
		v24MiddlewareProfileAdmin,
		ReasonContractInvalid,
		map[string]any{"allow": allowed},
	)
}

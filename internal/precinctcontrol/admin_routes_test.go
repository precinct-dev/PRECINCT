// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcontrol

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildAdminRoutes(t *testing.T) {
	routes := BuildAdminRoutes(
		AdminRouteConfig{MiddlewareStep: 16},
		AdminGatewayRoutes{
			HandleDLPRulesets:    func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
			HandleApprovals:      func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
			HandleBreakGlass:     func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
			HandleProfiles:       func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
			HandleLoopRuns:       func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
			HandleCircuitBreaker: func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
			HandlePolicyReload:   func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
			HandleFallback:       func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusNotFound); return true },
		},
	)
	if len(routes) != 8 {
		t.Fatalf("expected 8 admin routes, got %d", len(routes))
	}

	reqs := []struct {
		name string
		path string
		code int
	}{
		{name: "rulesets", path: "/admin/dlp/rulesets", code: http.StatusOK},
		{name: "approvals", path: "/admin/approvals", code: http.StatusOK},
		{name: "breakglass", path: "/admin/breakglass/status", code: http.StatusOK},
		{name: "profiles", path: "/admin/profiles/status", code: http.StatusOK},
		{name: "loop", path: "/admin/loop/runs", code: http.StatusOK},
		{name: "circuit", path: "/admin/circuit-breakers", code: http.StatusOK},
		{name: "policy", path: "/admin/policy/reload", code: http.StatusOK},
		{name: "fallback", path: "/admin/unknown", code: http.StatusNotFound},
	}
	for _, tc := range reqs {
		t.Run(tc.name, func(t *testing.T) {
			handled := false
			for _, route := range routes {
				if route.Try != nil && route.Try(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.path, nil)) {
					handled = true
					break
				}
			}
			if !handled {
				t.Fatal("route was not handled")
			}
		})
	}
}

func TestDispatchAdminRoutes(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/unknown", nil)
	ok := DispatchAdminRoutes(rec, req, AdminRouteConfig{}, AdminGatewayRoutes{HandleFallback: func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusNotFound); return true }})
	if !ok {
		t.Fatal("expected dispatch to handle unknown admin route")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

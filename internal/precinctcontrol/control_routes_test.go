package precinctcontrol

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildInternalControlRoutes(t *testing.T) {
	var seen []string
	routes := BuildInternalControlRoutes(
		ControlRouteConfig{
			MiddlewareStep: 11,
		},
		InternalGatewayControlRoutes{
			HandleConnectorAuthorityEntry: func(w http.ResponseWriter, r *http.Request) bool {
				seen = append(seen, "connector")
				return true
			},
			HandleV24AdminEntry: func(w http.ResponseWriter, r *http.Request) bool {
				seen = append(seen, "admin")
				return true
			},
			HandlePhase3PlaneEntry: func(w http.ResponseWriter, r *http.Request) bool {
				seen = append(seen, "plane")
				return true
			},
			HandleModelCompatEntry: func(w http.ResponseWriter, r *http.Request) bool {
				seen = append(seen, "model")
				return true
			},
		},
	)
	if len(routes) != 4 {
		t.Fatalf("expected 4 control routes, got %d", len(routes))
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	if !routes[0].Try(rec, req) || seen[0] != "connector" {
		t.Fatalf("expected connector route to execute first")
	}
	if !routes[1].Try(rec, req) || seen[1] != "admin" {
		t.Fatalf("expected admin route to execute second")
	}
	if !routes[2].Try(rec, req) || seen[2] != "plane" {
		t.Fatalf("expected phase3 plane route to execute third")
	}
	if !routes[3].Try(rec, req) || seen[3] != "model" {
		t.Fatalf("expected model compat route to execute fourth")
	}

	if len(routes[0].Middleware) == 0 || routes[0].Middleware != "v24_connector_authority" {
		t.Fatalf("expected default connector middleware, got %q", routes[0].Middleware)
	}
}

func TestBuildInternalControlRoutesSkipsNilHandlers(t *testing.T) {
	var seen bool
	routes := BuildInternalControlRoutes(
		ControlRouteConfig{
			MiddlewareStep: 11,
		},
		InternalGatewayControlRoutes{},
	)
	if len(routes) != 4 {
		t.Fatalf("expected 4 control routes, got %d", len(routes))
	}

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	for _, route := range routes {
		if route.Try(httptest.NewRecorder(), r) {
			seen = true
		}
	}
	if seen {
		t.Fatal("expected all nil handlers to skip route handling")
	}
}

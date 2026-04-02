package precinctcontrol

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildConnectorAuthorityRoutes(t *testing.T) {
	routes := BuildConnectorAuthorityRoutes(
		ConnectorAuthorityRouteConfig{MiddlewareStep: 11},
		ConnectorAuthorityRoutes{
			HandleRegister: func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
			HandleValidate: func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
			HandleApprove:  func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
			HandleActivate: func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
			HandleRevoke:   func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
			HandleStatus:   func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
			HandleReport:   func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(http.StatusOK); return true },
		},
	)

	if len(routes) != 7 {
		t.Fatalf("expected 7 connector routes, got %d", len(routes))
	}

	testCases := []struct {
		name string
		path string
		code int
	}{
		{name: "register", path: connectorRegisterPath, code: http.StatusOK},
		{name: "validate", path: connectorValidatePath, code: http.StatusOK},
		{name: "approve", path: connectorApprovePath, code: http.StatusOK},
		{name: "activate", path: connectorActivatePath, code: http.StatusOK},
		{name: "revoke", path: connectorRevokePath, code: http.StatusOK},
		{name: "status", path: connectorStatusPath, code: http.StatusOK},
		{name: "report", path: connectorReportPath, code: http.StatusOK},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			handled := false
			for _, route := range routes {
				if route.Try == nil {
					continue
				}
				if route.Try(rec, req) {
					handled = true
					break
				}
			}
			if !handled {
				t.Fatalf("expected path %s to be handled", tc.path)
			}
			if rec.Code != tc.code {
				t.Fatalf("expected status %d for %s, got %d", tc.code, tc.path, rec.Code)
			}
		})
	}
}

func TestDispatchConnectorAuthorityRoutesUnknownPath(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/connectors/unknown", nil)
	ok := DispatchConnectorAuthorityRoutes(rec, req, ConnectorAuthorityRouteConfig{}, ConnectorAuthorityRoutes{HandleRegister: func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(http.StatusOK)
		return true
	}})
	if ok {
		t.Fatal("expected unknown connector path to be unhandled")
	}
}

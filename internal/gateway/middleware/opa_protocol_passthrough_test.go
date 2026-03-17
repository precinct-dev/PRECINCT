package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

type panicOPA struct{}

func (panicOPA) Evaluate(input OPAInput) (bool, string, error) {
	panic("OPA evaluator should not be called for protocol passthrough")
}

func TestOPAPolicy_ProtocolMethodsPassthrough(t *testing.T) {
	methods := []string{
		"initialize",
		"ping",
		"notifications/initialized",
		"tools/list",
	}

	for _, rpcMethod := range methods {
		t.Run(rpcMethod, func(t *testing.T) {
			called := false
			handler := BodyCapture(OPAPolicy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}), panicOPA{}))

			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"`+rpcMethod+`","params":{},"id":1}`))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if !called {
				t.Fatalf("next handler was not called for %s", rpcMethod)
			}
		})
	}
}

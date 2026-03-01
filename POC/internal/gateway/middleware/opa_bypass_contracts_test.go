package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOPABypassContracts_Validate_DefaultContractsPass(t *testing.T) {
	if err := ValidateOPABypassContracts(); err != nil {
		t.Fatalf("expected default bypass contracts to validate, got: %v", err)
	}
}

func TestOPABypassContracts_Validate_FailsWhenCompensatingChecksMissing(t *testing.T) {
	restore := SetOPABypassContractsForTest([]OPABypassContract{
		{
			ID:          "broken_contract",
			ExactPaths:  []string{"/v1/model/call"},
			ProbePath:   "/v1/model/call",
			ProbeMethod: http.MethodPost,
			// RequiredChecks intentionally omitted to prove fail-closed validation.
		},
	})
	defer restore()

	if err := ValidateOPABypassContracts(); err == nil {
		t.Fatal("expected bypass contract validation failure when required checks are missing")
	}
}

func TestOPABypassContracts_MatchEnumeratesBypassRoutes(t *testing.T) {
	for _, contract := range ListOPABypassContracts() {
		method := contract.ProbeMethod
		if method == "" {
			method = http.MethodPost
		}
		req := httptest.NewRequest(method, contract.ProbePath, nil)
		if contract.RequiresWebSocketUpgrade {
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
		}
		matched, ok := MatchOPABypassContract(req)
		if !ok {
			t.Fatalf("expected contract %q to match probe request %s %s", contract.ID, method, contract.ProbePath)
		}
		if matched.ID != contract.ID {
			t.Fatalf("expected contract id %q, got %q", contract.ID, matched.ID)
		}
	}
}

type bypassTestEvaluator struct {
	called int
}

func (b *bypassTestEvaluator) Evaluate(input OPAInput) (bool, string, error) {
	b.called++
	return false, "should-not-run", nil
}

func TestOPAPolicy_BypassContractSkipsEvaluator(t *testing.T) {
	opa := &bypassTestEvaluator{}
	nextCalled := false

	handler := OPAPolicy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}), opa)

	req := httptest.NewRequest(http.MethodPost, "/v1/model/call", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected bypassed request to reach next handler, got status %d", rec.Code)
	}
	if !nextCalled {
		t.Fatal("expected next handler to be called for bypass contract route")
	}
	if opa.called != 0 {
		t.Fatalf("expected OPA evaluator not to be called for bypass contract route, got %d calls", opa.called)
	}
}

package gateway

import (
	"net/http"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

func TestDLPRuleOpsStateMachineTransitions(t *testing.T) {
	mgr, _, err := newDLPRuleOpsManager()
	if err != nil {
		t.Fatalf("newDLPRuleOpsManager: %v", err)
	}

	payload := map[string]any{
		"rules": []any{
			map[string]any{"id": "deny-credentials", "action": "deny"},
		},
	}

	if _, err := mgr.Create("rs-state-machine", payload, "security@corp"); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if _, err := mgr.Approve("rs-state-machine", "security@corp"); err == nil {
		t.Fatal("approve should fail before validate")
	}
	if _, err := mgr.Validate("rs-state-machine"); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if _, err := mgr.Sign("rs-state-machine", "bad-signature"); err == nil {
		t.Fatal("sign should fail before approve")
	}
	approved, err := mgr.Approve("rs-state-machine", "security@corp")
	if err != nil {
		t.Fatalf("approve failed: %v", err)
	}
	if approved.ExpectedSignature == "" {
		t.Fatal("approve should produce expected_signature")
	}
	if _, err := mgr.Promote("rs-state-machine", "active"); err == nil {
		t.Fatal("promote should fail while unsigned")
	}
	if _, err := mgr.Sign("rs-state-machine", approved.ExpectedSignature); err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if _, err := mgr.Promote("rs-state-machine", "canary"); err != nil {
		t.Fatalf("promote canary failed: %v", err)
	}
	if _, err := mgr.Rollback("rs-state-machine"); err != nil {
		t.Fatalf("rollback canary failed: %v", err)
	}

	active, ok := mgr.ActiveRecord()
	if !ok {
		t.Fatal("active record should exist")
	}
	if active.RulesetID != "builtin/v1" {
		t.Fatalf("expected built-in active after canary rollback, got %s", active.RulesetID)
	}
}

func TestDLPRuleOpsEndpointsPromoteUnsignedAndSigned(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	createBody := map[string]any{
		"ruleset_id": "rs-endpoint",
		"created_by": "integration@test",
		"content": map[string]any{
			"rules": []any{
				map[string]any{"id": "deny-ssn", "action": "deny"},
			},
		},
	}
	code, resp := postGatewayJSON(t, h, http.MethodPost, "/admin/dlp/rulesets/create", createBody)
	if code != http.StatusOK {
		t.Fatalf("create expected 200, got %d body=%v", code, resp)
	}

	for _, op := range []string{"validate", "approve"} {
		body := map[string]any{"ruleset_id": "rs-endpoint"}
		if op == "approve" {
			body["approved_by"] = "security@test"
		}
		code, resp = postGatewayJSON(t, h, http.MethodPost, "/admin/dlp/rulesets/"+op, body)
		if code != http.StatusOK {
			t.Fatalf("%s expected 200, got %d body=%v", op, code, resp)
		}
	}

	expectedSig := nestedString(resp, "record", "expected_signature")
	if expectedSig == "" {
		t.Fatalf("approve response missing expected_signature: %v", resp)
	}

	code, resp = postGatewayJSON(t, h, http.MethodPost, "/admin/dlp/rulesets/promote", map[string]any{
		"ruleset_id": "rs-endpoint",
		"mode":       "active",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("unsigned promote expected 400, got %d body=%v", code, resp)
	}

	code, resp = postGatewayJSON(t, h, http.MethodPost, "/admin/dlp/rulesets/sign", map[string]any{
		"ruleset_id": "rs-endpoint",
		"signature":  expectedSig,
	})
	if code != http.StatusOK {
		t.Fatalf("sign expected 200, got %d body=%v", code, resp)
	}

	code, resp = postGatewayJSON(t, h, http.MethodPost, "/admin/dlp/rulesets/promote", map[string]any{
		"ruleset_id": "rs-endpoint",
		"mode":       "canary",
	})
	if code != http.StatusOK {
		t.Fatalf("promote canary expected 200, got %d body=%v", code, resp)
	}
	if state := nestedString(resp, "record", "state"); state != string(dlpRulesetStateCanary) {
		t.Fatalf("expected canary state, got %q body=%v", state, resp)
	}

	code, resp = postGatewayJSON(t, h, http.MethodGet, "/admin/dlp/rulesets/active", nil)
	if code != http.StatusOK {
		t.Fatalf("active endpoint expected 200, got %d body=%v", code, resp)
	}
	if activeID := nestedString(resp, "active", "ruleset_id"); activeID != "builtin/v1" {
		t.Fatalf("expected builtin active during canary, got %q body=%v", activeID, resp)
	}
	if canaryID := nestedString(resp, "canary", "ruleset_id"); canaryID != "rs-endpoint" {
		t.Fatalf("expected canary ruleset rs-endpoint, got %q body=%v", canaryID, resp)
	}

	code, resp = postGatewayJSON(t, h, http.MethodPost, "/admin/dlp/rulesets/promote", map[string]any{
		"ruleset_id": "rs-endpoint",
		"mode":       "active",
	})
	if code != http.StatusOK {
		t.Fatalf("promote active expected 200, got %d body=%v", code, resp)
	}
	if state := nestedString(resp, "record", "state"); state != string(dlpRulesetStateActive) {
		t.Fatalf("expected active state, got %q body=%v", state, resp)
	}

	code, resp = postGatewayJSON(t, h, http.MethodPost, "/admin/dlp/rulesets/rollback", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("rollback expected 200, got %d body=%v", code, resp)
	}
	if state := nestedString(resp, "record", "state"); state != string(dlpRulesetStateRolledBack) {
		t.Fatalf("expected rolled_back state, got %q body=%v", state, resp)
	}

	code, resp = postGatewayJSON(t, h, http.MethodGet, "/admin/dlp/rulesets/active", nil)
	if code != http.StatusOK {
		t.Fatalf("active endpoint expected 200, got %d body=%v", code, resp)
	}
	if activeID := nestedString(resp, "active", "ruleset_id"); activeID != "builtin/v1" {
		t.Fatalf("expected builtin active after rollback, got %q body=%v", activeID, resp)
	}
}

func nestedString(root map[string]any, k1, k2 string) string {
	inner, ok := root[k1].(map[string]any)
	if !ok {
		return ""
	}
	v, _ := inner[k2].(string)
	return v
}

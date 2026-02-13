package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestIngressSubmitConnectorConformanceReplayAndFreshness(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	connectorID := "ingress-submit-it-connector"
	sessionID := fmt.Sprintf("ingress-submit-session-%d", time.Now().UnixNano())

	registerCode, registerBody := ruleOpsPost(t, baseURL+"/v1/connectors/register", map[string]any{
		"connector_id": connectorID,
		"manifest": map[string]any{
			"connector_id":     connectorID,
			"connector_type":   "webhook",
			"source_principal": spiffeID,
			"version":          "1.0",
			"capabilities":     []any{"ingress.submit"},
			"signature": map[string]any{
				"algorithm": "sha256-manifest-v1",
				"value":     "bootstrap-signature",
			},
		},
	})
	if registerCode != http.StatusOK {
		t.Fatalf("connector register expected 200, got %d body=%v", registerCode, registerBody)
	}
	connectorSig := nestedRuleOpsField(registerBody, "record", "expected_signature")
	if connectorSig == "" {
		t.Fatalf("connector register missing expected_signature body=%v", registerBody)
	}

	registerCode, registerBody = ruleOpsPost(t, baseURL+"/v1/connectors/register", map[string]any{
		"connector_id": connectorID,
		"manifest": map[string]any{
			"connector_id":     connectorID,
			"connector_type":   "webhook",
			"source_principal": spiffeID,
			"version":          "1.0",
			"capabilities":     []any{"ingress.submit"},
			"signature": map[string]any{
				"algorithm": "sha256-manifest-v1",
				"value":     connectorSig,
			},
		},
	})
	if registerCode != http.StatusOK {
		t.Fatalf("connector re-register expected 200, got %d body=%v", registerCode, registerBody)
	}
	for _, op := range []string{"validate", "approve", "activate"} {
		code, body := ruleOpsPost(t, baseURL+"/v1/connectors/"+op, map[string]any{"connector_id": connectorID})
		if code != http.StatusOK {
			t.Fatalf("connector %s expected 200, got %d body=%v", op, code, body)
		}
	}

	postIngress := func(runID, eventID string, ts time.Time) (int, map[string]any) {
		return ruleOpsPost(t, baseURL+"/v1/ingress/submit", map[string]any{
			"envelope": map[string]any{
				"run_id":          runID,
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "ingress",
			},
			"policy": map[string]any{
				"envelope": map[string]any{
					"run_id":          runID,
					"session_id":      sessionID,
					"tenant":          "tenant-a",
					"actor_spiffe_id": spiffeID,
					"plane":           "ingress",
				},
				"action":   "ingress.admit",
				"resource": "ingress/event",
				"attributes": map[string]any{
					"connector_id":        connectorID,
					"source_id":           connectorID,
					"source_principal":    spiffeID,
					"connector_signature": connectorSig,
					"event_id":            eventID,
					"event_timestamp":     ts.UTC().Format(time.RFC3339),
				},
			},
		})
	}

	code, body := postIngress("run-ingress-submit-it-allow", "evt-it-allow", time.Now().UTC())
	if code != http.StatusOK {
		t.Fatalf("ingress allow expected 200, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "INGRESS_ALLOW" {
		t.Fatalf("ingress allow expected reason_code=INGRESS_ALLOW, got %q body=%v", reason, body)
	}

	code, body = postIngress("run-ingress-submit-it-replay", "evt-it-allow", time.Now().UTC())
	if code != http.StatusConflict {
		t.Fatalf("ingress replay expected 409, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "INGRESS_REPLAY_DETECTED" {
		t.Fatalf("ingress replay expected reason_code=INGRESS_REPLAY_DETECTED, got %q body=%v", reason, body)
	}

	code, body = postIngress("run-ingress-submit-it-stale", "evt-it-stale", time.Now().UTC().Add(-10*time.Minute))
	if code != http.StatusForbidden {
		t.Fatalf("ingress stale expected 403, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "INGRESS_FRESHNESS_STALE" {
		t.Fatalf("ingress stale expected reason_code=INGRESS_FRESHNESS_STALE, got %q body=%v", reason, body)
	}

	code, body = ruleOpsPost(t, baseURL+"/v1/connectors/revoke", map[string]any{"connector_id": connectorID})
	if code != http.StatusOK {
		t.Fatalf("connector revoke expected 200, got %d body=%v", code, body)
	}

	code, body = postIngress("run-ingress-submit-it-revoked", "evt-it-revoked", time.Now().UTC())
	if code != http.StatusForbidden {
		t.Fatalf("ingress revoked expected 403, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "INGRESS_SOURCE_UNAUTHENTICATED" {
		t.Fatalf("ingress revoked expected reason_code=INGRESS_SOURCE_UNAUTHENTICATED, got %q body=%v", reason, body)
	}
}

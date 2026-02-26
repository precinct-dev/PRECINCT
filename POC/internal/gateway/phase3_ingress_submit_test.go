package gateway

import (
	"net/http"
	"testing"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
)

func TestIngressSubmitValidatesCanonicalEnvelope(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	payload := map[string]any{
		"envelope": map[string]any{
			"run_id":          "run-ingress-submit-invalid",
			"session_id":      "session-ingress-submit-invalid",
			"tenant":          "tenant-a",
			"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"plane":           "ingress",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "run-mismatch",
				"session_id":      "session-ingress-submit-invalid",
				"tenant":          "tenant-a",
				"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				"plane":           "ingress",
			},
			"action":   "ingress.admit",
			"resource": "ingress/event",
		},
	}

	code, resp := postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", payload)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonContractInvalid) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonContractInvalid, resp["reason_code"])
	}
}

func TestIngressSubmitCanonicalAndCompatibilityAlias(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	spiffe := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	connectorID := "connector-submit-alias"
	connectorSig := activateConnectorForIngress(t, h, connectorID, spiffe)

	nowUTC := time.Now().UTC().Format(time.RFC3339)
	payload := func(runID, eventID string) map[string]any {
		return map[string]any{
			"envelope": map[string]any{
				"run_id":          runID,
				"session_id":      "session-submit-alias",
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffe,
				"plane":           "ingress",
			},
			"policy": map[string]any{
				"envelope": map[string]any{
					"run_id":          runID,
					"session_id":      "session-submit-alias",
					"tenant":          "tenant-a",
					"actor_spiffe_id": spiffe,
					"plane":           "ingress",
				},
				"action":   "ingress.admit",
				"resource": "ingress/event",
				"attributes": map[string]any{
					"connector_id":        connectorID,
					"source_id":           connectorID,
					"source_principal":    spiffe,
					"connector_signature": connectorSig,
					"event_id":            eventID,
					"event_timestamp":     nowUTC,
				},
			},
		}
	}

	code, resp := postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", payload("run-submit-canonical", "evt-submit-canonical"))
	if code != http.StatusOK {
		t.Fatalf("submit expected 200, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressAllow) {
		t.Fatalf("submit expected reason_code=%s, got %v", ReasonIngressAllow, resp["reason_code"])
	}

	code, resp = postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/admit", payload("run-submit-alias", "evt-submit-alias"))
	if code != http.StatusOK {
		t.Fatalf("admit alias expected 200, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressAllow) {
		t.Fatalf("admit alias expected reason_code=%s, got %v", ReasonIngressAllow, resp["reason_code"])
	}
}

func TestIngressSubmitReplayAndFreshnessDeterministicReasons(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	spiffe := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	connectorID := "connector-submit-replay"
	connectorSig := activateConnectorForIngress(t, h, connectorID, spiffe)

	buildPayload := func(runID, eventID string, ts time.Time) map[string]any {
		tsValue := ""
		if !ts.IsZero() {
			tsValue = ts.UTC().Format(time.RFC3339)
		}
		return map[string]any{
			"envelope": map[string]any{
				"run_id":          runID,
				"session_id":      "session-submit-replay",
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffe,
				"plane":           "ingress",
			},
			"policy": map[string]any{
				"envelope": map[string]any{
					"run_id":          runID,
					"session_id":      "session-submit-replay",
					"tenant":          "tenant-a",
					"actor_spiffe_id": spiffe,
					"plane":           "ingress",
				},
				"action":   "ingress.admit",
				"resource": "ingress/event",
				"attributes": map[string]any{
					"connector_id":        connectorID,
					"source_id":           connectorID,
					"source_principal":    spiffe,
					"connector_signature": connectorSig,
					"event_id":            eventID,
					"event_timestamp":     tsValue,
				},
			},
		}
	}

	now := time.Now().UTC()
	code, resp := postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", buildPayload("run-submit-replay-1", "evt-replay", now))
	if code != http.StatusOK {
		t.Fatalf("first submit expected 200, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressAllow) {
		t.Fatalf("first submit expected reason_code=%s, got %v", ReasonIngressAllow, resp["reason_code"])
	}

	code, resp = postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", buildPayload("run-submit-replay-2", "evt-replay", now))
	if code != http.StatusConflict {
		t.Fatalf("replay submit expected 409, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressReplayDetected) {
		t.Fatalf("replay submit expected reason_code=%s, got %v", ReasonIngressReplayDetected, resp["reason_code"])
	}

	stale := time.Now().UTC().Add(-10 * time.Minute)
	code, resp = postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", buildPayload("run-submit-stale", "evt-stale", stale))
	if code != http.StatusForbidden {
		t.Fatalf("stale submit expected 403, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressFreshnessStale) {
		t.Fatalf("stale submit expected reason_code=%s, got %v", ReasonIngressFreshnessStale, resp["reason_code"])
	}
}

func TestIngressSubmitSourcePrincipalMismatchDenied(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	manifestSPIFFE := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	reqSPIFFE := "spiffe://poc.local/agents/mcp-client/other/dev"
	connectorID := "connector-submit-source-mismatch"
	connectorSig := activateConnectorForIngress(t, h, connectorID, manifestSPIFFE)

	payload := map[string]any{
		"envelope": map[string]any{
			"run_id":          "run-submit-source-mismatch",
			"session_id":      "session-submit-source-mismatch",
			"tenant":          "tenant-a",
			"actor_spiffe_id": manifestSPIFFE,
			"plane":           "ingress",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "run-submit-source-mismatch",
				"session_id":      "session-submit-source-mismatch",
				"tenant":          "tenant-a",
				"actor_spiffe_id": manifestSPIFFE,
				"plane":           "ingress",
			},
			"action":   "ingress.admit",
			"resource": "ingress/event",
			"attributes": map[string]any{
				"connector_id":        connectorID,
				"source_id":           connectorID,
				"source_principal":    reqSPIFFE,
				"connector_signature": connectorSig,
				"event_id":            "evt-source-mismatch",
				"event_timestamp":     time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	code, resp := postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", payload)
	if code != http.StatusForbidden {
		t.Fatalf("source mismatch expected 403, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressSourceUnauth) {
		t.Fatalf("source mismatch expected reason_code=%s, got %v", ReasonIngressSourceUnauth, resp["reason_code"])
	}
}

func activateConnectorForIngress(t *testing.T, h http.Handler, connectorID, sourcePrincipal string) string {
	t.Helper()

	manifest := connectorManifest{
		ConnectorID:     connectorID,
		ConnectorType:   "webhook",
		SourcePrincipal: sourcePrincipal,
		Version:         "1.0",
		Capabilities:    []string{"ingress.submit"},
	}
	manifest.Signature = connectorManifestSignature{
		Algorithm: connectorSignatureAlgorithm,
		Value:     computeConnectorExpectedSignature(manifest),
	}

	code, resp := postGatewayJSON(t, h, http.MethodPost, "/v1/connectors/register", map[string]any{
		"connector_id": connectorID,
		"manifest":     manifest,
	})
	if code != http.StatusOK {
		t.Fatalf("register expected 200, got %d body=%v", code, resp)
	}
	for _, op := range []string{"validate", "approve", "activate"} {
		code, resp = postGatewayJSON(t, h, http.MethodPost, "/v1/connectors/"+op, map[string]any{"connector_id": connectorID})
		if code != http.StatusOK {
			t.Fatalf("%s expected 200, got %d body=%v", op, code, resp)
		}
	}

	return manifest.Signature.Value
}

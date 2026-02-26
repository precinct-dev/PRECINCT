package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
)

func TestConnectorManifestSchemaValidation(t *testing.T) {
	valid := connectorManifest{
		ConnectorID:     "connector-a",
		ConnectorType:   "webhook",
		SourcePrincipal: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Version:         "1.0",
		Capabilities:    []string{"ingress.submit"},
		Signature: connectorManifestSignature{
			Algorithm: connectorSignatureAlgorithm,
			Value:     "abc",
		},
	}
	if err := validateConnectorManifestSchema(valid); err != nil {
		t.Fatalf("expected valid schema, got err: %v", err)
	}

	invalid := valid
	invalid.Signature = connectorManifestSignature{}
	if err := validateConnectorManifestSchema(invalid); err == nil {
		t.Fatal("expected schema validation error for missing signature")
	}
}

func TestConnectorLifecycleTransitions(t *testing.T) {
	cca := newConnectorConformanceAuthority()
	manifest := connectorManifest{
		ConnectorID:     "connector-lifecycle",
		ConnectorType:   "webhook",
		SourcePrincipal: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Version:         "1.0",
		Capabilities:    []string{"ingress.submit"},
	}
	manifest.Signature = connectorManifestSignature{
		Algorithm: connectorSignatureAlgorithm,
		Value:     computeConnectorExpectedSignature(manifest),
	}

	if _, err := cca.register(manifest); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if _, err := cca.activate(manifest.ConnectorID); err == nil {
		t.Fatal("activate should fail before approve")
	}
	if _, err := cca.validate(manifest.ConnectorID); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if _, err := cca.approve(manifest.ConnectorID); err != nil {
		t.Fatalf("approve failed: %v", err)
	}
	rec, err := cca.activate(manifest.ConnectorID)
	if err != nil {
		t.Fatalf("activate failed: %v", err)
	}
	if rec.State != connectorStateActive {
		t.Fatalf("expected active state, got %s", rec.State)
	}
	rec, err = cca.revoke(manifest.ConnectorID)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if rec.State != connectorStateRevoked {
		t.Fatalf("expected revoked state, got %s", rec.State)
	}
}

func TestConnectorEndpointsAndIngressEnforcement(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	manifest := connectorManifest{
		ConnectorID:     "connector-e2e",
		ConnectorType:   "webhook",
		SourcePrincipal: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Version:         "1.0",
		Capabilities:    []string{"ingress.submit"},
	}
	manifest.Signature = connectorManifestSignature{
		Algorithm: connectorSignatureAlgorithm,
		Value:     computeConnectorExpectedSignature(manifest),
	}

	registerBody := map[string]any{
		"connector_id": manifest.ConnectorID,
		"manifest":     manifest,
	}
	code, resp := postGatewayJSON(t, h, http.MethodPost, "/v1/connectors/register", registerBody)
	if code != http.StatusOK {
		t.Fatalf("register expected 200, got %d body=%v", code, resp)
	}

	for _, op := range []string{"validate", "approve", "activate"} {
		code, resp = postGatewayJSON(t, h, http.MethodPost, "/v1/connectors/"+op, map[string]any{"connector_id": manifest.ConnectorID})
		if code != http.StatusOK {
			t.Fatalf("%s expected 200, got %d body=%v", op, code, resp)
		}
	}

	ingressPayload := map[string]any{
		"envelope": map[string]any{
			"run_id":          "run-connector-active",
			"session_id":      "session-connector",
			"tenant":          "tenant-a",
			"actor_spiffe_id": manifest.SourcePrincipal,
			"plane":           "ingress",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "run-connector-active",
				"session_id":      "session-connector",
				"tenant":          "tenant-a",
				"actor_spiffe_id": manifest.SourcePrincipal,
				"plane":           "ingress",
			},
			"action":   "ingress.admit",
			"resource": "ingress/event",
			"attributes": map[string]any{
				"connector_id":        manifest.ConnectorID,
				"connector_signature": manifest.Signature.Value,
				"source_id":           manifest.ConnectorID,
				"source_principal":    manifest.SourcePrincipal,
				"event_id":            "evt-active",
			},
		},
	}
	code, resp = postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/admit", ingressPayload)
	if code != http.StatusOK {
		t.Fatalf("active ingress expected 200, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressAllow) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonIngressAllow, resp["reason_code"])
	}

	code, resp = postGatewayJSON(t, h, http.MethodPost, "/v1/connectors/revoke", map[string]any{"connector_id": manifest.ConnectorID})
	if code != http.StatusOK {
		t.Fatalf("revoke expected 200, got %d body=%v", code, resp)
	}

	code, resp = postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/admit", ingressPayload)
	if code != http.StatusForbidden {
		t.Fatalf("revoked ingress expected 403, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressSourceUnauth) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonIngressSourceUnauth, resp["reason_code"])
	}

	code, resp = postGatewayJSON(t, h, http.MethodGet, "/v1/connectors/report", nil)
	if code != http.StatusOK {
		t.Fatalf("report expected 200, got %d body=%v", code, resp)
	}
	connectors, ok := resp["connectors"].([]any)
	if !ok || len(connectors) == 0 {
		t.Fatalf("report missing connectors list: %v", resp)
	}
	found := false
	for _, row := range connectors {
		entry, ok := row.(map[string]any)
		if !ok {
			continue
		}
		if entry["connector_id"] == manifest.ConnectorID {
			found = true
			if entry["last_decision_id"] == "" {
				t.Fatalf("expected last_decision_id in report entry: %v", entry)
			}
		}
	}
	if !found {
		t.Fatalf("connector %s not present in report: %v", manifest.ConnectorID, resp)
	}
}

func postGatewayJSON(t *testing.T, handler http.Handler, method, path string, payload map[string]any) (int, map[string]any) {
	t.Helper()
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Body.Len() == 0 {
		return rec.Code, map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response body: %v body=%s", err, rec.Body.String())
	}
	return rec.Code, out
}

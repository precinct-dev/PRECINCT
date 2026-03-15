package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"github.com/precinct-dev/precinct/internal/testutil"
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

func TestConnectorAuthorityStartsWithoutSeededConnector(t *testing.T) {
	cca := newConnectorConformanceAuthority()

	if _, ok := cca.status("compose-webhook"); ok {
		t.Fatal("expected connector authority to start without seeded compose-webhook state")
	}

	report := cca.conformanceReport()
	connectors, ok := report["connectors"].([]map[string]any)
	if ok && len(connectors) != 0 {
		t.Fatalf("expected no seeded connectors in report, got %v", connectors)
	}
	if rows, ok := report["connectors"].([]any); ok && len(rows) != 0 {
		t.Fatalf("expected no seeded connectors in report, got %v", rows)
	}
}

func TestGatewayStartsWithoutSeededConnectorAcrossProfiles(t *testing.T) {
	projectRoot := testutil.ProjectRoot()
	signedRegistryPath, signedRegistryPubKeyPath := writeSignedStrictToolRegistryFixture(t)

	tests := []struct {
		name     string
		newSetup func(*testing.T) *Gateway
	}{
		{
			name: "dev",
			newSetup: func(t *testing.T) *Gateway {
				gw, _ := newPhase3TestGateway(t)
				return gw
			},
		},
		{
			name: "strict",
			newSetup: func(t *testing.T) *Gateway {
				cfg := &Config{
					Port:                          0,
					UpstreamURL:                   "https://mcp-server.example.com/mcp",
					OPAPolicyDir:                  testutil.OPAPolicyDir(),
					OPAPolicyPublicKey:            signedRegistryPubKeyPath,
					ToolRegistryConfigPath:        signedRegistryPath,
					ToolRegistryPublicKey:         signedRegistryPubKeyPath,
					ModelProviderCatalogPath:      filepath.Join(projectRoot, "config", "model-provider-catalog.v2.yaml"),
					ModelProviderCatalogPublicKey: filepath.Join(projectRoot, "config", "attestation-ed25519.pub"),
					GuardArtifactPath:             filepath.Join(projectRoot, "config", "guard-artifact.bin"),
					GuardArtifactSHA256:           "8232540100ebde3b5682c2b47d1eee50764f6dadca3842400157061656fc95a3",
					GuardArtifactPublicKey:        filepath.Join(projectRoot, "config", "attestation-ed25519.pub"),
					AuditLogPath:                  "",
					OPAPolicyPath:                 testutil.OPAPolicyPath(),
					MaxRequestSizeBytes:           1024,
					SPIFFEMode:                    "prod",
					MCPTransportMode:              "mcp",
					EnforcementProfile:            enforcementProfileProdStandard,
					ApprovalSigningKey:            "prod-approval-signing-key-material-at-least-32",
					AdminAuthzAllowedSPIFFEIDs:    []string{"spiffe://poc.local/admin/security"},
					KeyDBURL:                      "redis://keydb:6379",
					DestinationsConfigPath:        filepath.Join(projectRoot, "config", "destinations.yaml"),
					RiskThresholdsPath:            filepath.Join(projectRoot, "config", "risk_thresholds.yaml"),
				}

				gw, err := New(cfg)
				if err != nil {
					t.Fatalf("New gateway: %v", err)
				}
				t.Cleanup(func() { _ = gw.Close() })
				return gw
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw := tc.newSetup(t)
			if _, ok := gw.cca.status("compose-webhook"); ok {
				t.Fatalf("%s gateway unexpectedly started with seeded compose-webhook state", tc.name)
			}
			report := gw.cca.conformanceReport()
			if rows, ok := report["connectors"].([]any); ok && len(rows) != 0 {
				t.Fatalf("%s gateway expected no startup connector records, got %v", tc.name, rows)
			}
		})
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

func TestConnectorMutationEndpointsRequireAdminAuthorization(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	manifest := connectorManifest{
		ConnectorID:     "connector-admin-authz",
		ConnectorType:   "webhook",
		SourcePrincipal: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Version:         "1.0",
		Capabilities:    []string{"ingress.submit"},
	}
	manifest.Signature = connectorManifestSignature{
		Algorithm: connectorSignatureAlgorithm,
		Value:     computeConnectorExpectedSignature(manifest),
	}

	nonAdminSPIFFEID := "spiffe://poc.local/agents/not-admin/dev"
	for _, tc := range []struct {
		name    string
		path    string
		method  string
		payload map[string]any
	}{
		{
			name:   "register",
			path:   "/v1/connectors/register",
			method: http.MethodPost,
			payload: map[string]any{
				"connector_id": manifest.ConnectorID,
				"manifest":     manifest,
			},
		},
		{name: "validate", path: "/v1/connectors/validate", method: http.MethodPost, payload: map[string]any{"connector_id": manifest.ConnectorID}},
		{name: "approve", path: "/v1/connectors/approve", method: http.MethodPost, payload: map[string]any{"connector_id": manifest.ConnectorID}},
		{name: "activate", path: "/v1/connectors/activate", method: http.MethodPost, payload: map[string]any{"connector_id": manifest.ConnectorID}},
		{name: "revoke", path: "/v1/connectors/revoke", method: http.MethodPost, payload: map[string]any{"connector_id": manifest.ConnectorID}},
	} {
		code, resp := postGatewayJSONAs(t, h, tc.method, tc.path, tc.payload, nonAdminSPIFFEID)
		if code != http.StatusForbidden {
			t.Fatalf("%s expected 403 for non-admin, got %d body=%v", tc.name, code, resp)
		}
	}

	code, resp := postGatewayJSONAs(t, h, http.MethodGet, "/v1/connectors/report", nil, nonAdminSPIFFEID)
	if code != http.StatusOK {
		t.Fatalf("report expected 200 for authenticated non-admin, got %d body=%v", code, resp)
	}
}

func postGatewayJSON(t *testing.T, handler http.Handler, method, path string, payload map[string]any) (int, map[string]any) {
	t.Helper()
	return postGatewayJSONAs(t, handler, method, path, payload, "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
}

func postGatewayJSONAs(t *testing.T, handler http.Handler, method, path string, payload map[string]any, spiffeID string) (int, map[string]any) {
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
	req.Header.Set("X-SPIFFE-ID", spiffeID)
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

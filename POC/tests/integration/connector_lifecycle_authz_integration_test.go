package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestConnectorLifecycleMutationsRequireAdminAuthorization(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)
	adminSPIFFEID := adminSPIFFEIDForTest()
	nonAdminSPIFFEID := nonAdminSPIFFEIDForTest()
	connectorID := fmt.Sprintf("connector-admin-it-%d", time.Now().UnixNano())

	code, body := ruleOpsGetAs(t, baseURL+"/v1/connectors/report", nonAdminSPIFFEID)
	if code != http.StatusOK {
		t.Fatalf("non-admin report at startup expected 200, got %d body=%v", code, body)
	}
	connectors, ok := body["connectors"].([]any)
	if !ok {
		t.Fatalf("startup report missing connectors array: %v", body)
	}
	if len(connectors) != 0 {
		t.Fatalf("expected no seeded connectors at startup, got %v", connectors)
	}

	registerPayload := map[string]any{
		"connector_id": connectorID,
		"manifest": map[string]any{
			"connector_id":     connectorID,
			"connector_type":   "webhook",
			"source_principal": adminSPIFFEID,
			"version":          "1.0",
			"capabilities":     []any{"ingress.submit"},
			"signature": map[string]any{
				"algorithm": "sha256-manifest-v1",
				"value":     "bootstrap-signature",
			},
		},
	}

	code, body = ruleOpsPostAs(t, baseURL+"/v1/connectors/register", registerPayload, nonAdminSPIFFEID)
	if code != http.StatusForbidden {
		t.Fatalf("non-admin register expected 403, got %d body=%v", code, body)
	}

	code, body = ruleOpsPostAs(t, baseURL+"/v1/connectors/register", registerPayload, adminSPIFFEID)
	if code != http.StatusOK {
		t.Fatalf("admin register expected 200, got %d body=%v", code, body)
	}
	connectorSig := nestedRuleOpsField(body, "record", "expected_signature")
	if connectorSig == "" {
		t.Fatalf("admin register missing expected_signature body=%v", body)
	}

	canonicalRegisterPayload := map[string]any{
		"connector_id": connectorID,
		"manifest": map[string]any{
			"connector_id":     connectorID,
			"connector_type":   "webhook",
			"source_principal": adminSPIFFEID,
			"version":          "1.0",
			"capabilities":     []any{"ingress.submit"},
			"signature": map[string]any{
				"algorithm": "sha256-manifest-v1",
				"value":     connectorSig,
			},
		},
	}
	code, body = ruleOpsPostAs(t, baseURL+"/v1/connectors/register", canonicalRegisterPayload, adminSPIFFEID)
	if code != http.StatusOK {
		t.Fatalf("admin canonical register expected 200, got %d body=%v", code, body)
	}

	for _, op := range []string{"validate", "approve", "activate", "revoke"} {
		code, body = ruleOpsPostAs(t, baseURL+"/v1/connectors/"+op, map[string]any{"connector_id": connectorID}, nonAdminSPIFFEID)
		if code != http.StatusForbidden {
			t.Fatalf("non-admin %s expected 403, got %d body=%v", op, code, body)
		}
	}

	for _, op := range []string{"validate", "approve", "activate"} {
		code, body = ruleOpsPostAs(t, baseURL+"/v1/connectors/"+op, map[string]any{"connector_id": connectorID}, adminSPIFFEID)
		if code != http.StatusOK {
			t.Fatalf("admin %s expected 200, got %d body=%v", op, code, body)
		}
	}

	code, body = ruleOpsGetAs(t, baseURL+"/v1/connectors/status?connector_id="+connectorID, nonAdminSPIFFEID)
	if code != http.StatusOK {
		t.Fatalf("non-admin status expected 200, got %d body=%v", code, body)
	}

	code, body = ruleOpsGetAs(t, baseURL+"/v1/connectors/report", nonAdminSPIFFEID)
	if code != http.StatusOK {
		t.Fatalf("non-admin report expected 200, got %d body=%v", code, body)
	}

	code, body = ruleOpsPostAs(t, baseURL+"/v1/connectors/revoke", map[string]any{"connector_id": connectorID}, adminSPIFFEID)
	if code != http.StatusOK {
		t.Fatalf("admin revoke expected 200, got %d body=%v", code, body)
	}
}

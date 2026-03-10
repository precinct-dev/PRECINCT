package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
)

func TestBreakGlassAdminLifecycleEndpoints(t *testing.T) {
	g := &Gateway{breakGlass: newBreakGlassManager(nil)}
	spiffeID := "spiffe://poc.local/agents/test"

	requestReq := httptest.NewRequest(http.MethodPost, "/admin/breakglass/request", bytes.NewBufferString(`{
		"incident_id":"INC-123",
		"scope":{"action":"model.call","resource":"gpt-4o","actor_spiffe_id":"spiffe://poc.local/agents/test"},
		"requested_by":"security@corp",
		"ttl_seconds":120
	}`))
	requestReq = requestReq.WithContext(middleware.WithSPIFFEID(requestReq.Context(), spiffeID))
	requestRec := httptest.NewRecorder()
	g.adminBreakGlassHandler(requestRec, requestReq)
	if requestRec.Code != http.StatusOK {
		t.Fatalf("request expected 200, got %d body=%s", requestRec.Code, requestRec.Body.String())
	}
	var requestResp map[string]any
	if err := json.NewDecoder(requestRec.Body).Decode(&requestResp); err != nil {
		t.Fatalf("decode request response: %v", err)
	}
	record, _ := requestResp["record"].(map[string]any)
	requestID, _ := record["request_id"].(string)
	if requestID == "" {
		t.Fatalf("missing request_id body=%v", requestResp)
	}

	approve1 := httptest.NewRequest(http.MethodPost, "/admin/breakglass/approve", bytes.NewBufferString(`{
		"request_id":"`+requestID+`",
		"approved_by":"security-1@corp"
	}`))
	approve1 = approve1.WithContext(middleware.WithSPIFFEID(approve1.Context(), spiffeID))
	approve1Rec := httptest.NewRecorder()
	g.adminBreakGlassHandler(approve1Rec, approve1)
	if approve1Rec.Code != http.StatusOK {
		t.Fatalf("approve #1 expected 200, got %d body=%s", approve1Rec.Code, approve1Rec.Body.String())
	}

	activateEarly := httptest.NewRequest(http.MethodPost, "/admin/breakglass/activate", bytes.NewBufferString(`{
		"request_id":"`+requestID+`",
		"activated_by":"ops@corp"
	}`))
	activateEarly = activateEarly.WithContext(middleware.WithSPIFFEID(activateEarly.Context(), spiffeID))
	activateEarlyRec := httptest.NewRecorder()
	g.adminBreakGlassHandler(activateEarlyRec, activateEarly)
	if activateEarlyRec.Code != http.StatusForbidden {
		t.Fatalf("early activate expected 403, got %d body=%s", activateEarlyRec.Code, activateEarlyRec.Body.String())
	}

	approve2 := httptest.NewRequest(http.MethodPost, "/admin/breakglass/approve", bytes.NewBufferString(`{
		"request_id":"`+requestID+`",
		"approved_by":"security-2@corp"
	}`))
	approve2 = approve2.WithContext(middleware.WithSPIFFEID(approve2.Context(), spiffeID))
	approve2Rec := httptest.NewRecorder()
	g.adminBreakGlassHandler(approve2Rec, approve2)
	if approve2Rec.Code != http.StatusOK {
		t.Fatalf("approve #2 expected 200, got %d body=%s", approve2Rec.Code, approve2Rec.Body.String())
	}

	activate := httptest.NewRequest(http.MethodPost, "/admin/breakglass/activate", bytes.NewBufferString(`{
		"request_id":"`+requestID+`",
		"activated_by":"ops@corp"
	}`))
	activate = activate.WithContext(middleware.WithSPIFFEID(activate.Context(), spiffeID))
	activateRec := httptest.NewRecorder()
	g.adminBreakGlassHandler(activateRec, activate)
	if activateRec.Code != http.StatusOK {
		t.Fatalf("activate expected 200, got %d body=%s", activateRec.Code, activateRec.Body.String())
	}

	revert := httptest.NewRequest(http.MethodPost, "/admin/breakglass/revert", bytes.NewBufferString(`{
		"request_id":"`+requestID+`",
		"reverted_by":"ops@corp"
	}`))
	revert = revert.WithContext(middleware.WithSPIFFEID(revert.Context(), spiffeID))
	revertRec := httptest.NewRecorder()
	g.adminBreakGlassHandler(revertRec, revert)
	if revertRec.Code != http.StatusOK {
		t.Fatalf("revert expected 200, got %d body=%s", revertRec.Code, revertRec.Body.String())
	}
}

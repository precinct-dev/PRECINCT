package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
)

func TestAdminApprovalsLifecycle(t *testing.T) {
	g := &Gateway{
		approvalCapabilities: middleware.NewApprovalCapabilityService("test-key", 5*time.Minute, 30*time.Minute, nil),
	}

	// request
	reqBody := `{
		"scope": {
			"action": "tool.call",
			"resource": "bash",
			"actor_spiffe_id": "spiffe://poc.local/agents/test",
			"session_id": "sess-admin-1"
		},
		"requested_by": "agent-owner@corp",
		"ttl_seconds": 120
	}`
	requestReq := httptest.NewRequest(http.MethodPost, "/admin/approvals/request", bytes.NewBufferString(reqBody))
	requestReq = requestReq.WithContext(middleware.WithSessionID(middleware.WithSPIFFEID(requestReq.Context(), "spiffe://poc.local/agents/test"), "sess-admin-1"))
	requestRec := httptest.NewRecorder()
	g.adminApprovalsHandler(requestRec, requestReq)
	if requestRec.Code != http.StatusOK {
		t.Fatalf("request endpoint expected 200, got %d body=%s", requestRec.Code, requestRec.Body.String())
	}
	var requestResp map[string]any
	if err := json.NewDecoder(requestRec.Body).Decode(&requestResp); err != nil {
		t.Fatalf("decode request response: %v", err)
	}
	record, _ := requestResp["record"].(map[string]any)
	requestID, _ := record["request_id"].(string)
	if requestID == "" {
		t.Fatalf("request response missing request_id: %v", requestResp)
	}

	// grant
	grantReqBody := `{"request_id":"` + requestID + `","approved_by":"security@corp","reason":"ticket-42"}`
	grantReq := httptest.NewRequest(http.MethodPost, "/admin/approvals/grant", bytes.NewBufferString(grantReqBody))
	grantReq = grantReq.WithContext(middleware.WithSessionID(middleware.WithSPIFFEID(grantReq.Context(), "spiffe://poc.local/agents/test"), "sess-admin-1"))
	grantRec := httptest.NewRecorder()
	g.adminApprovalsHandler(grantRec, grantReq)
	if grantRec.Code != http.StatusOK {
		t.Fatalf("grant endpoint expected 200, got %d body=%s", grantRec.Code, grantRec.Body.String())
	}
	var grantResp map[string]any
	if err := json.NewDecoder(grantRec.Body).Decode(&grantResp); err != nil {
		t.Fatalf("decode grant response: %v", err)
	}
	token, _ := grantResp["capability_token"].(string)
	if token == "" {
		t.Fatalf("grant response missing capability token: %v", grantResp)
	}

	// consume
	consumeReqBody := `{
		"capability_token":"` + token + `",
		"scope": {
			"action":"tool.call",
			"resource":"bash",
			"actor_spiffe_id":"spiffe://poc.local/agents/test",
			"session_id":"sess-admin-1"
		}
	}`
	consumeReq := httptest.NewRequest(http.MethodPost, "/admin/approvals/consume", bytes.NewBufferString(consumeReqBody))
	consumeReq = consumeReq.WithContext(middleware.WithSessionID(middleware.WithSPIFFEID(consumeReq.Context(), "spiffe://poc.local/agents/test"), "sess-admin-1"))
	consumeRec := httptest.NewRecorder()
	g.adminApprovalsHandler(consumeRec, consumeReq)
	if consumeRec.Code != http.StatusOK {
		t.Fatalf("consume endpoint expected 200, got %d body=%s", consumeRec.Code, consumeRec.Body.String())
	}
}

func TestAdminApprovalsDeny(t *testing.T) {
	g := &Gateway{
		approvalCapabilities: middleware.NewApprovalCapabilityService("test-key", 5*time.Minute, 30*time.Minute, nil),
	}

	createReq := httptest.NewRequest(http.MethodPost, "/admin/approvals/request", bytes.NewBufferString(`{
		"scope": {
			"action":"model.call",
			"resource":"gpt-4o",
			"actor_spiffe_id":"spiffe://poc.local/agents/test",
			"session_id":"sess-admin-2"
		}
	}`))
	createReq = createReq.WithContext(middleware.WithSessionID(middleware.WithSPIFFEID(createReq.Context(), "spiffe://poc.local/agents/test"), "sess-admin-2"))
	createRec := httptest.NewRecorder()
	g.adminApprovalsHandler(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create request expected 200, got %d body=%s", createRec.Code, createRec.Body.String())
	}
	var createResp map[string]any
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	record, _ := createResp["record"].(map[string]any)
	requestID, _ := record["request_id"].(string)
	if requestID == "" {
		t.Fatalf("missing request_id in create response: %v", createResp)
	}

	denyReq := httptest.NewRequest(http.MethodPost, "/admin/approvals/deny", bytes.NewBufferString(`{
		"request_id":"`+requestID+`",
		"denied_by":"security@corp",
		"reason":"human review denied"
	}`))
	denyReq = denyReq.WithContext(middleware.WithSessionID(middleware.WithSPIFFEID(denyReq.Context(), "spiffe://poc.local/agents/test"), "sess-admin-2"))
	denyRec := httptest.NewRecorder()
	g.adminApprovalsHandler(denyRec, denyReq)
	if denyRec.Code != http.StatusOK {
		t.Fatalf("deny endpoint expected 200, got %d body=%s", denyRec.Code, denyRec.Body.String())
	}
}

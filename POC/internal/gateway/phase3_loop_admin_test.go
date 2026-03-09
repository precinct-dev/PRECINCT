package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminLoopRunsListAndGet(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	handler := gw.Handler()
	caller := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"

	seed := validLoopRequest(validLoopAttributes())
	seed.Envelope.RunID = "run-loop-admin"
	seed.Policy.Envelope.RunID = "run-loop-admin"
	rec := sendPhase3Request(t, handler, "/v1/loop/check", caller, seed)
	if rec.Code != http.StatusOK {
		t.Fatalf("failed to seed loop run status=%d body=%s", rec.Code, rec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/loop/runs", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected list status 200 got=%d body=%s", listRec.Code, listRec.Body.String())
	}
	var listResp loopRunsAdminResponse
	if err := json.NewDecoder(bytes.NewBuffer(listRec.Body.Bytes())).Decode(&listResp); err != nil {
		t.Fatalf("decode list response failed: %v body=%s", err, listRec.Body.String())
	}
	if listResp.Status != "ok" || len(listResp.Runs) == 0 {
		t.Fatalf("unexpected list response: %+v", listResp)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/loop/runs/run-loop-admin", nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected get status 200 got=%d body=%s", getRec.Code, getRec.Body.String())
	}
	var getResp loopRunsAdminResponse
	if err := json.NewDecoder(bytes.NewBuffer(getRec.Body.Bytes())).Decode(&getResp); err != nil {
		t.Fatalf("decode get response failed: %v body=%s", err, getRec.Body.String())
	}
	if getResp.Run == nil || getResp.Run.RunID != "run-loop-admin" {
		t.Fatalf("unexpected get response: %+v", getResp)
	}
}

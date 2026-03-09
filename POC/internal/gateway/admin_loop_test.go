package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Unit Tests: Admin Loop Runs Endpoints
// ---------------------------------------------------------------------------

func TestAdminLoopRuns_ListReturnsOKWithRunsArray(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	g := &Gateway{loopPolicy: engine}

	req := httptest.NewRequest(http.MethodGet, "/admin/loop/runs", nil)
	rec := httptest.NewRecorder()
	g.adminLoopRunsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", resp["status"])
	}
	runs, ok := resp["runs"].([]any)
	if !ok {
		t.Fatalf("expected runs array, got %T", resp["runs"])
	}
	if len(runs) != 0 {
		t.Fatalf("expected empty runs, got %d", len(runs))
	}
}

func TestAdminLoopRuns_ListReturnsPopulatedRuns(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	g := &Gateway{loopPolicy: engine}

	// Create a run via evaluate.
	loopReq := makeLoopRequest("run-list-001", "boundary", nil)
	engine.evaluate(loopReq, "dec-001", "trace-001", time.Now().UTC())

	req := httptest.NewRequest(http.MethodGet, "/admin/loop/runs", nil)
	rec := httptest.NewRecorder()
	g.adminLoopRunsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	runs := resp["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}
	run := runs[0].(map[string]any)
	if run["run_id"] != "run-list-001" {
		t.Fatalf("expected run_id=run-list-001, got %v", run["run_id"])
	}
}

func TestAdminLoopRuns_DetailReturnsRunForKnownID(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	g := &Gateway{loopPolicy: engine}

	// Create a run.
	loopReq := makeLoopRequest("run-detail-001", "boundary", nil)
	engine.evaluate(loopReq, "dec-001", "trace-001", time.Now().UTC())

	req := httptest.NewRequest(http.MethodGet, "/admin/loop/runs/run-detail-001", nil)
	rec := httptest.NewRecorder()
	g.adminLoopRunsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", resp["status"])
	}
	run, ok := resp["run"].(map[string]any)
	if !ok {
		t.Fatalf("expected run object, got %T", resp["run"])
	}
	if run["run_id"] != "run-detail-001" {
		t.Fatalf("expected run_id=run-detail-001, got %v", run["run_id"])
	}
	// Verify state machine fields are present.
	if run["state"] == nil {
		t.Fatal("expected state field in run")
	}
	if run["limits"] == nil {
		t.Fatal("expected limits field in run")
	}
	if run["usage"] == nil {
		t.Fatal("expected usage field in run")
	}
}

func TestAdminLoopRuns_DetailReturns404ForUnknownID(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	g := &Gateway{loopPolicy: engine}

	req := httptest.NewRequest(http.MethodGet, "/admin/loop/runs/nonexistent-run", nil)
	rec := httptest.NewRecorder()
	g.adminLoopRunsHandler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "failed" {
		t.Fatalf("expected status=failed, got %v", resp["status"])
	}
	if resp["error"] != "run not found" {
		t.Fatalf("expected error='run not found', got %v", resp["error"])
	}
}

func TestAdminLoopRuns_HaltTransitionsToHaltedOperator(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	g := &Gateway{loopPolicy: engine}

	// Create a running run.
	loopReq := makeLoopRequest("run-halt-001", "boundary", nil)
	engine.evaluate(loopReq, "dec-001", "trace-001", time.Now().UTC())

	req := httptest.NewRequest(http.MethodPost, "/admin/loop/runs/run-halt-001/halt", nil)
	rec := httptest.NewRecorder()
	g.adminLoopRunsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", resp["status"])
	}
	if resp["halt_decision"] != "deny" {
		t.Fatalf("expected halt_decision=deny, got %v", resp["halt_decision"])
	}
	if resp["halt_reason"] != string(ReasonLoopHaltOperator) {
		t.Fatalf("expected halt_reason=LOOP_HALT_OPERATOR, got %v", resp["halt_reason"])
	}
	run := resp["run"].(map[string]any)
	if run["state"] != string(loopStateHaltedOperator) {
		t.Fatalf("expected HALTED_OPERATOR state, got %v", run["state"])
	}
}

func TestAdminLoopRuns_HaltOnAlreadyTerminalReturns409(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	g := &Gateway{loopPolicy: engine}

	// Create a run and complete it.
	loopReq := makeLoopRequest("run-halt-409", "boundary", nil)
	engine.evaluate(loopReq, "dec-001", "trace-001", time.Now().UTC())
	completeReq := makeLoopRequest("run-halt-409", "complete", nil)
	engine.evaluate(completeReq, "dec-002", "trace-002", time.Now().UTC())

	// Try to halt a completed run.
	req := httptest.NewRequest(http.MethodPost, "/admin/loop/runs/run-halt-409/halt", nil)
	rec := httptest.NewRecorder()
	g.adminLoopRunsHandler(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "failed" {
		t.Fatalf("expected status=failed, got %v", resp["status"])
	}
	if resp["error"] != "run already terminal" {
		t.Fatalf("expected error='run already terminal', got %v", resp["error"])
	}
}

func TestAdminLoopRuns_HaltOnAlreadyHaltedReturns409(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	g := &Gateway{loopPolicy: engine}

	// Create a run, halt it via operator.
	loopReq := makeLoopRequest("run-halt-double", "boundary", nil)
	engine.evaluate(loopReq, "dec-001", "trace-001", time.Now().UTC())
	haltReq := makeLoopRequest("run-halt-double", "operator_halt", nil)
	engine.evaluate(haltReq, "dec-002", "trace-002", time.Now().UTC())

	// Try to halt again via admin.
	req := httptest.NewRequest(http.MethodPost, "/admin/loop/runs/run-halt-double/halt", nil)
	rec := httptest.NewRecorder()
	g.adminLoopRunsHandler(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminLoopRuns_HaltOnUnknownRunReturns404(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	g := &Gateway{loopPolicy: engine}

	req := httptest.NewRequest(http.MethodPost, "/admin/loop/runs/unknown-run/halt", nil)
	rec := httptest.NewRecorder()
	g.adminLoopRunsHandler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminLoopRuns_PostOnListReturns405(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	g := &Gateway{loopPolicy: engine}

	req := httptest.NewRequest(http.MethodPost, "/admin/loop/runs", nil)
	rec := httptest.NewRecorder()
	g.adminLoopRunsHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminLoopRuns_GetOnHaltReturns405(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	g := &Gateway{loopPolicy: engine}

	// Create a run so the path is valid.
	loopReq := makeLoopRequest("run-method-test", "boundary", nil)
	engine.evaluate(loopReq, "dec-001", "trace-001", time.Now().UTC())

	req := httptest.NewRequest(http.MethodGet, "/admin/loop/runs/run-method-test/halt", nil)
	rec := httptest.NewRecorder()
	g.adminLoopRunsHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Integration Tests: No mocks, real engine lifecycle
// ---------------------------------------------------------------------------

func TestAdminLoopRuns_Integration_CreateInspectHalt(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	g := &Gateway{loopPolicy: engine}

	// Step 1: Create a run via loop check (real state machine call).
	loopReq := makeLoopRequest("int-run-001", "boundary", nil)
	decision, reason, status, _ := engine.evaluate(loopReq, "dec-001", "trace-001", time.Now().UTC())
	if decision != DecisionAllow || reason != ReasonLoopAllow || status != 200 {
		t.Fatalf("setup: unexpected evaluate result: decision=%s reason=%s status=%d", decision, reason, status)
	}

	// Step 2: Inspect via admin detail endpoint.
	detailReq := httptest.NewRequest(http.MethodGet, "/admin/loop/runs/int-run-001", nil)
	detailRec := httptest.NewRecorder()
	g.adminLoopRunsHandler(detailRec, detailReq)

	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail: expected 200, got %d body=%s", detailRec.Code, detailRec.Body.String())
	}
	var detailResp map[string]any
	if err := json.NewDecoder(detailRec.Body).Decode(&detailResp); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	run := detailResp["run"].(map[string]any)
	if run["state"] != string(loopStateRunning) {
		t.Fatalf("detail: expected RUNNING state, got %v", run["state"])
	}

	// Step 3: Halt via admin endpoint.
	haltReq := httptest.NewRequest(http.MethodPost, "/admin/loop/runs/int-run-001/halt", nil)
	haltRec := httptest.NewRecorder()
	g.adminLoopRunsHandler(haltRec, haltReq)

	if haltRec.Code != http.StatusOK {
		t.Fatalf("halt: expected 200, got %d body=%s", haltRec.Code, haltRec.Body.String())
	}
	var haltResp map[string]any
	if err := json.NewDecoder(haltRec.Body).Decode(&haltResp); err != nil {
		t.Fatalf("decode halt: %v", err)
	}
	haltedRun := haltResp["run"].(map[string]any)
	if haltedRun["state"] != string(loopStateHaltedOperator) {
		t.Fatalf("halt: expected HALTED_OPERATOR, got %v", haltedRun["state"])
	}
	if haltResp["halt_decision"] != "deny" {
		t.Fatalf("halt: expected halt_decision=deny, got %v", haltResp["halt_decision"])
	}
	if haltResp["halt_reason"] != string(ReasonLoopHaltOperator) {
		t.Fatalf("halt: expected halt_reason=LOOP_HALT_OPERATOR, got %v", haltResp["halt_reason"])
	}

	// Step 4: Verify halted run cannot be resumed.
	// Attempt another boundary check on the halted run.
	resumeReq := makeLoopRequest("int-run-001", "boundary", nil)
	decision2, reason2, status2, _ := engine.evaluate(resumeReq, "dec-003", "trace-003", time.Now().UTC())
	if decision2 != DecisionDeny {
		t.Fatalf("resume: expected DecisionDeny, got %s", decision2)
	}
	if reason2 != ReasonLoopHaltOperator {
		t.Fatalf("resume: expected LOOP_HALT_OPERATOR reason, got %s", reason2)
	}
	if status2 != httpStatusConflict {
		t.Fatalf("resume: expected 409, got %d", status2)
	}
}

func TestAdminLoopRuns_Integration_HaltedRunCannotBeResumed(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	g := &Gateway{loopPolicy: engine}

	// Create and halt a run.
	loopReq := makeLoopRequest("int-run-002", "boundary", nil)
	engine.evaluate(loopReq, "dec-001", "trace-001", time.Now().UTC())

	haltReq := httptest.NewRequest(http.MethodPost, "/admin/loop/runs/int-run-002/halt", nil)
	haltRec := httptest.NewRecorder()
	g.adminLoopRunsHandler(haltRec, haltReq)

	if haltRec.Code != http.StatusOK {
		t.Fatalf("halt: expected 200, got %d body=%s", haltRec.Code, haltRec.Body.String())
	}

	// Verify the run is HALTED_OPERATOR via detail endpoint.
	detailReq := httptest.NewRequest(http.MethodGet, "/admin/loop/runs/int-run-002", nil)
	detailRec := httptest.NewRecorder()
	g.adminLoopRunsHandler(detailRec, detailReq)

	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail after halt: expected 200, got %d", detailRec.Code)
	}
	var detailResp map[string]any
	if err := json.NewDecoder(detailRec.Body).Decode(&detailResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	run := detailResp["run"].(map[string]any)
	if run["state"] != string(loopStateHaltedOperator) {
		t.Fatalf("expected HALTED_OPERATOR, got %v", run["state"])
	}

	// Attempting to halt again via admin returns 409.
	haltAgainReq := httptest.NewRequest(http.MethodPost, "/admin/loop/runs/int-run-002/halt", nil)
	haltAgainRec := httptest.NewRecorder()
	g.adminLoopRunsHandler(haltAgainRec, haltAgainReq)

	if haltAgainRec.Code != http.StatusConflict {
		t.Fatalf("halt again: expected 409, got %d body=%s", haltAgainRec.Code, haltAgainRec.Body.String())
	}

	// Attempting to resume via direct evaluate also fails.
	resumeReq := makeLoopRequest("int-run-002", "boundary", nil)
	decision, reason, status, _ := engine.evaluate(resumeReq, "dec-010", "trace-010", time.Now().UTC())
	if decision != DecisionDeny || reason != ReasonLoopHaltOperator || status != httpStatusConflict {
		t.Fatalf("resume after halt: expected deny/LOOP_HALT_OPERATOR/409, got %s/%s/%d", decision, reason, status)
	}
}

func TestAdminLoopRuns_Integration_ListShowsMultipleRuns(t *testing.T) {
	engine := newLoopPlanePolicyEngine()
	g := &Gateway{loopPolicy: engine}

	// Create several runs in different states.
	now := time.Now().UTC()
	req1 := makeLoopRequest("int-list-001", "boundary", nil)
	engine.evaluate(req1, "dec-001", "trace-001", now)

	req2 := makeLoopRequest("int-list-002", "boundary", nil)
	engine.evaluate(req2, "dec-002", "trace-002", now.Add(time.Second))

	req3 := makeLoopRequest("int-list-003", "boundary", nil)
	engine.evaluate(req3, "dec-003", "trace-003", now.Add(2*time.Second))
	completeReq := makeLoopRequest("int-list-003", "complete", nil)
	engine.evaluate(completeReq, "dec-004", "trace-004", now.Add(3*time.Second))

	// List all runs.
	listReq := httptest.NewRequest(http.MethodGet, "/admin/loop/runs", nil)
	listRec := httptest.NewRecorder()
	g.adminLoopRunsHandler(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", listRec.Code, listRec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(listRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	runs := resp["runs"].([]any)
	if len(runs) != 3 {
		t.Fatalf("expected 3 runs, got %d", len(runs))
	}

	// Runs should be sorted by UpdatedAt desc -- int-list-003 was last updated.
	first := runs[0].(map[string]any)
	if first["run_id"] != "int-list-003" {
		t.Fatalf("expected first run_id=int-list-003 (most recently updated), got %v", first["run_id"])
	}
}

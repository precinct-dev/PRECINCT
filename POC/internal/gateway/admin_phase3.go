package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
)

// logLoopAdminEvent emits an audit event for loop admin operations.
// action should be one of: "admin.loop.list", "admin.loop.detail", "admin.loop.halt".
func (g *Gateway) logLoopAdminEvent(r *http.Request, action string, httpStatus int, metadata map[string]any) {
	if g == nil || g.auditor == nil {
		return
	}
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})

	// Build a human-readable result string from metadata.
	result := fmt.Sprintf("action=%s status=%d", action, httpStatus)
	if metadata != nil {
		if runID, ok := metadata["run_id"]; ok {
			result += fmt.Sprintf(" run_id=%v", runID)
		}
		if state, ok := metadata["state"]; ok {
			result += fmt.Sprintf(" state=%v", state)
		}
		if reason, ok := metadata["halt_reason"]; ok {
			result += fmt.Sprintf(" halt_reason=%v", reason)
		}
		if errMsg, ok := metadata["error"]; ok {
			result += fmt.Sprintf(" error=%v", errMsg)
		}
	}

	g.auditor.Log(middleware.AuditEvent{
		SessionID:  middleware.GetSessionID(r.Context()),
		DecisionID: decisionID,
		TraceID:    traceID,
		SPIFFEID:   middleware.GetSPIFFEID(r.Context()),
		Action:     action,
		Result:     result,
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: httpStatus,
	})
}

type dlpRulesetStatus struct {
	ActiveVersion   string            `json:"active_version"`
	ActiveDigest    string            `json:"active_digest"`
	ActiveRulesetID string            `json:"active_ruleset_id,omitempty"`
	CanaryRulesetID string            `json:"canary_ruleset_id,omitempty"`
	ActiveRuleset   *dlpRulesetRecord `json:"active_ruleset,omitempty"`
	CanaryRuleset   *dlpRulesetRecord `json:"canary_ruleset,omitempty"`
	Mode            string            `json:"mode"`
	Note            string            `json:"note,omitempty"`
}

type dlpRuleOpsRequest struct {
	RulesetID  string         `json:"ruleset_id"`
	Content    map[string]any `json:"content,omitempty"`
	CreatedBy  string         `json:"created_by,omitempty"`
	ApprovedBy string         `json:"approved_by,omitempty"`
	Signature  string         `json:"signature,omitempty"`
	Mode       string         `json:"mode,omitempty"`
}

const dlpRulesetAdminPath = "/admin/dlp/rulesets"

func (g *Gateway) handleV24AdminEntry(w http.ResponseWriter, r *http.Request) bool {
	if !isAdminPath(r.URL.Path) {
		return false
	}
	if !g.authorizeAdminRequest(w, r) {
		return true
	}

	if strings.HasPrefix(r.URL.Path, dlpRulesetAdminPath) {
		g.adminDLPRulesetsHandler(w, r)
		return true
	}
	if strings.HasPrefix(r.URL.Path, approvalAdminPath) {
		g.adminApprovalsHandler(w, r)
		return true
	}
	if strings.HasPrefix(r.URL.Path, breakGlassAdminPath) {
		g.adminBreakGlassHandler(w, r)
		return true
	}
	if strings.HasPrefix(r.URL.Path, profileAdminPath) {
		g.adminProfilesHandler(w, r)
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/admin/loop/runs") {
		g.adminLoopRunsHandler(w, r)
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/admin/circuit-breakers/reset") {
		g.adminCircuitBreakersResetHandler(w, r)
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/admin/circuit-breakers") {
		g.adminCircuitBreakersHandler(w, r)
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/admin/policy/reload") {
		g.adminPolicyReloadHandler(w, r)
		return true
	}

	http.NotFound(w, r)
	return true
}

// adminDLPRulesetsHandler exposes governed DLP RuleOps lifecycle operations.
//
// Supported endpoints:
//   - GET  /admin/dlp/rulesets
//   - GET  /admin/dlp/rulesets/active
//   - POST /admin/dlp/rulesets/create
//   - POST /admin/dlp/rulesets/validate
//   - POST /admin/dlp/rulesets/approve
//   - POST /admin/dlp/rulesets/sign
//   - POST /admin/dlp/rulesets/promote
//   - POST /admin/dlp/rulesets/rollback
func (g *Gateway) adminDLPRulesetsHandler(w http.ResponseWriter, r *http.Request) {
	if g == nil || g.dlpRuleOps == nil {
		writeV24GatewayError(
			w,
			r,
			http.StatusServiceUnavailable,
			middleware.ErrMCPTransportFailed,
			"dlp ruleops unavailable",
			v24MiddlewareRuleOpsAdmin,
			ReasonContractInvalid,
			nil,
		)
		return
	}

	pathSuffix := strings.TrimPrefix(r.URL.Path, dlpRulesetAdminPath)
	if pathSuffix == r.URL.Path {
		http.NotFound(w, r)
		return
	}

	switch pathSuffix {
	case "", "/":
		if r.Method != http.MethodGet {
			g.writeRuleOpsMethodNotAllowed(w, r, "GET")
			return
		}
		g.handleDLPRulesetSummary(w, r)
		return
	case "/active":
		if r.Method != http.MethodGet {
			g.writeRuleOpsMethodNotAllowed(w, r, "GET")
			return
		}
		g.handleDLPRulesetActive(w, r)
		return
	case "/create":
		g.handleDLPRulesetOperation(w, r, "create")
		return
	case "/validate":
		g.handleDLPRulesetOperation(w, r, "validate")
		return
	case "/approve":
		g.handleDLPRulesetOperation(w, r, "approve")
		return
	case "/sign":
		g.handleDLPRulesetOperation(w, r, "sign")
		return
	case "/promote":
		g.handleDLPRulesetOperation(w, r, "promote")
		return
	case "/rollback":
		g.handleDLPRulesetOperation(w, r, "rollback")
		return
	default:
		http.NotFound(w, r)
		return
	}
}

func (g *Gateway) handleDLPRulesetSummary(w http.ResponseWriter, r *http.Request) {
	version, digest := g.dlpRuleOps.ActiveRuleset()
	active, hasActive := g.dlpRuleOps.ActiveRecord()
	canary, hasCanary := g.dlpRuleOps.CanaryRecord()

	var activeRef *dlpRulesetRecord
	if hasActive {
		a := active
		activeRef = &a
	}
	var canaryRef *dlpRulesetRecord
	if hasCanary {
		c := canary
		canaryRef = &c
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dlpRulesetStatus{
		ActiveVersion:   version,
		ActiveDigest:    digest,
		ActiveRulesetID: active.RulesetID,
		CanaryRulesetID: canary.RulesetID,
		ActiveRuleset:   activeRef,
		CanaryRuleset:   canaryRef,
		Mode:            "governed_lifecycle",
		Note:            "RuleOps lifecycle supports create, validate, approve, sign, promote(canary|active), rollback.",
	})
}

func (g *Gateway) handleDLPRulesetActive(w http.ResponseWriter, r *http.Request) {
	active, ok := g.dlpRuleOps.ActiveRecord()
	if !ok {
		writeV24GatewayError(
			w,
			r,
			http.StatusNotFound,
			middleware.ErrContractValidationFailed,
			"no active ruleset",
			v24MiddlewareRuleOpsAdmin,
			ReasonContractInvalid,
			nil,
		)
		return
	}
	canary, hasCanary := g.dlpRuleOps.CanaryRecord()
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	g.logDLPRuleOpsDecision(r, active.RulesetID, "active", "allow", "active_ruleset_reported", decisionID, traceID, http.StatusOK)

	resp := map[string]any{
		"status":       "ok",
		"active":       active,
		"decision_id":  decisionID,
		"trace_id":     traceID,
		"active_state": active.State,
	}
	if hasCanary {
		resp["canary"] = canary
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) handleDLPRulesetOperation(w http.ResponseWriter, r *http.Request, operation string) {
	if r.Method != http.MethodPost {
		g.writeRuleOpsMethodNotAllowed(w, r, "POST")
		return
	}
	req, ok := decodeDLPRuleOpsRequest(w, r, operation)
	if !ok {
		return
	}

	var (
		rec dlpRulesetRecord
		err error
	)
	switch operation {
	case "create":
		rec, err = g.dlpRuleOps.Create(req.RulesetID, req.Content, req.CreatedBy)
	case "validate":
		rec, err = g.dlpRuleOps.Validate(req.RulesetID)
	case "approve":
		rec, err = g.dlpRuleOps.Approve(req.RulesetID, req.ApprovedBy)
	case "sign":
		rec, err = g.dlpRuleOps.Sign(req.RulesetID, req.Signature)
	case "promote":
		rec, err = g.dlpRuleOps.Promote(req.RulesetID, req.Mode)
	case "rollback":
		rec, err = g.dlpRuleOps.Rollback(req.RulesetID)
	default:
		err = fmt.Errorf("unsupported operation: %s", operation)
	}
	if err != nil {
		g.writeDLPRuleOpsError(w, r, req.RulesetID, operation, err)
		return
	}
	g.writeDLPRuleOpsOK(w, r, req.RulesetID, operation, rec)
}

func decodeDLPRuleOpsRequest(w http.ResponseWriter, r *http.Request, operation string) (dlpRuleOpsRequest, bool) {
	var req dlpRuleOpsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV24GatewayError(
			w,
			r,
			http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest,
			"invalid json payload",
			v24MiddlewareRuleOpsAdmin,
			ReasonContractInvalid,
			map[string]any{
				"operation": operation,
			},
		)
		return dlpRuleOpsRequest{}, false
	}
	return req, true
}

func (g *Gateway) writeRuleOpsMethodNotAllowed(w http.ResponseWriter, r *http.Request, allowed string) {
	w.Header().Set("Allow", allowed)
	writeV24GatewayError(
		w,
		r,
		http.StatusMethodNotAllowed,
		middleware.ErrMCPInvalidRequest,
		"method not allowed",
		v24MiddlewareRuleOpsAdmin,
		ReasonContractInvalid,
		map[string]any{"allow": allowed},
	)
}

func (g *Gateway) writeDLPRuleOpsOK(w http.ResponseWriter, r *http.Request, rulesetID, operation string, rec dlpRulesetRecord) {
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	g.logDLPRuleOpsDecision(r, rulesetID, operation, "allow", "operation_success", decisionID, traceID, http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ruleset_id":  rulesetID,
		"operation":   operation,
		"status":      "ok",
		"state":       rec.State,
		"record":      rec,
		"decision_id": decisionID,
		"trace_id":    traceID,
	})
}

func (g *Gateway) writeDLPRuleOpsError(w http.ResponseWriter, r *http.Request, rulesetID, operation string, err error) {
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	g.logDLPRuleOpsDecision(r, rulesetID, operation, "deny", err.Error(), decisionID, traceID, http.StatusBadRequest)
	writeV24GatewayError(
		w,
		r,
		http.StatusBadRequest,
		middleware.ErrContractValidationFailed,
		err.Error(),
		v24MiddlewareRuleOpsAdmin,
		ReasonContractInvalid,
		map[string]any{
			"ruleset_id": strings.TrimSpace(rulesetID),
			"operation":  operation,
		},
	)
}

func (g *Gateway) logDLPRuleOpsDecision(r *http.Request, rulesetID, operation, decision, reason, decisionID, traceID string, httpStatus int) {
	if g == nil || g.auditor == nil {
		return
	}
	result := fmt.Sprintf("ruleset_id=%s operation=%s decision=%s reason=%s", rulesetID, operation, decision, reason)
	g.auditor.Log(middleware.AuditEvent{
		SessionID:  middleware.GetSessionID(r.Context()),
		DecisionID: decisionID,
		TraceID:    traceID,
		SPIFFEID:   middleware.GetSPIFFEID(r.Context()),
		Action:     "ruleops." + operation,
		Result:     result,
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: httpStatus,
	})
}

// adminLoopRunsHandler exposes loop run observability and operator halt.
//
// Supported endpoints:
//   - GET  /admin/loop/runs           -> list all runs
//   - GET  /admin/loop/runs/<run_id>  -> single run detail
//   - POST /admin/loop/runs/<run_id>/halt -> operator halt
func (g *Gateway) adminLoopRunsHandler(w http.ResponseWriter, r *http.Request) {
	const basePath = "/admin/loop/runs"
	suffix := strings.TrimPrefix(r.URL.Path, basePath)

	// GET /admin/loop/runs or GET /admin/loop/runs/
	if suffix == "" || suffix == "/" {
		if r.Method != http.MethodGet {
			g.writeLoopAdminMethodNotAllowed(w, r, "GET")
			return
		}
		g.handleAdminLoopRunsList(w, r)
		return
	}

	// Remove leading slash to get the run ID or run_id/halt.
	suffix = strings.TrimPrefix(suffix, "/")

	// POST /admin/loop/runs/<run_id>/halt
	if strings.HasSuffix(suffix, "/halt") {
		if r.Method != http.MethodPost {
			g.writeLoopAdminMethodNotAllowed(w, r, "POST")
			return
		}
		runID := strings.TrimSuffix(suffix, "/halt")
		if runID == "" {
			writeV24GatewayError(w, r, http.StatusNotFound, middleware.ErrMCPInvalidRequest,
				"run not found", v24MiddlewareLoopAdmin, ReasonContractInvalid, nil)
			return
		}
		g.handleAdminLoopRunHalt(w, r, runID)
		return
	}

	// GET /admin/loop/runs/<run_id>
	if r.Method != http.MethodGet {
		g.writeLoopAdminMethodNotAllowed(w, r, "GET")
		return
	}
	runID := suffix
	if strings.Contains(runID, "/") {
		http.NotFound(w, r)
		return
	}
	g.handleAdminLoopRunDetail(w, r, runID)
}

func (g *Gateway) handleAdminLoopRunsList(w http.ResponseWriter, r *http.Request) {
	var runs []loopRunRecord
	if g.loopPolicy != nil {
		runs = g.loopPolicy.listRuns()
	}
	g.logLoopAdminEvent(r, "admin.loop.list", http.StatusOK, map[string]any{
		"run_count": len(runs),
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"runs":   runs,
	})
}

func (g *Gateway) handleAdminLoopRunDetail(w http.ResponseWriter, r *http.Request, runID string) {
	if g.loopPolicy == nil {
		g.logLoopAdminEvent(r, "admin.loop.detail", http.StatusNotFound, map[string]any{
			"run_id": runID,
			"error":  "run not found",
		})
		writeV24GatewayError(w, r, http.StatusNotFound, middleware.ErrMCPInvalidRequest,
			"run not found", v24MiddlewareLoopAdmin, ReasonContractInvalid,
			map[string]any{"run_id": runID})
		return
	}
	run, ok := g.loopPolicy.getRun(runID)
	if !ok {
		g.logLoopAdminEvent(r, "admin.loop.detail", http.StatusNotFound, map[string]any{
			"run_id": runID,
			"error":  "run not found",
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "failed",
			"error":  "run not found",
		})
		return
	}
	g.logLoopAdminEvent(r, "admin.loop.detail", http.StatusOK, map[string]any{
		"run_id": runID,
		"state":  string(run.State),
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"run":    run,
	})
}

func (g *Gateway) handleAdminLoopRunHalt(w http.ResponseWriter, r *http.Request, runID string) {
	if g.loopPolicy == nil {
		g.logLoopAdminEvent(r, "admin.loop.halt", http.StatusNotFound, map[string]any{
			"run_id": runID,
			"error":  "run not found",
		})
		writeV24GatewayError(w, r, http.StatusNotFound, middleware.ErrMCPInvalidRequest,
			"run not found", v24MiddlewareLoopAdmin, ReasonContractInvalid,
			map[string]any{"run_id": runID})
		return
	}

	// Check if the run exists before attempting halt.
	run, ok := g.loopPolicy.getRun(runID)
	if !ok {
		g.logLoopAdminEvent(r, "admin.loop.halt", http.StatusNotFound, map[string]any{
			"run_id": runID,
			"error":  "run not found",
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "failed",
			"error":  "run not found",
		})
		return
	}

	// If the run is already in a terminal state, return 409 Conflict.
	if isLoopTerminalState(run.State) {
		g.logLoopAdminEvent(r, "admin.loop.halt", http.StatusConflict, map[string]any{
			"run_id": runID,
			"state":  string(run.State),
			"error":  "run already terminal",
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "failed",
			"error":  "run already terminal",
			"run":    run,
		})
		return
	}

	// Construct a synthetic PlaneRequestV2 that passes through evaluate().
	// Re-use the existing run's limits and usage to avoid LIMITS_IMMUTABLE_VIOLATION.
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	req := PlaneRequestV2{
		Envelope: RunEnvelope{
			RunID:         runID,
			SessionID:     run.SessionID,
			Tenant:        "admin",
			ActorSPIFFEID: "admin",
			Plane:         PlaneLoop,
		},
		Policy: PolicyInputV2{
			Envelope: RunEnvelope{
				RunID:         runID,
				SessionID:     run.SessionID,
				Tenant:        "admin",
				ActorSPIFFEID: "admin",
				Plane:         PlaneLoop,
			},
			Action:   "loop.check",
			Resource: "agent-loop",
			Attributes: map[string]any{
				"run_id": runID,
				"event":  "operator_halt",
				"limits": loopLimitsToMap(run.Limits),
				"usage":  loopUsageToMap(run.Usage),
			},
		},
	}

	decision, reason, _, _ := g.loopPolicy.evaluate(req, decisionID, traceID, time.Now().UTC())

	// Re-fetch the updated run after evaluate.
	updatedRun, _ := g.loopPolicy.getRun(runID)
	g.logLoopAdminEvent(r, "admin.loop.halt", http.StatusOK, map[string]any{
		"run_id":      runID,
		"state":       string(updatedRun.State),
		"halt_reason": string(reason),
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":        "ok",
		"run":           updatedRun,
		"halt_decision": string(decision),
		"halt_reason":   string(reason),
	})
}

func (g *Gateway) writeLoopAdminMethodNotAllowed(w http.ResponseWriter, r *http.Request, allowed string) {
	w.Header().Set("Allow", allowed)
	writeV24GatewayError(w, r, http.StatusMethodNotAllowed, middleware.ErrMCPInvalidRequest,
		"method not allowed", v24MiddlewareLoopAdmin, ReasonContractInvalid,
		map[string]any{"allow": allowed})
}

// loopLimitsToMap converts immutable limits struct to a map for synthetic requests.
func loopLimitsToMap(l loopImmutableLimits) map[string]any {
	return map[string]any{
		"max_steps":              l.MaxSteps,
		"max_tool_calls":         l.MaxToolCalls,
		"max_model_calls":        l.MaxModelCalls,
		"max_wall_time_ms":       l.MaxWallTimeMS,
		"max_egress_bytes":       l.MaxEgressBytes,
		"max_model_cost_usd":     l.MaxModelCostUSD,
		"max_provider_failovers": l.MaxProviderFailovers,
		"max_risk_score":         l.MaxRiskScore,
	}
}

// loopUsageToMap converts usage snapshot struct to a map for synthetic requests.
func loopUsageToMap(u loopUsageSnapshot) map[string]any {
	return map[string]any{
		"steps":              u.Steps,
		"tool_calls":         u.ToolCalls,
		"model_calls":        u.ModelCalls,
		"wall_time_ms":       u.WallTimeMS,
		"egress_bytes":       u.EgressBytes,
		"model_cost_usd":     u.ModelCostUSD,
		"provider_failovers": u.ProviderFailovers,
		"risk_score":         u.RiskScore,
	}
}

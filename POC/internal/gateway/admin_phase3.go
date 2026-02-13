package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

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
	if strings.HasPrefix(r.URL.Path, "/admin/loop/runs") {
		g.adminLoopRunsHandler(w, r)
		return true
	}
	return false
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

// adminLoopRunsHandler exposes read-only loop run metadata. In the POC the loop
// plane is enforced mostly via immutable external limits (rate limiting, timeouts).
func (g *Gateway) adminLoopRunsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeV24GatewayError(
			w,
			r,
			http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest,
			"method not allowed",
			v24MiddlewareLoopAdmin,
			ReasonContractInvalid,
			map[string]any{"expected_method": http.MethodGet},
		)
		return
	}

	var runs []loopRunRecord
	if g.loopPolicy != nil {
		runs = g.loopPolicy.listRuns()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"runs": runs,
	})
}

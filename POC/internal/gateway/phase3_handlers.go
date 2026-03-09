package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

const (
	phase3AuditEventTypeDecisionV2 = "uasgs.plane.decision.v2"
)

func isDirectModelPath(path string) bool {
	return path == "/v1/model/direct" || path == "/v1/model/bypass"
}

func planeFromPath(path string) (Plane, bool) {
	switch path {
	case "/v1/ingress/admit":
		return PlaneIngress, true
	case "/v1/model/call":
		return PlaneModel, true
	case "/v1/context/admit":
		return PlaneContext, true
	case "/v1/loop/check":
		return PlaneLoop, true
	case "/v1/tool/execute":
		return PlaneTool, true
	default:
		return "", false
	}
}

func reasonForPlaneAllow(plane Plane) ReasonCode {
	switch plane {
	case PlaneIngress:
		return ReasonIngressAllow
	case PlaneModel:
		return ReasonModelAllow
	case PlaneContext:
		return ReasonContextAllow
	case PlaneLoop:
		return ReasonLoopAllow
	case PlaneTool:
		return ReasonToolAllow
	default:
		return ReasonContractInvalid
	}
}

// handlePhase3PlaneEntry routes baseline Phase 3 plane contracts through internal handlers.
// Returns true when the request path was handled.
func (g *Gateway) handlePhase3PlaneEntry(w http.ResponseWriter, r *http.Request) bool {
	if isDirectModelPath(r.URL.Path) {
		resp := PlaneDecisionV2{
			Decision:   DecisionDeny,
			ReasonCode: ReasonModelDirectEgressDeny,
			Envelope: RunEnvelope{
				RunID:         "legacy-model-direct",
				SessionID:     middleware.GetSessionID(r.Context()),
				Tenant:        "unknown",
				ActorSPIFFEID: middleware.GetSPIFFEID(r.Context()),
				Plane:         PlaneModel,
			},
			TraceID:    middleware.GetTraceID(r.Context()),
			DecisionID: middleware.GetDecisionID(r.Context()),
			Metadata: map[string]any{
				"path": r.URL.Path,
			},
		}
		g.writePlaneDecision(w, r, http.StatusForbidden, resp)
		return true
	}

	plane, ok := planeFromPath(r.URL.Path)
	if !ok {
		return false
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}

	var req PlaneRequestV2
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		g.writePlaneError(w, r, plane, http.StatusBadRequest, ReasonContractInvalid, "Invalid JSON payload")
		return true
	}
	if err := req.Validate(); err != nil {
		g.writePlaneError(w, r, plane, http.StatusBadRequest, ReasonContractInvalid, err.Error())
		return true
	}
	if req.Envelope.Plane != plane {
		g.writePlaneError(w, r, plane, http.StatusBadRequest, ReasonContractPlaneMismatch, "envelope.plane does not match endpoint")
		return true
	}

	traceID, decisionID := getDecisionCorrelationIDs(r, req.Envelope)
	if plane == PlaneIngress {
		g.handleIngressPlaneAdmit(w, r, req, traceID, decisionID)
		return true
	}
	if plane == PlaneModel {
		g.handleModelPlaneCall(w, r, req, traceID, decisionID)
		return true
	}
	if plane == PlaneContext {
		g.handleContextPlaneAdmit(w, r, req, traceID, decisionID)
		return true
	}
	if plane == PlaneLoop {
		g.handleLoopPlaneCheck(w, r, req, traceID, decisionID)
		return true
	}
	if plane == PlaneTool {
		g.handleToolPlaneExecute(w, r, req, traceID, decisionID)
		return true
	}

	resp := PlaneDecisionV2{
		Decision:   DecisionAllow,
		ReasonCode: reasonForPlaneAllow(plane),
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
	}
	g.writePlaneDecision(w, r, http.StatusOK, resp)
	return true
}

func (g *Gateway) writePlaneError(w http.ResponseWriter, r *http.Request, plane Plane, status int, reason ReasonCode, msg string) {
	resp := PlaneDecisionV2{
		Decision:   DecisionDeny,
		ReasonCode: reason,
		Envelope: RunEnvelope{
			RunID:         "invalid",
			SessionID:     middleware.GetSessionID(r.Context()),
			Tenant:        "unknown",
			ActorSPIFFEID: middleware.GetSPIFFEID(r.Context()),
			Plane:         plane,
		},
		TraceID:    middleware.GetTraceID(r.Context()),
		DecisionID: middleware.GetDecisionID(r.Context()),
	}
	g.logPlaneDecision(r, resp, status)

	middleware.WriteGatewayError(w, r, status, middleware.GatewayError{
		Code:           middleware.ErrContractValidationFailed,
		Message:        msg,
		Middleware:     "uasgs_plane_entry",
		MiddlewareStep: 0,
		Details: map[string]any{
			"plane":       plane,
			"reason_code": reason,
		},
		Remediation: "Use Phase 3 contract shape with matching envelope.plane and required fields.",
	})
}

func (g *Gateway) handleModelPlaneCall(w http.ResponseWriter, r *http.Request, req PlaneRequestV2, traceID, decisionID string) {
	if !modelCallerIsAuthenticated(r, req.Envelope.ActorSPIFFEID) {
		resp := PlaneDecisionV2{
			Decision:   DecisionDeny,
			ReasonCode: ReasonModelCallerUnauth,
			Envelope:   req.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata: map[string]any{
				"context_spiffe_id":  middleware.GetSPIFFEID(r.Context()),
				"envelope_spiffe_id": req.Envelope.ActorSPIFFEID,
			},
		}
		g.writePlaneDecision(w, r, http.StatusUnauthorized, resp)
		return
	}
	rlmMetadata := map[string]any{}
	if handled, decision, reason, status, metadata := g.evaluateRLMGovernance(req); handled {
		if decision != DecisionAllow {
			resp := PlaneDecisionV2{
				Decision:   decision,
				ReasonCode: reason,
				Envelope:   req.Envelope,
				TraceID:    traceID,
				DecisionID: decisionID,
				Metadata:   metadata,
			}
			g.writePlaneDecision(w, r, status, resp)
			return
		}
		rlmMetadata = metadata
	}

	if g.modelPlanePolicy == nil {
		g.modelPlanePolicy = newModelPlanePolicyEngine()
	}

	decision, reason, status, metadata := g.modelPlanePolicy.evaluate(req)
	for k, v := range rlmMetadata {
		metadata[k] = v
	}
	resp := PlaneDecisionV2{
		Decision:   decision,
		ReasonCode: reason,
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata:   metadata,
	}
	g.writePlaneDecision(w, r, status, resp)
}

func (g *Gateway) handleIngressPlaneAdmit(w http.ResponseWriter, r *http.Request, req PlaneRequestV2, traceID, decisionID string) {
	if g.ingressPolicy == nil {
		g.ingressPolicy = newIngressPlanePolicyEngine()
	}

	decision, reason, status, metadata := g.ingressPolicy.evaluate(req, time.Now().UTC())
	resp := PlaneDecisionV2{
		Decision:   decision,
		ReasonCode: reason,
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata:   metadata,
	}
	g.writePlaneDecision(w, r, status, resp)
}

func (g *Gateway) handleContextPlaneAdmit(w http.ResponseWriter, r *http.Request, req PlaneRequestV2, traceID, decisionID string) {
	if g.contextPolicy == nil {
		g.contextPolicy = newContextPlanePolicyEngine()
	}

	decision, reason, status, metadata := g.contextPolicy.evaluate(req, decisionID, traceID, time.Now().UTC())
	resp := PlaneDecisionV2{
		Decision:   decision,
		ReasonCode: reason,
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata:   metadata,
	}
	g.writePlaneDecision(w, r, status, resp)
}

func (g *Gateway) handleLoopPlaneCheck(w http.ResponseWriter, r *http.Request, req PlaneRequestV2, traceID, decisionID string) {
	if g.loopPolicy == nil {
		g.loopPolicy = newLoopPlanePolicyEngine()
	}

	decision, reason, status, metadata := g.loopPolicy.evaluate(req, decisionID, traceID, time.Now().UTC())
	resp := PlaneDecisionV2{
		Decision:   decision,
		ReasonCode: reason,
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata:   metadata,
	}
	g.writePlaneDecision(w, r, status, resp)
}

func (g *Gateway) handleToolPlaneExecute(w http.ResponseWriter, r *http.Request, req PlaneRequestV2, traceID, decisionID string) {
	rlmMetadata := map[string]any{}
	if handled, decision, reason, status, metadata := g.evaluateRLMGovernance(req); handled {
		if decision != DecisionAllow {
			resp := PlaneDecisionV2{
				Decision:   decision,
				ReasonCode: reason,
				Envelope:   req.Envelope,
				TraceID:    traceID,
				DecisionID: decisionID,
				Metadata:   metadata,
			}
			g.writePlaneDecision(w, r, status, resp)
			return
		}
		rlmMetadata = metadata
	}

	if g.toolPolicy == nil {
		g.toolPolicy = newToolPlanePolicyEngine(g.config.CapabilityRegistryV2Path)
	}

	decision, reason, status, metadata := g.toolPolicy.evaluate(req)
	for k, v := range rlmMetadata {
		metadata[k] = v
	}
	resp := PlaneDecisionV2{
		Decision:   decision,
		ReasonCode: reason,
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata:   metadata,
	}
	g.writePlaneDecision(w, r, status, resp)
}

func (g *Gateway) evaluateRLMGovernance(req PlaneRequestV2) (bool, Decision, ReasonCode, int, map[string]any) {
	if g.rlmPolicy == nil {
		g.rlmPolicy = newRLMGovernanceEngine()
	}
	return g.rlmPolicy.evaluate(req)
}

func modelCallerIsAuthenticated(r *http.Request, envelopeSPIFFEID string) bool {
	caller := strings.TrimSpace(middleware.GetSPIFFEID(r.Context()))
	envelope := strings.TrimSpace(envelopeSPIFFEID)
	if caller == "" || envelope == "" {
		return false
	}
	return caller == envelope
}

func getDecisionCorrelationIDs(r *http.Request, envelope RunEnvelope) (string, string) {
	traceID := middleware.GetTraceID(r.Context())
	if strings.TrimSpace(traceID) == "" {
		traceID = envelope.TraceID
	}
	decisionID := middleware.GetDecisionID(r.Context())
	if strings.TrimSpace(decisionID) == "" {
		decisionID = envelope.DecisionID
	}
	return traceID, decisionID
}

func (g *Gateway) writePlaneDecision(w http.ResponseWriter, r *http.Request, status int, resp PlaneDecisionV2) {
	g.logPlaneDecision(r, resp, status)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) logPlaneDecision(r *http.Request, d PlaneDecisionV2, status int) {
	evt := AuditEventV2{
		EventType:  phase3AuditEventTypeDecisionV2,
		Plane:      d.Envelope.Plane,
		ReasonCode: d.ReasonCode,
		Decision:   d.Decision,
		RunID:      d.Envelope.RunID,
		SessionID:  d.Envelope.SessionID,
		DecisionID: d.DecisionID,
		TraceID:    d.TraceID,
	}
	// If the contract is malformed we still emit the underlying audit event
	// with best-effort defaults to preserve forensic evidence.
	if err := evt.Validate(); err != nil {
		evt.EventType = phase3AuditEventTypeDecisionV2
	}
	result := string(d.Decision) + ":" + string(d.ReasonCode)
	if len(d.Metadata) > 0 {
		if b, err := json.Marshal(d.Metadata); err == nil {
			result += " " + string(b)
		}
	}
	severity := "Info"
	if d.ReasonCode == ReasonPromptSafetyOverride {
		severity = "High"
	}
	g.auditor.Log(middleware.AuditEvent{
		EventType:  evt.EventType,
		Severity:   severity,
		SessionID:  d.Envelope.SessionID,
		DecisionID: d.DecisionID,
		TraceID:    d.TraceID,
		SPIFFEID:   d.Envelope.ActorSPIFFEID,
		Action:     "uasgs_plane_" + string(d.Envelope.Plane),
		Result:     result,
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: status,
		Security: &middleware.SecurityAudit{
			SafeZoneFlags: []string{string(d.ReasonCode)},
		},
	})
}

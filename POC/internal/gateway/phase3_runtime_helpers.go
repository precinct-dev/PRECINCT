package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

// handlePhase3PlaneEntry is a placeholder for additional Phase 3 plane entry points
// (ingress/context/loop/tool). These are control-plane endpoints for framework-agnostic
// integration; they allow external governors to enforce limits without requiring
// invasive changes inside an agent framework loop.
func (g *Gateway) handlePhase3PlaneEntry(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/v1/") {
		return false
	}

	switch r.URL.Path {
	case "/v1/ingress/submit":
		g.handleIngressAdmit(w, r)
		return true
	case "/v1/ingress/admit":
		g.handleIngressAdmit(w, r)
		return true
	case "/v1/context/admit":
		g.handleContextAdmit(w, r)
		return true
	case "/v1/model/call":
		g.handleModelCall(w, r)
		return true
	case "/v1/tool/execute":
		g.handleToolExecute(w, r)
		return true
	case "/v1/loop/check":
		g.handleLoopCheck(w, r)
		return true
	default:
		return false
	}
}

func getDecisionCorrelationIDs(r *http.Request, env RunEnvelope) (traceID string, decisionID string) {
	traceID = strings.TrimSpace(env.TraceID)
	if traceID == "" {
		traceID = strings.TrimSpace(middleware.GetTraceID(r.Context()))
	}
	decisionID = strings.TrimSpace(env.DecisionID)
	if decisionID == "" {
		decisionID = strings.TrimSpace(middleware.GetDecisionID(r.Context()))
	}

	// Best-effort fallbacks: deterministic-enough for logs without bringing in UUID deps.
	if traceID == "" {
		traceID = "trace-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	if decisionID == "" {
		decisionID = "decision-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return traceID, decisionID
}

func modelCallerIsAuthenticated(r *http.Request, actorSPIFFEID string) bool {
	ctxID := strings.TrimSpace(middleware.GetSPIFFEID(r.Context()))
	if ctxID == "" {
		return false
	}
	if strings.TrimSpace(actorSPIFFEID) != "" && ctxID != actorSPIFFEID {
		return false
	}
	return true
}

func (g *Gateway) logPlaneDecision(r *http.Request, decision PlaneDecisionV2, httpStatus int) {
	if g == nil || g.auditor == nil {
		return
	}

	plane := string(decision.Envelope.Plane)
	if plane == "" {
		plane = "unknown"
	}

	action := fmt.Sprintf("plane.%s.decision", plane)
	// Embed run_id for grep-based E2E proof collection (scenario_f_phase3_planes.sh).
	result := fmt.Sprintf("run_id=%s decision=%s reason_code=%s", decision.Envelope.RunID, decision.Decision, decision.ReasonCode)

	g.auditor.Log(middleware.AuditEvent{
		SessionID:  defaultString(decision.Envelope.SessionID, middleware.GetSessionID(r.Context())),
		DecisionID: decision.DecisionID,
		TraceID:    decision.TraceID,
		SPIFFEID:   middleware.GetSPIFFEID(r.Context()),
		Action:     action,
		Result:     result,
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: httpStatus,
	})
}

// evaluateRLMGovernance is a minimal governance hook for RLM-style execution. In a
// fully wired Phase 3 implementation, this would:
// - enforce max depth/subcall budgets
// - prevent bypassing plane controls from a framework-spawned REPL
// - attribute nested calls to a lineage_id for audit and cost accounting
func (g *Gateway) evaluateRLMGovernance(req PlaneRequestV2) (bool, Decision, ReasonCode, int, map[string]any) {
	mode := strings.ToLower(strings.TrimSpace(req.Envelope.ExecutionMode))
	if mode != "rlm" {
		return false, DecisionAllow, ReasonRLMAllow, http.StatusOK, nil
	}

	attrs := req.Policy.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}

	depth := getIntAttr(attrs, "rlm_depth", 0)
	maxDepth := getIntAttr(attrs, "rlm_max_depth", 3)
	if depth > maxDepth {
		return true, DecisionDeny, ReasonRLMHaltMaxDepth, http.StatusForbidden, map[string]any{
			"rlm_depth":     depth,
			"rlm_max_depth": maxDepth,
		}
	}

	return true, DecisionAllow, ReasonRLMAllow, http.StatusOK, map[string]any{
		"rlm_depth":     depth,
		"rlm_max_depth": maxDepth,
		"lineage_id":    req.Envelope.LineageID,
	}
}

// evaluatePromptSafety enforces "context engineering" guardrails at the model-plane
// boundary. This is intentionally conservative:
// - Only activates when a compliance profile or prompt action is set.
// - Uses the built-in DLP scanner as a baseline safety classifier.
//
// Returns handled=false when no prompt safety policy was requested.
func evaluatePromptSafety(attrs map[string]any, enforceHIPAAPromptSafety bool) (Decision, ReasonCode, int, map[string]any, bool) {
	if attrs == nil {
		attrs = map[string]any{}
	}

	compliance := strings.ToLower(getStringAttr(attrs, "compliance_profile", ""))
	promptAction := strings.ToLower(getStringAttr(attrs, "prompt_action", ""))
	hasPIIHint := getBoolAttr(attrs, "prompt_has_pii", false)
	hasPHIHint := getBoolAttr(attrs, "prompt_has_phi", false)

	// No explicit policy request: do not change historical behavior.
	if compliance == "" && promptAction == "" && !hasPIIHint && !hasPHIHint {
		return DecisionAllow, "", 0, nil, false
	}

	prompt := getStringAttr(attrs, "prompt", "")
	scan := middleware.NewBuiltInScanner().Scan(prompt)
	meta := map[string]any{
		"prompt_has_pii_hint": hasPIIHint,
		"prompt_has_phi_hint": hasPHIHint,
		"dlp_flags":           scan.Flags,
		"dlp_has_pii":         scan.HasPII,
		"dlp_has_creds":       scan.HasCredentials,
		"dlp_has_suspicious":  scan.HasSuspicious,
	}

	// HIPAA: treat any PII/PHI in prompts as forbidden by default.
	// (Operationally, a real deployment would support tokenization/redaction
	// workflows with explicit approvals.)
	if enforceHIPAAPromptSafety && strings.Contains(compliance, "hipaa") {
		if scan.HasPII || scan.HasCredentials || hasPHIHint || hasPIIHint {
			return DecisionDeny, ReasonPromptSafetyRawDenied, http.StatusForbidden, meta, true
		}
	}

	// Optional strict enforcement: deny if prompt looks like injection/jailbreak content.
	// This is only active when explicitly requested by the caller.
	if promptAction == "enforce" || promptAction == "deny" || promptAction == "deny_unsafe" {
		if scan.HasSuspicious {
			return DecisionDeny, ReasonContextPromptUnsafe, http.StatusForbidden, meta, true
		}
	}

	// Prompt safety was requested; allow but carry metadata.
	return DecisionAllow, ReasonModelAllow, http.StatusOK, meta, true
}

func (g *Gateway) decodePlaneRequest(w http.ResponseWriter, r *http.Request, expectedPlane Plane) (PlaneRequestV2, bool) {
	if r.Method != http.MethodPost {
		writeV24GatewayError(
			w,
			r,
			http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest,
			"method not allowed",
			v24MiddlewarePhase3Plane,
			ReasonContractInvalid,
			map[string]any{
				"expected_method": http.MethodPost,
			},
		)
		return PlaneRequestV2{}, false
	}

	var req PlaneRequestV2
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV24GatewayError(
			w,
			r,
			http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest,
			"invalid json payload",
			v24MiddlewarePhase3Plane,
			ReasonContractInvalid,
			map[string]any{
				"expected_plane": expectedPlane,
			},
		)
		return PlaneRequestV2{}, false
	}

	if err := req.Validate(); err != nil {
		traceID, decisionID := getDecisionCorrelationIDs(r, req.Envelope)
		g.logPlaneDecision(r, PlaneDecisionV2{
			Decision:   DecisionDeny,
			ReasonCode: ReasonContractInvalid,
			Envelope:   req.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata: map[string]any{
				"error": err.Error(),
			},
		}, http.StatusBadRequest)
		writeV24GatewayError(
			w,
			r,
			http.StatusBadRequest,
			middleware.ErrContractValidationFailed,
			"contract validation failed",
			v24MiddlewarePhase3Plane,
			ReasonContractInvalid,
			map[string]any{
				"error": err.Error(),
			},
		)
		return PlaneRequestV2{}, false
	}

	if req.Envelope.Plane != expectedPlane {
		traceID, decisionID := getDecisionCorrelationIDs(r, req.Envelope)
		g.logPlaneDecision(r, PlaneDecisionV2{
			Decision:   DecisionDeny,
			ReasonCode: ReasonContractPlaneMismatch,
			Envelope:   req.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata: map[string]any{
				"expected_plane": expectedPlane,
				"got_plane":      req.Envelope.Plane,
			},
		}, http.StatusBadRequest)
		writeV24GatewayError(
			w,
			r,
			http.StatusBadRequest,
			middleware.ErrContractValidationFailed,
			"plane mismatch",
			v24MiddlewarePhase3Plane,
			ReasonContractPlaneMismatch,
			map[string]any{
				"expected_plane": expectedPlane,
				"got_plane":      req.Envelope.Plane,
			},
		)
		return PlaneRequestV2{}, false
	}

	callerSPIFFEID := strings.TrimSpace(middleware.GetSPIFFEID(r.Context()))
	if callerSPIFFEID != "" && callerSPIFFEID != req.Envelope.ActorSPIFFEID {
		traceID, decisionID := getDecisionCorrelationIDs(r, req.Envelope)
		g.logPlaneDecision(r, PlaneDecisionV2{
			Decision:   DecisionDeny,
			ReasonCode: ReasonContractInvalid,
			Envelope:   req.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata: map[string]any{
				"error":              "actor identity mismatch",
				"caller_spiffe_id":   callerSPIFFEID,
				"envelope_spiffe_id": req.Envelope.ActorSPIFFEID,
			},
		}, http.StatusForbidden)
		writeV24GatewayError(
			w,
			r,
			http.StatusForbidden,
			middleware.ErrAuthzPolicyDenied,
			"caller identity does not match envelope actor_spiffe_id",
			v24MiddlewarePhase3Plane,
			v24ReasonPolicyHookRejected,
			map[string]any{
				"caller_spiffe_id":   callerSPIFFEID,
				"envelope_spiffe_id": req.Envelope.ActorSPIFFEID,
			},
		)
		return PlaneRequestV2{}, false
	}

	return req, true
}

func (g *Gateway) handleIngressAdmit(w http.ResponseWriter, r *http.Request) {
	req, ok := g.decodePlaneRequest(w, r, PlaneIngress)
	if !ok {
		return
	}
	traceID, decisionID := getDecisionCorrelationIDs(r, req.Envelope)
	attrs := req.Policy.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}

	connectorID := getStringAttr(attrs, "connector_id", "")
	if connectorID == "" {
		connectorID = getStringAttr(attrs, "source_id", "")
	}
	connectorSig := getStringAttr(attrs, "connector_signature", "")
	sourcePrincipal := getStringAttr(attrs, "source_principal", "")

	if sourcePrincipal != "" && req.Envelope.ActorSPIFFEID != "" && sourcePrincipal != req.Envelope.ActorSPIFFEID {
		resp := PlaneDecisionV2{
			Decision:   DecisionDeny,
			ReasonCode: ReasonIngressSourceUnauth,
			Envelope:   req.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata: map[string]any{
				"source_principal": sourcePrincipal,
				"actor_spiffe_id":  req.Envelope.ActorSPIFFEID,
				"source_check":     "source_principal_actor_mismatch",
			},
		}
		g.logPlaneDecision(r, resp, http.StatusForbidden)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	if connectorID != "" && g.cca != nil {
		allowed, reason, rec := g.cca.runtimeCheck(connectorID, connectorSig)
		if !allowed {
			resp := PlaneDecisionV2{
				Decision:   DecisionDeny,
				ReasonCode: ReasonIngressSourceUnauth,
				Envelope:   req.Envelope,
				TraceID:    traceID,
				DecisionID: decisionID,
				Metadata: map[string]any{
					"connector_id":    connectorID,
					"connector_check": reason,
					"connector_state": rec.State,
				},
			}
			g.logPlaneDecision(r, resp, http.StatusForbidden)
			g.cca.updateAuditRef(connectorID, decisionID, traceID, reason, "runtime_ingress_check")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if rec.Manifest.SourcePrincipal != "" && req.Envelope.ActorSPIFFEID != rec.Manifest.SourcePrincipal {
			resp := PlaneDecisionV2{
				Decision:   DecisionDeny,
				ReasonCode: ReasonIngressSourceUnauth,
				Envelope:   req.Envelope,
				TraceID:    traceID,
				DecisionID: decisionID,
				Metadata: map[string]any{
					"connector_id":       connectorID,
					"source_principal":   sourcePrincipal,
					"actor_spiffe_id":    req.Envelope.ActorSPIFFEID,
					"manifest_principal": rec.Manifest.SourcePrincipal,
					"source_check":       "actor_manifest_mismatch",
				},
			}
			g.logPlaneDecision(r, resp, http.StatusForbidden)
			g.cca.updateAuditRef(connectorID, decisionID, traceID, "actor_manifest_mismatch", "runtime_ingress_check")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if sourcePrincipal != "" && rec.Manifest.SourcePrincipal != "" && sourcePrincipal != rec.Manifest.SourcePrincipal {
			resp := PlaneDecisionV2{
				Decision:   DecisionDeny,
				ReasonCode: ReasonIngressSourceUnauth,
				Envelope:   req.Envelope,
				TraceID:    traceID,
				DecisionID: decisionID,
				Metadata: map[string]any{
					"connector_id":       connectorID,
					"source_principal":   sourcePrincipal,
					"manifest_principal": rec.Manifest.SourcePrincipal,
					"source_check":       "source_manifest_mismatch",
				},
			}
			g.logPlaneDecision(r, resp, http.StatusForbidden)
			g.cca.updateAuditRef(connectorID, decisionID, traceID, "source_manifest_mismatch", "runtime_ingress_check")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		g.cca.updateAuditRef(connectorID, decisionID, traceID, "connector_active", "runtime_ingress_check")
	}

	eventTimestamp := getStringAttr(attrs, "event_timestamp", "")
	if eventTimestamp != "" {
		parsed, err := time.Parse(time.RFC3339, eventTimestamp)
		if err != nil {
			resp := PlaneDecisionV2{
				Decision:   DecisionDeny,
				ReasonCode: ReasonIngressSchemaInvalid,
				Envelope:   req.Envelope,
				TraceID:    traceID,
				DecisionID: decisionID,
				Metadata: map[string]any{
					"error":           "event_timestamp must be RFC3339",
					"event_timestamp": eventTimestamp,
				},
			}
			g.logPlaneDecision(r, resp, http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		now := time.Now().UTC()
		if g.ingressReplayGuard != nil && !g.ingressReplayGuard.fresh(now, parsed) {
			freshnessWindow := int(g.ingressReplayGuard.window.Seconds())
			maxFuture := int(g.ingressReplayGuard.maxFuture.Seconds())
			resp := PlaneDecisionV2{
				Decision:   DecisionDeny,
				ReasonCode: ReasonIngressFreshnessStale,
				Envelope:   req.Envelope,
				TraceID:    traceID,
				DecisionID: decisionID,
				Metadata: map[string]any{
					"event_timestamp":          eventTimestamp,
					"freshness_window_seconds": freshnessWindow,
					"max_future_seconds":       maxFuture,
				},
			}
			g.logPlaneDecision(r, resp, http.StatusForbidden)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
	}

	replayKey := ingressReplayKey(connectorID, attrs)
	if replayKey != "" && g.ingressReplayGuard != nil && g.ingressReplayGuard.checkAndMark(replayKey, time.Now().UTC()) {
		resp := PlaneDecisionV2{
			Decision:   DecisionDeny,
			ReasonCode: ReasonIngressReplayDetected,
			Envelope:   req.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata: map[string]any{
				"replay_key": replayKey,
			},
		}
		g.logPlaneDecision(r, resp, http.StatusConflict)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	resp := PlaneDecisionV2{
		Decision:   DecisionAllow,
		ReasonCode: ReasonIngressAllow,
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata: map[string]any{
			"action":   req.Policy.Action,
			"resource": req.Policy.Resource,
		},
	}

	g.logPlaneDecision(r, resp, http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) handleContextAdmit(w http.ResponseWriter, r *http.Request) {
	req, ok := g.decodePlaneRequest(w, r, PlaneContext)
	if !ok {
		return
	}
	traceID, decisionID := getDecisionCorrelationIDs(r, req.Envelope)

	attrs := req.Policy.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}

	// Minimal "no scan, no send" posture: context must have passed basic checks.
	if !getBoolAttr(attrs, "scan_passed", false) || !getBoolAttr(attrs, "prompt_check_passed", false) || getBoolAttr(attrs, "prompt_injection_detected", false) {
		resp := PlaneDecisionV2{
			Decision:   DecisionDeny,
			ReasonCode: ReasonContextNoScanNoSend,
			Envelope:   req.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata: map[string]any{
				"scan_passed":               getBoolAttr(attrs, "scan_passed", false),
				"prompt_check_passed":       getBoolAttr(attrs, "prompt_check_passed", false),
				"prompt_injection_detected": getBoolAttr(attrs, "prompt_injection_detected", false),
			},
		}
		g.logPlaneDecision(r, resp, http.StatusForbidden)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	resp := PlaneDecisionV2{
		Decision:   DecisionAllow,
		ReasonCode: ReasonContextAllow,
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata: map[string]any{
			"action":   req.Policy.Action,
			"resource": req.Policy.Resource,
		},
	}

	g.logPlaneDecision(r, resp, http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) handleModelCall(w http.ResponseWriter, r *http.Request) {
	req, ok := g.decodePlaneRequest(w, r, PlaneModel)
	if !ok {
		return
	}

	traceID, decisionID := getDecisionCorrelationIDs(r, req.Envelope)
	decision, reason, status, metadata := g.evaluateModelPlaneDecision(r, req)
	resp := PlaneDecisionV2{
		Decision:   decision,
		ReasonCode: reason,
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata:   metadata,
	}

	g.logPlaneDecision(r, resp, status)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) handleToolExecute(w http.ResponseWriter, r *http.Request) {
	req, ok := g.decodePlaneRequest(w, r, PlaneTool)
	if !ok {
		return
	}
	traceID, decisionID := getDecisionCorrelationIDs(r, req.Envelope)
	attrs := req.Policy.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}

	capabilityID := strings.TrimSpace(getStringAttr(attrs, "capability_id", ""))
	toolName := strings.TrimSpace(getStringAttr(attrs, "tool_name", ""))
	if capabilityID == "" || toolName == "" || !strings.HasPrefix(capabilityID, "tool.default.") {
		resp := PlaneDecisionV2{
			Decision:   DecisionDeny,
			ReasonCode: ReasonToolCapabilityDenied,
			Envelope:   req.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata: map[string]any{
				"capability_id":   capabilityID,
				"tool_name":       toolName,
				"required_prefix": "tool.default.",
			},
		}
		g.logPlaneDecision(r, resp, http.StatusForbidden)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	resp := PlaneDecisionV2{
		Decision:   DecisionAllow,
		ReasonCode: ReasonToolAllow,
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata: map[string]any{
			"action":   req.Policy.Action,
			"resource": req.Policy.Resource,
		},
	}

	g.logPlaneDecision(r, resp, http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) handleLoopCheck(w http.ResponseWriter, r *http.Request) {
	req, ok := g.decodePlaneRequest(w, r, PlaneLoop)
	if !ok {
		return
	}
	traceID, decisionID := getDecisionCorrelationIDs(r, req.Envelope)

	attrs := req.Policy.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}

	limits, _ := attrs["limits"].(map[string]any)
	usage, _ := attrs["usage"].(map[string]any)
	if limits == nil {
		limits = map[string]any{}
	}
	if usage == nil {
		usage = map[string]any{}
	}

	maxSteps := getIntAttr(limits, "max_steps", 0)
	steps := getIntAttr(usage, "steps", 0)
	if maxSteps > 0 && steps > maxSteps {
		resp := PlaneDecisionV2{
			Decision:   DecisionDeny,
			ReasonCode: ReasonLoopHaltMaxSteps,
			Envelope:   req.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata: map[string]any{
				"max_steps": maxSteps,
				"steps":     steps,
			},
		}
		g.logPlaneDecision(r, resp, http.StatusTooManyRequests)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	resp := PlaneDecisionV2{
		Decision:   DecisionAllow,
		ReasonCode: ReasonLoopAllow,
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata: map[string]any{
			"max_steps": maxSteps,
			"steps":     steps,
		},
	}
	g.logPlaneDecision(r, resp, http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

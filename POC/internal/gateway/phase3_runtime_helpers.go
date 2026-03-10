package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
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

// evaluateRLMGovernance delegates to the stateful RLM governance engine which
// tracks multi-agent lineage and enforces subcall budgets per lineage.
func (g *Gateway) evaluateRLMGovernance(req PlaneRequestV2) (bool, Decision, ReasonCode, int, map[string]any) {
	if g.rlmEngine != nil {
		return g.rlmEngine.evaluate(req)
	}
	// Fallback: engine not initialized -- bypass.
	return false, "", "", 0, nil
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

	// HIPAA profile handling for regulated prompt material:
	// - default deny for raw regulated content
	// - explicit quarantine outcomes when callers request tokenization/redaction
	if enforceHIPAAPromptSafety && strings.Contains(compliance, "hipaa") {
		hasRegulatedContent := scan.HasPII || scan.HasCredentials || hasPHIHint || hasPIIHint
		if hasRegulatedContent {
			switch promptAction {
			case "tokenize", "tokenized":
				meta["minimum_necessary_outcome"] = "tokenize"
				meta["prompt_safety_action"] = "tokenize"
				return DecisionQuarantine, ReasonPromptSafetyTokenized, http.StatusForbidden, meta, true
			case "redact", "redacted":
				meta["minimum_necessary_outcome"] = "redact"
				meta["prompt_safety_action"] = "redact"
				return DecisionQuarantine, ReasonPromptSafetyRedacted, http.StatusForbidden, meta, true
			default:
				meta["minimum_necessary_outcome"] = "deny"
				meta["prompt_safety_action"] = "deny_raw"
				return DecisionDeny, ReasonPromptSafetyRawDenied, http.StatusForbidden, meta, true
			}
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

	// OC-j9fj: When attributes contain canonical envelope fields, delegate to the
	// ingress plane policy engine for structured validation, source principal
	// matching, replay detection, and payload content-addressing.
	// Requests without canonical fields fall through to existing handler logic
	// for backward compatibility (AC8).
	if g.ingressPolicy != nil && hasCanonicalEnvelopeFields(attrs) {
		decision, reason, httpStatus, metadata := g.ingressPolicy.evaluate(req, time.Now().UTC())
		resp := PlaneDecisionV2{
			Decision:   decision,
			ReasonCode: reason,
			Envelope:   req.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata:   metadata,
		}
		g.logPlaneDecision(r, resp, httpStatus)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpStatus)
		_ = json.NewEncoder(w).Encode(resp)
		return
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
	decision, reason, status, metadata := evaluateContextInvariants(attrs)
	if decision != DecisionAllow {
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
		return
	}

	resp := PlaneDecisionV2{
		Decision:   DecisionAllow,
		ReasonCode: ReasonContextAllow,
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata: mergeMetadata(map[string]any{
			"action":   req.Policy.Action,
			"resource": req.Policy.Resource,
		}, metadata),
	}

	g.logPlaneDecision(r, resp, http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func evaluateContextInvariants(attrs map[string]any) (Decision, ReasonCode, int, map[string]any) {
	if attrs == nil {
		attrs = map[string]any{}
	}

	scanPassed := getBoolAttr(attrs, "scan_passed", false)
	promptCheckPassed := getBoolAttr(attrs, "prompt_check_passed", false)
	promptInjectionDetected := getBoolAttr(attrs, "prompt_injection_detected", false)
	if !scanPassed || !promptCheckPassed || promptInjectionDetected {
		return DecisionDeny, ReasonContextNoScanNoSend, http.StatusForbidden, map[string]any{
			"invariant":                 "no_scan_no_send",
			"scan_passed":               scanPassed,
			"prompt_check_passed":       promptCheckPassed,
			"prompt_injection_detected": promptInjectionDetected,
		}
	}

	memoryOperation := strings.ToLower(getStringAttr(attrs, "memory_operation", "none"))
	modelEgress := getBoolAttr(attrs, "model_egress", false)
	provenance, _ := attrs["provenance"].(map[string]any)
	hasSource := strings.TrimSpace(getStringAttr(provenance, "source", "")) != ""
	hasChecksum := strings.TrimSpace(getStringAttr(provenance, "checksum", "")) != ""
	provenancePresent := hasSource && hasChecksum
	persistRequested := memoryOperation == "write" || memoryOperation == "persist" || memoryOperation == "upsert"
	if persistRequested && !provenancePresent {
		return DecisionDeny, ReasonContextMemoryWriteDenied, http.StatusForbidden, map[string]any{
			"invariant":        "no_provenance_no_persist",
			"memory_operation": memoryOperation,
			"provenance": map[string]any{
				"source_present":   hasSource,
				"checksum_present": hasChecksum,
			},
		}
	}

	// Memory tier classification: parse and validate memory_tier attribute.
	// Default is "ephemeral" when not provided.
	memoryTier := strings.ToLower(strings.TrimSpace(getStringAttr(attrs, "memory_tier", "ephemeral")))
	switch memoryTier {
	case "ephemeral", "session", "long_term", "regulated":
	default:
		return DecisionDeny, ReasonContextSchemaInvalid, http.StatusBadRequest, map[string]any{
			"invariant":    "memory_tier_validation",
			"memory_tier":  memoryTier,
			"error":        "memory_tier must be one of ephemeral/session/long_term/regulated",
		}
	}

	verificationRequired := modelEgress || persistRequested || memoryOperation == "read"
	if verificationRequired {
		verified := getBoolAttr(provenance, "verified", false)
		verifier := strings.TrimSpace(getStringAttr(provenance, "verifier", ""))
		verificationMethod := strings.TrimSpace(getStringAttr(provenance, "verification_method", ""))
		if !provenancePresent || !verified || verifier == "" || verificationMethod == "" {
			return DecisionDeny, ReasonContextSchemaInvalid, http.StatusForbidden, map[string]any{
				"invariant":              "no_verification_no_load",
				"verification_required":  true,
				"model_egress":           modelEgress,
				"memory_operation":       memoryOperation,
				"memory_tier":            memoryTier,
				"provenance_present":     provenancePresent,
				"verification_verified":  verified,
				"verifier_present":       verifier != "",
				"verification_method_ok": verificationMethod != "",
			}
		}
	}

	// Memory tier enforcement: write to long_term requires clean DLP classification.
	if persistRequested && memoryTier == "long_term" {
		dlpClassification := strings.ToLower(strings.TrimSpace(getStringAttr(attrs, "dlp_classification", "")))
		if dlpClassification != "clean" {
			return DecisionDeny, ReasonContextMemoryWriteDenied, http.StatusForbidden, map[string]any{
				"invariant":          "memory_tier_write_denied",
				"memory_operation":   memoryOperation,
				"memory_tier":        memoryTier,
				"dlp_classification": dlpClassification,
				"error":              "long_term memory writes require dlp_classification=clean",
			}
		}
	}

	// Memory tier enforcement: read from regulated tier requires step-up.
	if memoryOperation == "read" && memoryTier == "regulated" {
		return DecisionStepUp, ReasonContextMemoryReadStepUp, http.StatusAccepted, map[string]any{
			"invariant":        "memory_tier_read_step_up",
			"memory_operation": memoryOperation,
			"memory_tier":      memoryTier,
		}
	}

	if modelEgress {
		classification := strings.ToLower(strings.TrimSpace(getStringAttr(attrs, "dlp_classification", "")))
		if classification == "" {
			return DecisionDeny, ReasonContextDLPRequired, http.StatusForbidden, map[string]any{
				"invariant":    "minimum_necessary",
				"model_egress": true,
				"memory_tier":  memoryTier,
				"error":        "dlp_classification is required for model-bound context",
			}
		}

		outcome := strings.ToLower(strings.TrimSpace(getStringAttr(attrs, "minimum_necessary_outcome", "")))
		tokenized := getBoolAttr(attrs, "tokenized", false) || outcome == "tokenize" || outcome == "tokenized"
		redacted := getBoolAttr(attrs, "redacted", false) || outcome == "redact" || outcome == "redacted"
		minimumNecessaryApplied := getBoolAttr(attrs, "minimum_necessary_applied", false) || tokenized || redacted

		if isSensitiveClassification(classification) {
			if !tokenized && !redacted {
				return DecisionDeny, ReasonContextDLPDenied, http.StatusForbidden, map[string]any{
					"invariant":                  "minimum_necessary",
					"dlp_classification":         classification,
					"memory_tier":                memoryTier,
					"minimum_necessary_applied":  minimumNecessaryApplied,
					"minimum_necessary_outcome":  "deny",
					"required_minimum_necessary": "tokenize_or_redact",
				}
			}
			return DecisionAllow, ReasonContextAllow, http.StatusOK, map[string]any{
				"invariant":                 "minimum_necessary",
				"dlp_classification":        classification,
				"memory_tier":               memoryTier,
				"minimum_necessary_applied": true,
				"minimum_necessary_outcome": minimumNecessaryOutcome(tokenized, redacted),
			}
		}

		content := getStringAttr(attrs, "content", "")
		if !minimumNecessaryApplied && len(content) > 2048 {
			return DecisionDeny, ReasonContextDLPDenied, http.StatusForbidden, map[string]any{
				"invariant":                  "minimum_necessary",
				"dlp_classification":         classification,
				"memory_tier":                memoryTier,
				"minimum_necessary_applied":  minimumNecessaryApplied,
				"minimum_necessary_outcome":  "deny",
				"required_minimum_necessary": "apply_minimization_for_large_context",
				"content_length":             len(content),
			}
		}

		if minimumNecessaryApplied {
			return DecisionAllow, ReasonContextAllow, http.StatusOK, map[string]any{
				"invariant":                 "minimum_necessary",
				"dlp_classification":        classification,
				"memory_tier":               memoryTier,
				"minimum_necessary_applied": true,
				"minimum_necessary_outcome": defaultString(outcome, "minimized"),
			}
		}
	}

	return DecisionAllow, ReasonContextAllow, http.StatusOK, map[string]any{
		"memory_operation": memoryOperation,
		"memory_tier":      memoryTier,
	}
}

func minimumNecessaryOutcome(tokenized, redacted bool) string {
	if tokenized {
		return "tokenize"
	}
	if redacted {
		return "redact"
	}
	return "minimized"
}

func isSensitiveClassification(classification string) bool {
	switch strings.ToLower(strings.TrimSpace(classification)) {
	case "sensitive", "pii", "phi", "regulated":
		return true
	default:
		return false
	}
}

func mergeMetadata(base, extra map[string]any) map[string]any {
	if base == nil && extra == nil {
		return nil
	}
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
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
		req.Policy.Attributes = attrs
	}

	policy := g.toolPolicy
	if policy == nil {
		policy = newToolPlanePolicyEngine("")
	}
	eval := policy.evaluate(req)
	if eval.RequireStepUp {
		token := strings.TrimSpace(getStringAttr(attrs, "approval_capability_token", ""))
		if token == "" {
			token = strings.TrimSpace(getStringAttr(attrs, "step_up_token", ""))
		}
		if token == "" {
			token = strings.TrimSpace(getStringAttr(attrs, "approval_token", ""))
		}

		if token == "" {
			eval.Metadata = mergeMetadata(eval.Metadata, map[string]any{
				"step_up_state": "missing_token",
			})
		} else if g.approvalCapabilities == nil {
			eval.Metadata = mergeMetadata(eval.Metadata, map[string]any{
				"step_up_state": "approval_service_unavailable",
			})
		} else {
			_, err := g.approvalCapabilities.ValidateAndConsume(token, middleware.ApprovalScope{
				Action:        strings.TrimSpace(req.Policy.Action),
				Resource:      strings.TrimSpace(req.Policy.Resource),
				ActorSPIFFEID: req.Envelope.ActorSPIFFEID,
				SessionID:     req.Envelope.SessionID,
			})
			if err == nil {
				eval.RequireStepUp = false
				eval.Decision = DecisionAllow
				eval.Reason = ReasonToolAllow
				eval.HTTPStatus = statusForToolReason(ReasonToolAllow)
				eval.Metadata = mergeMetadata(eval.Metadata, map[string]any{
					"step_up_state": "approved_token_consumed",
				})
			} else {
				eval.Metadata = mergeMetadata(eval.Metadata, map[string]any{
					"step_up_state": "invalid_or_expired_token",
				})
			}
		}
	}

	resp := PlaneDecisionV2{
		Decision:   eval.Decision,
		ReasonCode: eval.Reason,
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata:   eval.Metadata,
	}

	g.logPlaneDecision(r, resp, eval.HTTPStatus)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(eval.HTTPStatus)
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) handleLoopCheck(w http.ResponseWriter, r *http.Request) {
	req, ok := g.decodePlaneRequest(w, r, PlaneLoop)
	if !ok {
		return
	}
	traceID, decisionID := getDecisionCorrelationIDs(r, req.Envelope)

	policy := g.loopPolicy
	if policy == nil {
		policy = newLoopPlanePolicyEngine()
	}
	decision, reason, httpStatus, metadata := policy.evaluate(req, decisionID, traceID, time.Now().UTC())
	resp := PlaneDecisionV2{
		Decision:   decision,
		ReasonCode: reason,
		Envelope:   req.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata:   metadata,
	}
	g.logPlaneDecision(r, resp, httpStatus)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(resp)
}

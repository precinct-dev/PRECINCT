package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
)

const (
	openAICompatChatCompletionsPath = "/openai/v1/chat/completions"
)

type modelProviderResponse struct {
	statusCode int
	body       []byte
	headers    http.Header
}

type modelEgressResult struct {
	providerUsed      string
	reason            ReasonCode
	statusCode        int
	responseBody      []byte
	responseHeaders   http.Header
	upstreamStatus    int
	fallbackAttempted bool
}

func isOpenAICompatPath(path string) bool {
	return path == openAICompatChatCompletionsPath
}

func (g *Gateway) handleModelCompatEntry(w http.ResponseWriter, r *http.Request) bool {
	if !isOpenAICompatPath(r.URL.Path) {
		return false
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}

	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		middleware.WriteGatewayError(w, r, http.StatusBadRequest, middleware.GatewayError{
			Code:           middleware.ErrContractValidationFailed,
			Message:        "Invalid OpenAI-compatible JSON payload",
			ReasonCode:     string(ReasonContractInvalid),
			Middleware:     "model_plane",
			MiddlewareStep: 14,
		})
		return true
	}

	model := strings.TrimSpace(stringValue(payload["model"]))
	if model == "" {
		middleware.WriteGatewayError(w, r, http.StatusBadRequest, middleware.GatewayError{
			Code:           middleware.ErrContractValidationFailed,
			Message:        "OpenAI payload must include model",
			ReasonCode:     string(ReasonContractInvalid),
			Middleware:     "model_plane",
			MiddlewareStep: 14,
		})
		return true
	}

	planeReq := g.buildModelPlaneRequestFromOpenAI(r, payload)
	traceID, decisionID := getDecisionCorrelationIDs(r, planeReq.Envelope)
	decision, reason, status, metadata := g.evaluateModelPlaneDecision(r, planeReq)
	projectionEnabled := g.shouldApplyPolicyIntentProjection()
	projectionApplied := false
	projectionFormat := ""

	if decision != DecisionAllow {
		metadata["policy_intent_projection_enabled"] = projectionEnabled
		metadata["policy_intent_projection_applied"] = false
		metadata["policy_intent_projection_format"] = ""
		resp := PlaneDecisionV2{
			Decision:   decision,
			ReasonCode: reason,
			Envelope:   planeReq.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata:   metadata,
		}
		g.logPlaneDecision(r, resp, status)
		middleware.WriteGatewayError(w, r, status, middleware.GatewayError{
			Code:           "model_plane_denied",
			Message:        fmt.Sprintf("Model plane denied request: %s", reason),
			ReasonCode:     string(reason),
			Middleware:     "model_plane",
			MiddlewareStep: 14,
			Details:        metadata,
			Remediation:    "Use an approved provider/model/residency profile or reduce budget usage.",
		})
		return true
	}

	if projectionEnabled {
		projection := buildModelPolicyIntentProjection(planeReq.Policy.Attributes, planeReq.Envelope)
		if projection != "" {
			projectionApplied = prependSystemPolicyIntentMessage(payload, projection)
			if projectionApplied {
				projectionFormat = "xml.v1"
			}
		}
	}

	egress, err := g.executeModelEgress(r.Context(), planeReq.Policy.Attributes, payload, r.Header.Get("Authorization"))
	if err != nil {
		denyReason := ReasonModelProviderUnavailable
		if strings.Contains(strings.ToLower(err.Error()), "allowlist") || strings.Contains(strings.ToLower(err.Error()), "drift") {
			denyReason = ReasonModelDestinationDenied
		}
		denyMetadata := map[string]any{
			"error":                            err.Error(),
			"provider":                         strings.ToLower(getStringAttr(planeReq.Policy.Attributes, "provider", "openai")),
			"policy_intent_projection_enabled": projectionEnabled,
			"policy_intent_projection_applied": projectionApplied,
			"policy_intent_projection_format":  projectionFormat,
		}
		resp := PlaneDecisionV2{
			Decision:   DecisionDeny,
			ReasonCode: denyReason,
			Envelope:   planeReq.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata:   denyMetadata,
		}
		g.logPlaneDecision(r, resp, http.StatusBadGateway)
		middleware.WriteGatewayError(w, r, http.StatusBadGateway, middleware.GatewayError{
			Code:           "model_provider_unavailable",
			Message:        "Model provider egress failed",
			ReasonCode:     string(denyReason),
			Middleware:     "model_plane",
			MiddlewareStep: 14,
			Details:        denyMetadata,
			Remediation:    "Verify provider availability, destination allowlist, and fallback configuration.",
		})
		return true
	}

	finalDecision := DecisionAllow
	finalReason := egress.reason
	finalStatus := egress.statusCode
	if finalReason == "" {
		finalReason = reason
	}
	if finalStatus >= 400 {
		finalDecision = DecisionDeny
		if finalReason == ReasonModelAllow || finalReason == "" {
			finalReason = ReasonModelProviderUpstreamError
		}
	}

	resp := PlaneDecisionV2{
		Decision:   finalDecision,
		ReasonCode: finalReason,
		Envelope:   planeReq.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata: map[string]any{
			"provider_used":                    egress.providerUsed,
			"upstream_status":                  egress.upstreamStatus,
			"fallback_attempted":               egress.fallbackAttempted,
			"policy_reason_code":               reason,
			"policy_decision":                  decision,
			"policy_http_status":               status,
			"openai_compat_route":              openAICompatChatCompletionsPath,
			"policy_intent_projection_enabled": projectionEnabled,
			"policy_intent_projection_applied": projectionApplied,
			"policy_intent_projection_format":  projectionFormat,
		},
	}
	g.logPlaneDecision(r, resp, finalStatus)

	writeProviderResponse(w, egress, decisionID, traceID, finalReason, projectionEnabled, projectionApplied)
	return true
}

func (g *Gateway) buildModelPlaneRequestFromOpenAI(r *http.Request, payload map[string]any) PlaneRequestV2 {
	provider := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Model-Provider")))
	if provider == "" {
		provider = "groq"
	}

	model := strings.TrimSpace(stringValue(payload["model"]))
	if model == "" {
		model = "llama-3.3-70b-versatile"
	}

	sessionID := middleware.GetSessionID(r.Context())
	if strings.TrimSpace(sessionID) == "" {
		sessionID = "model-session-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}

	envelope := RunEnvelope{
		RunID:         "model-run-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		SessionID:     sessionID,
		Tenant:        defaultString(strings.TrimSpace(r.Header.Get("X-Tenant")), "default"),
		ActorSPIFFEID: middleware.GetSPIFFEID(r.Context()),
		Plane:         PlaneModel,
	}

	trustedRiskMode := g.trustedModelRiskMode(r.Context())
	trustedComplianceProfile := g.trustedComplianceProfile(r.Context())
	trustedStepUpApproved := trustedModelStepUpApproved(r.Context())
	approvalMarker := ""
	if trustedStepUpApproved {
		approvalMarker = strings.TrimSpace(r.Header.Get("X-Approval-Marker"))
	}

	attrs := map[string]any{
		"provider":           provider,
		"model":              model,
		"residency_intent":   defaultString(strings.TrimSpace(r.Header.Get("X-Residency-Intent")), "us"),
		"risk_mode":          trustedRiskMode,
		"budget_profile":     defaultString(strings.TrimSpace(r.Header.Get("X-Budget-Profile")), "standard"),
		"budget_units":       parseHeaderInt(r.Header.Get("X-Budget-Units"), 1),
		"mediation_mode":     "mediated",
		"direct_egress":      false,
		"compliance_profile": trustedComplianceProfile,
		"model_scope":        defaultString(strings.ToLower(strings.TrimSpace(r.Header.Get("X-Model-Scope"))), "external"),
		"prompt_action":      strings.ToLower(strings.TrimSpace(r.Header.Get("X-Prompt-Action"))),
		"approval_marker":    approvalMarker,
		"step_up_approved":   trustedStepUpApproved,
	}
	attrs["prompt"] = extractOpenAIPrompt(payload)

	if endpoint := strings.TrimSpace(r.Header.Get("X-Provider-Endpoint")); endpoint != "" {
		attrs["provider_endpoint"] = endpoint
	}
	if endpoint := strings.TrimSpace(r.Header.Get("X-Provider-Endpoint-Groq")); endpoint != "" {
		attrs["provider_endpoint_groq"] = endpoint
	}
	if endpoint := strings.TrimSpace(r.Header.Get("X-Provider-Endpoint-OpenAI")); endpoint != "" {
		attrs["provider_endpoint_openai"] = endpoint
	}
	if endpoint := strings.TrimSpace(r.Header.Get("X-Provider-Endpoint-Azure-OpenAI")); endpoint != "" {
		attrs["provider_endpoint_azure_openai"] = endpoint
	}
	if hasPHI := parseHeaderBool(r.Header.Get("X-Prompt-Has-PHI"), false); hasPHI {
		attrs["prompt_has_phi"] = true
	}
	if hasPII := parseHeaderBool(r.Header.Get("X-Prompt-Has-PII"), false); hasPII {
		attrs["prompt_has_pii"] = true
	}

	return PlaneRequestV2{
		Envelope: envelope,
		Policy: PolicyInputV2{
			Envelope:   envelope,
			Action:     "model.call",
			Resource:   "model/inference",
			Attributes: attrs,
		},
	}
}

func (g *Gateway) evaluateModelPlaneDecision(r *http.Request, req PlaneRequestV2) (Decision, ReasonCode, int, map[string]any) {
	if !modelCallerIsAuthenticated(r, req.Envelope.ActorSPIFFEID) {
		return DecisionDeny, ReasonModelCallerUnauth, http.StatusUnauthorized, map[string]any{
			"context_spiffe_id":  middleware.GetSPIFFEID(r.Context()),
			"envelope_spiffe_id": req.Envelope.ActorSPIFFEID,
		}
	}

	rlmMetadata := map[string]any{}
	if handled, decision, reason, status, metadata := g.evaluateRLMGovernance(req); handled {
		if decision != DecisionAllow {
			return decision, reason, status, metadata
		}
		rlmMetadata = metadata
	}

	// Break-glass override: for bounded emergency incidents, allow scoped
	// high-risk model mode within strict TTL and explicit incident context.
	if req.Policy.Attributes == nil {
		req.Policy.Attributes = map[string]any{}
	}
	g.applyEnforcementProfileDefaults(req.Policy.Attributes)

	modelPolicy := g.ensureModelPlanePolicy()
	modelName := getStringAttr(req.Policy.Attributes, "model", "")
	scope := breakGlassScope{
		Action:        "model.call",
		Resource:      modelName,
		ActorSPIFFEID: req.Envelope.ActorSPIFFEID,
	}
	breakGlassRecord, breakGlassActive := breakGlassRecord{}, false
	if g.breakGlass != nil {
		breakGlassRecord, breakGlassActive = g.breakGlass.activeOverride(scope)
		if breakGlassActive {
			req.Policy.Attributes["step_up_approved"] = true
			req.Policy.Attributes["break_glass_incident_id"] = breakGlassRecord.IncidentID
			req.Policy.Attributes["break_glass_active"] = true
		}
	}

	decision, reason, status, metadata := modelPolicy.evaluate(req)
	if breakGlassActive {
		metadata["break_glass_incident_id"] = breakGlassRecord.IncidentID
		metadata["break_glass_request_id"] = breakGlassRecord.RequestID
		metadata["break_glass_elevated_audit"] = true
	}
	for k, v := range rlmMetadata {
		metadata[k] = v
	}
	return decision, reason, status, metadata
}

func (g *Gateway) executeModelEgress(ctx context.Context, attrs map[string]any, payload map[string]any, authHeader string) (*modelEgressResult, error) {
	provider := strings.ToLower(getStringAttr(attrs, "provider", "openai"))
	residency := strings.ToLower(getStringAttr(attrs, "residency_intent", "us"))
	riskMode := strings.ToLower(getStringAttr(attrs, "risk_mode", "low"))

	primaryTarget, err := g.resolveProviderTarget(provider, attrs)
	if err != nil {
		return nil, err
	}

	primaryResp, primaryErr := g.invokeProvider(ctx, primaryTarget, payload, authHeader)
	if primaryErr == nil && primaryResp.statusCode < 500 {
		return &modelEgressResult{
			providerUsed:      provider,
			reason:            ReasonModelAllow,
			statusCode:        primaryResp.statusCode,
			responseBody:      primaryResp.body,
			responseHeaders:   primaryResp.headers,
			upstreamStatus:    primaryResp.statusCode,
			fallbackAttempted: false,
		}, nil
	}

	fallbackProvider, ok := g.ensureModelPlanePolicy().selectFallback(provider, getStringAttr(attrs, "model", ""), residency, riskMode)
	if !ok {
		if primaryErr != nil {
			return nil, fmt.Errorf("provider=%s unavailable: %w", provider, primaryErr)
		}
		return &modelEgressResult{
			providerUsed:      provider,
			reason:            ReasonModelNoFallback,
			statusCode:        primaryResp.statusCode,
			responseBody:      primaryResp.body,
			responseHeaders:   primaryResp.headers,
			upstreamStatus:    primaryResp.statusCode,
			fallbackAttempted: true,
		}, nil
	}

	fallbackTarget, err := g.resolveProviderTarget(fallbackProvider, attrs)
	if err != nil {
		return nil, err
	}
	fallbackResp, fallbackErr := g.invokeProvider(ctx, fallbackTarget, payload, authHeader)
	if fallbackErr != nil {
		return nil, fmt.Errorf("primary=%s and fallback=%s unavailable: %w", provider, fallbackProvider, fallbackErr)
	}

	return &modelEgressResult{
		providerUsed:      fallbackProvider,
		reason:            ReasonModelFallbackApplied,
		statusCode:        fallbackResp.statusCode,
		responseBody:      fallbackResp.body,
		responseHeaders:   fallbackResp.headers,
		upstreamStatus:    fallbackResp.statusCode,
		fallbackAttempted: true,
	}, nil
}

func (g *Gateway) ensureModelPlanePolicy() *modelPlanePolicyEngine {
	if g == nil {
		return newModelPlanePolicyEngine()
	}
	if g.modelPlanePolicy != nil {
		return g.modelPlanePolicy
	}
	enforceMediation := true
	enforceHIPAA := true
	if g.enforcementProfile != nil {
		enforceMediation = g.enforcementProfile.Controls.EnforceModelMediationGate
		enforceHIPAA = g.enforcementProfile.Controls.EnforceHIPAAPromptSafety
	} else if g.config != nil {
		enforceMediation = g.config.EnforceModelMediationGate
		enforceHIPAA = g.config.EnforceHIPAAPromptSafetyGate
	}
	g.modelPlanePolicy = newModelPlanePolicyEngineWithControls(enforceMediation, enforceHIPAA)
	return g.modelPlanePolicy
}

func (g *Gateway) applyEnforcementProfileDefaults(attrs map[string]any) {
	if attrs == nil {
		return
	}
	profile := g.profileSnapshot()
	if strings.TrimSpace(profile.Name) == "" {
		return
	}
	attrs["enforcement_profile"] = profile.Name

	if profile.Controls.EnforceModelMediationGate {
		if strings.TrimSpace(getStringAttr(attrs, "mediation_mode", "")) == "" {
			attrs["mediation_mode"] = "mediated"
		}
		if _, ok := attrs["direct_egress"]; !ok {
			attrs["direct_egress"] = false
		}
	}
	if profile.Name == enforcementProfileProdRegulatedHIPAA {
		if strings.TrimSpace(getStringAttr(attrs, "compliance_profile", "")) == "" {
			attrs["compliance_profile"] = "hipaa"
		}
		if strings.TrimSpace(getStringAttr(attrs, "prompt_action", "")) == "" {
			attrs["prompt_action"] = "deny"
		}
	}
}

func (g *Gateway) shouldApplyPolicyIntentProjection() bool {
	if g == nil {
		return false
	}
	if g.config != nil && g.config.ModelPolicyIntentPrependEnabled {
		return true
	}
	return g.enforcementProfile != nil && g.enforcementProfile.StartupGateMode == "strict"
}

func (g *Gateway) resolveProviderTarget(provider string, attrs map[string]any) (*url.URL, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	expectedEndpoint, hasExpectedEndpoint := g.ensureModelPlanePolicy().expectedProviderEndpoint(provider)
	endpointSource := "default"

	// Provider-specific override takes precedence for fallback routing tests
	// and explicit operator policy controls.
	overrideKey := "provider_endpoint_" + provider
	endpoint := strings.TrimSpace(getStringAttr(attrs, overrideKey, ""))
	if endpoint != "" {
		endpointSource = "provider_override"
	}
	if endpoint == "" {
		endpoint = strings.TrimSpace(getStringAttr(attrs, "provider_endpoint", ""))
		if endpoint != "" {
			endpointSource = "global_override"
		}
	}
	// Compose/K8s demo determinism: allow an operator-set endpoint override via env var.
	// This keeps demo flows self-contained (no external network or real API keys).
	//
	// Examples:
	// - MODEL_PROVIDER_ENDPOINT_GROQ=http://host.docker.internal:8083/openai/v1/chat/completions
	// - MODEL_PROVIDER_ENDPOINT_OPENAI=...
	if endpoint == "" {
		envKey := "MODEL_PROVIDER_ENDPOINT_" + strings.ToUpper(provider)
		endpoint = strings.TrimSpace(os.Getenv(envKey))
		if endpoint != "" {
			endpointSource = "env_override"
		}
	}

	if endpoint == "" {
		if hasExpectedEndpoint {
			endpoint = strings.TrimSpace(expectedEndpoint)
			if endpoint != "" {
				endpointSource = "catalog"
			}
		} else {
			switch provider {
			case "groq":
				endpoint = "https://api.groq.com/openai/v1/chat/completions"
				endpointSource = "builtin"
			case "openai":
				endpoint = "https://api.openai.com/v1/chat/completions"
				endpointSource = "builtin"
			case "azure_openai":
				endpoint = strings.TrimSpace(getStringAttr(attrs, "azure_openai_endpoint", ""))
				if endpoint != "" {
					endpointSource = "legacy_azure_override"
				}
			default:
				return nil, fmt.Errorf("unsupported provider endpoint mapping: %s", provider)
			}
		}
	}
	if endpoint == "" {
		return nil, fmt.Errorf("provider endpoint is empty for %s", provider)
	}
	if hasExpectedEndpoint {
		expected := strings.TrimSpace(expectedEndpoint)
		if expected != "" && endpoint != expected {
			if !g.isLocalDevEndpointOverrideAllowed(endpointSource, endpoint) {
				return nil, fmt.Errorf("provider endpoint drift detected for %s: configured=%s expected=%s", provider, endpoint, expected)
			}
		}
	}

	target, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid provider endpoint: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(target.Hostname()))
	if host == "" {
		return nil, fmt.Errorf("provider endpoint host is empty")
	}
	// Production posture: require HTTPS. Dev/POC exception: allow HTTP only to
	// localhost/host.docker.internal or single-label internal service names
	// (e.g., docker-compose service DNS) to keep demos deterministic without
	// publishing tool-plane ports to the host.
	if target.Scheme != "https" && !isLocalHost(host) && !isSingleLabelHostname(host) {
		return nil, fmt.Errorf("provider endpoint must use https outside local development")
	}

	allowlist := g.destinationAllowlist
	if allowlist == nil {
		allowlist = middleware.DefaultDestinationAllowlist()
	}
	if !allowlist.IsAllowed(host) {
		return nil, fmt.Errorf("provider destination %s is not on allowlist", host)
	}

	return target, nil
}

func (g *Gateway) isLocalDevEndpointOverrideAllowed(source string, endpoint string) bool {
	switch source {
	case "provider_override", "global_override", "env_override", "legacy_azure_override":
	default:
		return false
	}
	if g == nil || g.config == nil {
		return false
	}
	if strings.ToLower(strings.TrimSpace(g.config.SPIFFEMode)) != "dev" {
		return false
	}
	target, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(target.Hostname()))
	return isLocalHost(host) || isSingleLabelHostname(host)
}

func (g *Gateway) invokeProvider(ctx context.Context, target *url.URL, payload map[string]any, authHeader string) (*modelProviderResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(authHeader) != "" {
		req.Header.Set("Authorization", authHeader)
	}

	client := &http.Client{
		Timeout: 45 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read provider response: %w", err)
	}

	return &modelProviderResponse{
		statusCode: resp.StatusCode,
		body:       respBody,
		headers:    resp.Header.Clone(),
	}, nil
}

func writeProviderResponse(w http.ResponseWriter, result *modelEgressResult, decisionID, traceID string, reason ReasonCode, projectionEnabled, projectionApplied bool) {
	copyHeaderIfPresent(w.Header(), result.responseHeaders, "Content-Type")
	copyHeaderIfPresent(w.Header(), result.responseHeaders, "OpenAI-Processing-Ms")
	copyHeaderIfPresent(w.Header(), result.responseHeaders, "X-Request-Id")
	w.Header().Set("X-Precinct-Decision-ID", decisionID)
	w.Header().Set("X-Precinct-Trace-ID", traceID)
	w.Header().Set("X-Precinct-Reason-Code", string(reason))
	w.Header().Set("X-Precinct-Provider-Used", result.providerUsed)
	w.Header().Set("X-Precinct-Policy-Intent-Projection", projectionHeaderValue(projectionEnabled, projectionApplied))
	w.WriteHeader(result.statusCode)
	_, _ = w.Write(result.responseBody)
}

func copyHeaderIfPresent(dst http.Header, src http.Header, key string) {
	if src == nil {
		return
	}
	if v := src.Get(key); strings.TrimSpace(v) != "" {
		dst.Set(key, v)
	}
}

func projectionHeaderValue(enabled, applied bool) string {
	if !enabled {
		return "disabled"
	}
	if applied {
		return "applied"
	}
	return "enabled_not_applied"
}

func buildModelPolicyIntentProjection(attrs map[string]any, envelope RunEnvelope) string {
	if attrs == nil {
		attrs = map[string]any{}
	}
	provider := sanitizeProjectionToken(getStringAttr(attrs, "provider", "unknown"))
	model := sanitizeProjectionToken(getStringAttr(attrs, "model", "unspecified"))
	residency := sanitizeProjectionToken(getStringAttr(attrs, "residency_intent", "unspecified"))
	riskMode := sanitizeProjectionToken(getStringAttr(attrs, "risk_mode", "unspecified"))
	compliance := sanitizeProjectionToken(getStringAttr(attrs, "compliance_profile", "standard"))
	mediation := sanitizeProjectionToken(getStringAttr(attrs, "mediation_mode", "mediated"))
	actor := sanitizeProjectionToken(envelope.ActorSPIFFEID)
	if actor == "" {
		actor = "unknown"
	}

	prohibited := []string{
		"direct_egress",
		"policy_bypass",
		"credential_exfiltration",
		"unapproved_destination",
	}
	if parseBoolAttr(attrs, "prompt_has_phi") || strings.Contains(compliance, "hipaa") {
		prohibited = append(prohibited, "phi_disclosure")
	}
	if parseBoolAttr(attrs, "prompt_has_pii") {
		prohibited = append(prohibited, "pii_disclosure")
	}

	escalation := "request_step_up_approval_when_action_is_high_risk_or_uncertain"
	if parseBoolAttr(attrs, "step_up_approved") {
		escalation = "step_up_approval_present_keep_actions_within_approved_scope"
	}

	var prohibitedItems strings.Builder
	for _, item := range prohibited {
		prohibitedItems.WriteString("<item>")
		prohibitedItems.WriteString(xmlEscape(item))
		prohibitedItems.WriteString("</item>")
	}

	return "<policy_intent version=\"1\"><actor>" + xmlEscape(actor) + "</actor>" +
		"<model provider=\"" + xmlEscape(provider) +
		"\" name=\"" + xmlEscape(model) +
		"\" residency=\"" + xmlEscape(residency) +
		"\" risk=\"" + xmlEscape(riskMode) +
		"\" compliance=\"" + xmlEscape(compliance) +
		"\" mediation=\"" + xmlEscape(mediation) + "\"/>" +
		"<allowed><item>mediated_model_call</item></allowed>" +
		"<prohibited>" + prohibitedItems.String() + "</prohibited>" +
		"<escalation>" + xmlEscape(escalation) + "</escalation>" +
		"<authority>advisory_only_runtime_policy_enforcement_remains_authoritative</authority>" +
		"</policy_intent>"
}

func prependSystemPolicyIntentMessage(payload map[string]any, projection string) bool {
	if payload == nil || strings.TrimSpace(projection) == "" {
		return false
	}
	systemMsg := map[string]any{
		"role":    "system",
		"name":    "precinct_policy_intent",
		"content": projection,
	}
	rawMessages, ok := payload["messages"]
	if !ok {
		payload["messages"] = []any{systemMsg}
		return true
	}
	msgs, ok := rawMessages.([]any)
	if !ok {
		payload["messages"] = []any{systemMsg}
		return true
	}
	payload["messages"] = append([]any{systemMsg}, msgs...)
	return true
}

func sanitizeProjectionToken(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	if len(raw) > 120 {
		raw = raw[:120]
	}
	var b strings.Builder
	for _, ch := range raw {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch == '-' || ch == '_' || ch == '.' || ch == ':' || ch == '/':
			b.WriteRune(ch)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func parseBoolAttr(attrs map[string]any, key string) bool {
	v, ok := attrs[key]
	if !ok {
		return false
	}
	switch vv := v.(type) {
	case bool:
		return vv
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(vv))
		return err == nil && b
	default:
		return false
	}
}

func xmlEscape(raw string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(raw)
}

func extractOpenAIPrompt(payload map[string]any) string {
	rawMessages, ok := payload["messages"]
	if !ok {
		return ""
	}
	list, ok := rawMessages.([]any)
	if !ok {
		return ""
	}
	parts := make([]string, 0, len(list))
	for _, item := range list {
		msg, ok := item.(map[string]any)
		if !ok {
			continue
		}
		content := strings.TrimSpace(stringValue(msg["content"]))
		if content != "" {
			parts = append(parts, content)
		}
	}
	return strings.Join(parts, "\n")
}

func parseHeaderInt(raw string, fallback int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func parseHeaderBool(raw string, fallback bool) bool {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}

func trustedModelStepUpApproved(ctx context.Context) bool {
	result := middleware.GetStepUpResult(ctx)
	if result == nil {
		return false
	}
	return result.Allowed && result.Gate == "approval"
}

func (g *Gateway) trustedModelRiskMode(ctx context.Context) string {
	// Fail-safe default when trusted context is missing or indicates elevated risk.
	if middleware.IsStrictRuntimeProfile(ctx) {
		return "high"
	}
	session := middleware.GetSessionContextData(ctx)
	if session == nil || len(session.DataClassifications) == 0 {
		return "high"
	}
	for _, class := range session.DataClassifications {
		switch strings.ToLower(strings.TrimSpace(class)) {
		case "phi", "pii", "sensitive", "regulated", "confidential":
			return "high"
		}
	}
	if session.RiskScore >= 0.5 {
		return "high"
	}
	return "low"
}

func (g *Gateway) trustedComplianceProfile(ctx context.Context) string {
	session := middleware.GetSessionContextData(ctx)
	if session != nil {
		for _, class := range session.DataClassifications {
			switch strings.ToLower(strings.TrimSpace(class)) {
			case "phi", "pii", "sensitive", "regulated", "confidential":
				return "hipaa"
			}
		}
	}
	if g != nil {
		profile := strings.ToLower(strings.TrimSpace(g.profileSnapshot().Name))
		if profile == enforcementProfileProdRegulatedHIPAA {
			return "hipaa"
		}
	}
	return "standard"
}

func stringValue(v any) string {
	switch vv := v.(type) {
	case string:
		return vv
	default:
		return ""
	}
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func isLocalHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1", "host.docker.internal":
		return true
	default:
		return false
	}
}

func isSingleLabelHostname(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	// Single-label hostnames are typical in docker-compose (service DNS names)
	// and are treated as local-dev-only for non-TLS provider endpoints.
	return !strings.Contains(host, ".")
}

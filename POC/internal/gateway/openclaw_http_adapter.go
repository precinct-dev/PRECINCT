package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
	adapter "github.com/example/agentic-security-poc/internal/integrations/openclaw"
)

type openClawFunctionCall struct {
	CallID    string
	Name      string
	Arguments string
}

func (g *Gateway) handleAppHTTPEntry(w http.ResponseWriter, r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}

	switch r.URL.Path {
	case adapter.ResponsesPath:
		g.handleOpenClawResponses(w, r)
		return true
	case adapter.ToolsInvokePath:
		g.handleOpenClawToolsInvoke(w, r)
		return true
	default:
		return false
	}
}

func (g *Gateway) handleOpenClawResponses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeV24GatewayError(
			w,
			r,
			http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest,
			"method not allowed",
			v24MiddlewareAppWrapperHTTP,
			ReasonContractInvalid,
			map[string]any{
				"route":           adapter.ResponsesPath,
				"expected_method": http.MethodPost,
			},
		)
		return
	}

	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		writeV24GatewayError(
			w,
			r,
			http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest,
			"unable to read request body",
			v24MiddlewareAppWrapperHTTP,
			ReasonContractInvalid,
			map[string]any{
				"route": adapter.ResponsesPath,
			},
		)
		return
	}

	req, err := adapter.ParseResponsesRequest(rawBody)
	if err != nil {
		writeV24GatewayError(
			w,
			r,
			http.StatusBadRequest,
			middleware.ErrContractValidationFailed,
			"invalid OpenClaw responses request",
			v24MiddlewareAppWrapperHTTP,
			ReasonContractInvalid,
			map[string]any{
				"route": adapter.ResponsesPath,
				"error": err.Error(),
			},
		)
		return
	}

	if req.Stream {
		writeV24GatewayError(
			w,
			r,
			http.StatusBadRequest,
			middleware.ErrContractValidationFailed,
			"stream=true is not supported on secure wrapper path; use stream=false",
			v24MiddlewareAppWrapperHTTP,
			ReasonContractInvalid,
			map[string]any{
				"route": adapter.ResponsesPath,
			},
		)
		return
	}

	openAIPayload := map[string]any{
		"model":    req.Model,
		"messages": adapter.BuildOpenAIMessages(req),
	}
	if req.MaxOutputTokens > 0 {
		openAIPayload["max_tokens"] = req.MaxOutputTokens
	}

	planeReq := g.buildModelPlaneRequestFromOpenAI(r, openAIPayload)
	traceID, decisionID := getDecisionCorrelationIDs(r, planeReq.Envelope)
	decision, reason, status, metadata := g.evaluateModelPlaneDecision(r, planeReq)
	projectionEnabled := g.shouldApplyPolicyIntentProjection()
	projectionApplied := false
	projectionFormat := ""

	if decision != DecisionAllow {
		metadata = mergeMetadata(metadata, map[string]any{
			"openclaw_route":                   adapter.ResponsesPath,
			"policy_intent_projection_enabled": projectionEnabled,
			"policy_intent_projection_applied": false,
			"policy_intent_projection_format":  "",
		})
		resp := PlaneDecisionV2{
			Decision:   decision,
			ReasonCode: reason,
			Envelope:   planeReq.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata:   metadata,
		}
		g.logPlaneDecision(r, resp, status)
		writeOpenClawResponseError(w, status, req.Model, decisionID, traceID, reason, "request denied by model policy")
		return
	}

	if projectionEnabled {
		projection := buildModelPolicyIntentProjection(planeReq.Policy.Attributes, planeReq.Envelope)
		if projection != "" {
			projectionApplied = prependSystemPolicyIntentMessage(openAIPayload, projection)
			if projectionApplied {
				projectionFormat = "xml.v1"
			}
		}
	}

	egress, err := g.executeModelEgress(r.Context(), planeReq.Policy.Attributes, openAIPayload, r.Header.Get("Authorization"))
	if err != nil {
		denyReason := ReasonModelProviderUnavailable
		lowerErr := strings.ToLower(err.Error())
		if strings.Contains(lowerErr, "allowlist") || strings.Contains(lowerErr, "drift") {
			denyReason = ReasonModelDestinationDenied
		}
		resp := PlaneDecisionV2{
			Decision:   DecisionDeny,
			ReasonCode: denyReason,
			Envelope:   planeReq.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata: map[string]any{
				"error":                            err.Error(),
				"openclaw_route":                   adapter.ResponsesPath,
				"policy_intent_projection_enabled": projectionEnabled,
				"policy_intent_projection_applied": projectionApplied,
				"policy_intent_projection_format":  projectionFormat,
			},
		}
		g.logPlaneDecision(r, resp, http.StatusBadGateway)
		writeOpenClawResponseError(w, http.StatusBadGateway, req.Model, decisionID, traceID, denyReason, "model provider egress failed")
		return
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

	text, functionCall, usage := parseOpenAIProviderResponse(egress.responseBody)
	outputItems, statusValue := buildOpenClawResponseOutput(decisionID, text, functionCall, finalStatus)
	metadata = map[string]any{
		"provider_used":                    egress.providerUsed,
		"upstream_status":                  egress.upstreamStatus,
		"fallback_attempted":               egress.fallbackAttempted,
		"policy_reason_code":               reason,
		"policy_decision":                  decision,
		"policy_http_status":               status,
		"openclaw_route":                   adapter.ResponsesPath,
		"openai_compat_route":              openAICompatChatCompletionsPath,
		"policy_intent_projection_enabled": projectionEnabled,
		"policy_intent_projection_applied": projectionApplied,
		"policy_intent_projection_format":  projectionFormat,
	}
	g.logPlaneDecision(r, PlaneDecisionV2{
		Decision:   finalDecision,
		ReasonCode: finalReason,
		Envelope:   planeReq.Envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata:   metadata,
	}, finalStatus)

	response := map[string]any{
		"id":         "resp_" + decisionID,
		"object":     "response",
		"created_at": time.Now().Unix(),
		"status":     statusValue,
		"model":      req.Model,
		"output":     outputItems,
		"usage":      usage,
	}
	if finalStatus >= 400 {
		response["error"] = map[string]any{
			"code":    "api_error",
			"message": "upstream model provider error",
		}
	}

	copyHeaderIfPresent(w.Header(), egress.responseHeaders, "Content-Type")
	copyHeaderIfPresent(w.Header(), egress.responseHeaders, "OpenAI-Processing-Ms")
	copyHeaderIfPresent(w.Header(), egress.responseHeaders, "X-Request-Id")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Precinct-Decision-ID", decisionID)
	w.Header().Set("X-Precinct-Trace-ID", traceID)
	w.Header().Set("X-Precinct-Reason-Code", string(finalReason))
	w.Header().Set("X-Precinct-Provider-Used", egress.providerUsed)
	w.Header().Set("X-Precinct-Policy-Intent-Projection", projectionHeaderValue(projectionEnabled, projectionApplied))
	w.WriteHeader(finalStatus)
	_ = json.NewEncoder(w).Encode(response)
}

func (g *Gateway) handleOpenClawToolsInvoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeV24GatewayError(
			w,
			r,
			http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest,
			"method not allowed",
			v24MiddlewareAppWrapperHTTP,
			ReasonContractInvalid,
			map[string]any{
				"route":           adapter.ToolsInvokePath,
				"expected_method": http.MethodPost,
			},
		)
		return
	}

	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		writeV24GatewayError(
			w,
			r,
			http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest,
			"unable to read request body",
			v24MiddlewareAppWrapperHTTP,
			ReasonContractInvalid,
			map[string]any{
				"route": adapter.ToolsInvokePath,
			},
		)
		return
	}

	req, err := adapter.ParseToolsInvokeRequest(rawBody)
	if err != nil {
		writeV24GatewayError(
			w,
			r,
			http.StatusBadRequest,
			middleware.ErrContractValidationFailed,
			"invalid tools.invoke request",
			v24MiddlewareAppWrapperHTTP,
			ReasonContractInvalid,
			map[string]any{
				"route": adapter.ToolsInvokePath,
				"error": err.Error(),
			},
		)
		return
	}

	envelope := RunEnvelope{
		RunID:         "openclaw-tools-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		SessionID:     resolveOpenClawSessionID(r, req),
		Tenant:        defaultString(strings.TrimSpace(r.Header.Get("X-Tenant")), "default"),
		ActorSPIFFEID: middleware.GetSPIFFEID(r.Context()),
		Plane:         PlaneTool,
	}
	traceID, decisionID := getDecisionCorrelationIDs(r, envelope)

	if adapter.IsDangerousHTTPTool(req.Tool) {
		metadata := map[string]any{
			"tool":           req.Tool,
			"openclaw_route": adapter.ToolsInvokePath,
		}
		g.logPlaneDecision(r, PlaneDecisionV2{
			Decision:   DecisionDeny,
			ReasonCode: ReasonToolCLICommandDenied,
			Envelope:   envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata:   metadata,
		}, http.StatusForbidden)
		writeOpenClawToolError(w, http.StatusForbidden, req.Tool, decisionID, traceID, ReasonToolCLICommandDenied, "dangerous tool is blocked on HTTP wrapper")
		return
	}

	target := adapter.ResolveToolPolicyTarget(req)
	attrs := map[string]any{
		"capability_id": target.CapabilityID,
		"tool_name":     req.Tool,
		"adapter":       target.Adapter,
		"protocol":      target.Adapter,
		"openclaw_args": req.Args,
	}
	if req.ApprovalToken != "" {
		attrs["approval_capability_token"] = req.ApprovalToken
	}

	planeReq := PlaneRequestV2{
		Envelope: envelope,
		Policy: PolicyInputV2{
			Envelope:   envelope,
			Action:     target.Action,
			Resource:   target.Resource,
			Attributes: attrs,
		},
	}
	eval := g.evaluateOpenClawToolRequest(planeReq)

	resp := PlaneDecisionV2{
		Decision:   eval.Decision,
		ReasonCode: eval.Reason,
		Envelope:   envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata:   mergeMetadata(eval.Metadata, map[string]any{"openclaw_route": adapter.ToolsInvokePath}),
	}
	g.logPlaneDecision(r, resp, eval.HTTPStatus)
	w.Header().Set("X-Precinct-Decision-ID", decisionID)
	w.Header().Set("X-Precinct-Trace-ID", traceID)
	w.Header().Set("X-Precinct-Reason-Code", string(eval.Reason))

	if eval.Decision != DecisionAllow {
		writeOpenClawToolError(w, eval.HTTPStatus, req.Tool, decisionID, traceID, eval.Reason, "tool invocation denied by policy")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true,
		"result": map[string]any{
			"tool":        req.Tool,
			"action":      target.Action,
			"resource":    target.Resource,
			"decision":    eval.Decision,
			"reason_code": eval.Reason,
			"decision_id": decisionID,
			"trace_id":    traceID,
			"dry_run":     req.DryRun,
			"metadata":    eval.Metadata,
		},
	})
}

func (g *Gateway) evaluateOpenClawToolRequest(req PlaneRequestV2) toolPlaneEvalResult {
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
	if !eval.RequireStepUp {
		return eval
	}

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
		return eval
	}
	if g.approvalCapabilities == nil {
		eval.Metadata = mergeMetadata(eval.Metadata, map[string]any{
			"step_up_state": "approval_service_unavailable",
		})
		return eval
	}

	_, err := g.approvalCapabilities.ValidateAndConsume(token, middleware.ApprovalScope{
		Action:        strings.TrimSpace(req.Policy.Action),
		Resource:      strings.TrimSpace(req.Policy.Resource),
		ActorSPIFFEID: req.Envelope.ActorSPIFFEID,
		SessionID:     req.Envelope.SessionID,
	})
	if err != nil {
		eval.Metadata = mergeMetadata(eval.Metadata, map[string]any{
			"step_up_state": "invalid_or_expired_token",
		})
		return eval
	}

	eval.RequireStepUp = false
	eval.Decision = DecisionAllow
	eval.Reason = ReasonToolAllow
	eval.HTTPStatus = statusForToolReason(ReasonToolAllow)
	eval.Metadata = mergeMetadata(eval.Metadata, map[string]any{
		"step_up_state": "approved_token_consumed",
	})
	return eval
}

func resolveOpenClawSessionID(r *http.Request, req adapter.ToolsInvokeRequest) string {
	if strings.TrimSpace(req.SessionKey) != "" {
		return strings.TrimSpace(req.SessionKey)
	}
	if sessionID := strings.TrimSpace(middleware.GetSessionID(r.Context())); sessionID != "" {
		return sessionID
	}
	return "openclaw-session-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

func writeOpenClawResponseError(
	w http.ResponseWriter,
	status int,
	model string,
	decisionID string,
	traceID string,
	reason ReasonCode,
	message string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Precinct-Decision-ID", decisionID)
	w.Header().Set("X-Precinct-Trace-ID", traceID)
	w.Header().Set("X-Precinct-Reason-Code", string(reason))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":         "resp_" + decisionID,
		"object":     "response",
		"created_at": time.Now().Unix(),
		"status":     "failed",
		"model":      model,
		"output":     []any{},
		"usage": map[string]any{
			"input_tokens":  0,
			"output_tokens": 0,
			"total_tokens":  0,
		},
		"error": map[string]any{
			"code":        "api_error",
			"message":     message,
			"reason_code": reason,
			"decision_id": decisionID,
			"trace_id":    traceID,
		},
	})
}

func writeOpenClawToolError(
	w http.ResponseWriter,
	status int,
	tool string,
	decisionID string,
	traceID string,
	reason ReasonCode,
	message string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Precinct-Decision-ID", decisionID)
	w.Header().Set("X-Precinct-Trace-ID", traceID)
	w.Header().Set("X-Precinct-Reason-Code", string(reason))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": false,
		"error": map[string]any{
			"type":        "policy_denied",
			"message":     message,
			"tool":        tool,
			"reason_code": reason,
			"decision_id": decisionID,
			"trace_id":    traceID,
		},
	})
}

func parseOpenAIProviderResponse(body []byte) (string, *openClawFunctionCall, map[string]any) {
	defaultUsage := map[string]any{
		"input_tokens":  0,
		"output_tokens": 0,
		"total_tokens":  0,
	}
	if len(body) == 0 {
		return "No response from model provider.", nil, defaultUsage
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "No response from model provider.", nil, defaultUsage
	}

	usage := parseOpenAIUsage(payload["usage"])
	choices, _ := payload["choices"].([]any)
	if len(choices) == 0 {
		return "No response from model provider.", nil, usage
	}

	firstChoice, _ := choices[0].(map[string]any)
	message, _ := firstChoice["message"].(map[string]any)
	if message == nil {
		return "No response from model provider.", nil, usage
	}

	if toolCall := parseOpenAIFunctionCall(message["tool_calls"]); toolCall != nil {
		return "", toolCall, usage
	}

	text := strings.TrimSpace(extractOpenAIMessageText(message["content"]))
	if text == "" {
		text = "No response from model provider."
	}
	return text, nil, usage
}

func parseOpenAIUsage(raw any) map[string]any {
	out := map[string]any{
		"input_tokens":  0,
		"output_tokens": 0,
		"total_tokens":  0,
	}
	usage, _ := raw.(map[string]any)
	if usage == nil {
		return out
	}
	prompt := intValue(usage["prompt_tokens"], 0)
	completion := intValue(usage["completion_tokens"], 0)
	total := intValue(usage["total_tokens"], prompt+completion)
	out["input_tokens"] = prompt
	out["output_tokens"] = completion
	out["total_tokens"] = total
	return out
}

func parseOpenAIFunctionCall(raw any) *openClawFunctionCall {
	toolCalls, _ := raw.([]any)
	if len(toolCalls) == 0 {
		return nil
	}
	first, _ := toolCalls[0].(map[string]any)
	if first == nil {
		return nil
	}
	function, _ := first["function"].(map[string]any)
	if function == nil {
		return nil
	}
	name := strings.TrimSpace(getString(function, "name", ""))
	if name == "" {
		return nil
	}
	callID := strings.TrimSpace(getString(first, "id", "call_"+strconv.FormatInt(time.Now().UnixNano(), 10)))
	arguments := getString(function, "arguments", "{}")
	return &openClawFunctionCall{
		CallID:    callID,
		Name:      name,
		Arguments: arguments,
	}
}

func extractOpenAIMessageText(raw any) string {
	switch value := raw.(type) {
	case string:
		return value
	case []any:
		parts := make([]string, 0, len(value))
		for _, item := range value {
			part, _ := item.(map[string]any)
			if part == nil {
				continue
			}
			if text := strings.TrimSpace(getString(part, "text", "")); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

func buildOpenClawResponseOutput(
	decisionID string,
	text string,
	functionCall *openClawFunctionCall,
	httpStatus int,
) ([]map[string]any, string) {
	if functionCall != nil {
		return []map[string]any{
			{
				"type":      "function_call",
				"id":        "call_" + decisionID,
				"call_id":   functionCall.CallID,
				"name":      functionCall.Name,
				"arguments": functionCall.Arguments,
			},
		}, "incomplete"
	}

	status := "completed"
	if httpStatus >= 400 {
		status = "failed"
	}
	return []map[string]any{
		{
			"type": "message",
			"id":   "msg_" + decisionID,
			"role": "assistant",
			"content": []map[string]any{
				{
					"type": "output_text",
					"text": text,
				},
			},
			"status": status,
		},
	}, status
}

func getString(m map[string]any, key, fallback string) string {
	if m == nil {
		return fallback
	}
	raw, ok := m[key]
	if !ok {
		return fallback
	}
	value, ok := raw.(string)
	if !ok {
		return fallback
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func intValue(raw any, fallback int) int {
	switch value := raw.(type) {
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float64:
		return int(value)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil {
			return n
		}
	}
	return fallback
}

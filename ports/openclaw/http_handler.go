package openclaw

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"github.com/precinct-dev/precinct/ports/openclaw/protocol"
)

const (
	middlewareNameHTTP = "v24_app_wrapper_http"
)

type openClawFunctionCall struct {
	CallID    string
	Name      string
	Arguments string
}

func (a *Adapter) handleResponses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.gw.WriteGatewayError(w, r, http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest, "method not allowed",
			middlewareNameHTTP, gateway.ReasonContractInvalid,
			map[string]any{"route": protocol.ResponsesPath, "expected_method": http.MethodPost})
		return
	}

	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest, "unable to read request body",
			middlewareNameHTTP, gateway.ReasonContractInvalid,
			map[string]any{"route": protocol.ResponsesPath})
		return
	}

	req, err := protocol.ParseResponsesRequest(rawBody)
	if err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrContractValidationFailed, "invalid OpenClaw responses request",
			middlewareNameHTTP, gateway.ReasonContractInvalid,
			map[string]any{"route": protocol.ResponsesPath, "error": err.Error()})
		return
	}

	if req.Stream {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrContractValidationFailed, "stream=true is not supported on secure wrapper path; use stream=false",
			middlewareNameHTTP, gateway.ReasonContractInvalid,
			map[string]any{"route": protocol.ResponsesPath})
		return
	}

	openAIPayload := map[string]any{
		"model":    req.Model,
		"messages": protocol.BuildOpenAIMessages(req),
	}
	if req.MaxOutputTokens > 0 {
		openAIPayload["max_tokens"] = req.MaxOutputTokens
	}

	planeReq := a.gw.BuildModelPlaneRequest(r, openAIPayload)
	traceID, decisionID := gateway.GetDecisionCorrelationIDs(r, planeReq.Envelope)
	decision, reason, status, metadata := a.gw.EvaluateModelPlaneDecision(r, planeReq)
	projectionEnabled := a.gw.ShouldApplyPolicyIntentProjection()
	projectionApplied := false
	projectionFormat := ""

	if decision != gateway.DecisionAllow {
		metadata = gateway.MergeMetadata(metadata, map[string]any{
			"openclaw_route":                   protocol.ResponsesPath,
			"policy_intent_projection_enabled": projectionEnabled,
			"policy_intent_projection_applied": false,
			"policy_intent_projection_format":  "",
		})
		resp := gateway.PlaneDecisionV2{
			Decision:   decision,
			ReasonCode: reason,
			Envelope:   planeReq.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata:   metadata,
		}
		a.gw.LogPlaneDecision(r, resp, status)
		writeResponseError(w, status, req.Model, decisionID, traceID, reason, "request denied by model policy")
		return
	}

	if projectionEnabled {
		projection := gateway.BuildModelPolicyIntentProjection(planeReq.Policy.Attributes, planeReq.Envelope)
		if projection != "" {
			projectionApplied = gateway.PrependSystemPolicyIntentMessage(openAIPayload, projection)
			if projectionApplied {
				projectionFormat = "xml.v1"
			}
		}
	}

	egress, err := a.gw.ExecuteModelEgress(r.Context(), planeReq.Policy.Attributes, openAIPayload, r.Header.Get("Authorization"))
	if err != nil {
		denyReason := gateway.ReasonModelProviderUnavailable
		lowerErr := strings.ToLower(err.Error())
		if strings.Contains(lowerErr, "allowlist") || strings.Contains(lowerErr, "drift") {
			denyReason = gateway.ReasonModelDestinationDenied
		}
		resp := gateway.PlaneDecisionV2{
			Decision:   gateway.DecisionDeny,
			ReasonCode: denyReason,
			Envelope:   planeReq.Envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata: map[string]any{
				"error":                            err.Error(),
				"openclaw_route":                   protocol.ResponsesPath,
				"policy_intent_projection_enabled": projectionEnabled,
				"policy_intent_projection_applied": projectionApplied,
				"policy_intent_projection_format":  projectionFormat,
			},
		}
		a.gw.LogPlaneDecision(r, resp, http.StatusBadGateway)
		writeResponseError(w, http.StatusBadGateway, req.Model, decisionID, traceID, denyReason, "model provider egress failed")
		return
	}

	finalDecision := gateway.DecisionAllow
	finalReason := egress.Reason
	finalStatus := egress.StatusCode
	if finalReason == "" {
		finalReason = reason
	}
	if finalStatus >= 400 {
		finalDecision = gateway.DecisionDeny
		if finalReason == gateway.ReasonModelAllow || finalReason == "" {
			finalReason = gateway.ReasonModelProviderUpstreamError
		}
	}

	text, functionCall, usage := parseOpenAIProviderResponse(egress.ResponseBody)
	outputItems, statusValue := buildResponseOutput(decisionID, text, functionCall, finalStatus)
	metadata = map[string]any{
		"provider_used":                    egress.ProviderUsed,
		"upstream_status":                  egress.UpstreamStatus,
		"fallback_attempted":               egress.FallbackAttempted,
		"policy_reason_code":               reason,
		"policy_decision":                  decision,
		"policy_http_status":               status,
		"openclaw_route":                   protocol.ResponsesPath,
		"openai_compat_route":              gateway.OpenAICompatChatCompletionsPath,
		"policy_intent_projection_enabled": projectionEnabled,
		"policy_intent_projection_applied": projectionApplied,
		"policy_intent_projection_format":  projectionFormat,
	}
	a.gw.LogPlaneDecision(r, gateway.PlaneDecisionV2{
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

	gateway.CopyHeaderIfPresent(w.Header(), egress.ResponseHeaders, "Content-Type")
	gateway.CopyHeaderIfPresent(w.Header(), egress.ResponseHeaders, "OpenAI-Processing-Ms")
	gateway.CopyHeaderIfPresent(w.Header(), egress.ResponseHeaders, "X-Request-Id")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Precinct-Decision-ID", decisionID)
	w.Header().Set("X-Precinct-Trace-ID", traceID)
	w.Header().Set("X-Precinct-Reason-Code", string(finalReason))
	w.Header().Set("X-Precinct-Provider-Used", egress.ProviderUsed)
	w.Header().Set("X-Precinct-Policy-Intent-Projection", gateway.ProjectionHeaderValue(projectionEnabled, projectionApplied))
	w.WriteHeader(finalStatus)
	_ = json.NewEncoder(w).Encode(response)
}

func (a *Adapter) handleToolsInvoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.gw.WriteGatewayError(w, r, http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest, "method not allowed",
			middlewareNameHTTP, gateway.ReasonContractInvalid,
			map[string]any{"route": protocol.ToolsInvokePath, "expected_method": http.MethodPost})
		return
	}

	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest, "unable to read request body",
			middlewareNameHTTP, gateway.ReasonContractInvalid,
			map[string]any{"route": protocol.ToolsInvokePath})
		return
	}

	req, err := protocol.ParseToolsInvokeRequest(rawBody)
	if err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrContractValidationFailed, "invalid tools.invoke request",
			middlewareNameHTTP, gateway.ReasonContractInvalid,
			map[string]any{"route": protocol.ToolsInvokePath, "error": err.Error()})
		return
	}

	envelope := gateway.RunEnvelope{
		RunID:         "openclaw-tools-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		SessionID:     resolveSessionID(r, req),
		Tenant:        gateway.DefaultString(strings.TrimSpace(r.Header.Get("X-Tenant")), "default"),
		ActorSPIFFEID: middleware.GetSPIFFEID(r.Context()),
		Plane:         gateway.PlaneTool,
	}
	traceID, decisionID := gateway.GetDecisionCorrelationIDs(r, envelope)

	if protocol.IsDangerousHTTPTool(req.Tool) {
		metadata := map[string]any{
			"tool":           req.Tool,
			"openclaw_route": protocol.ToolsInvokePath,
		}
		a.gw.LogPlaneDecision(r, gateway.PlaneDecisionV2{
			Decision:   gateway.DecisionDeny,
			ReasonCode: gateway.ReasonToolCLICommandDenied,
			Envelope:   envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata:   metadata,
		}, http.StatusForbidden)
		writeToolError(w, http.StatusForbidden, req.Tool, decisionID, traceID, gateway.ReasonToolCLICommandDenied, "dangerous tool is blocked on HTTP wrapper")
		return
	}

	target := protocol.ResolveToolPolicyTarget(req)
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

	planeReq := gateway.PlaneRequestV2{
		Envelope: envelope,
		Policy: gateway.PolicyInputV2{
			Envelope:   envelope,
			Action:     target.Action,
			Resource:   target.Resource,
			Attributes: attrs,
		},
	}
	eval := a.evaluateToolRequest(planeReq)

	resp := gateway.PlaneDecisionV2{
		Decision:   eval.Decision,
		ReasonCode: eval.Reason,
		Envelope:   envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata:   gateway.MergeMetadata(eval.Metadata, map[string]any{"openclaw_route": protocol.ToolsInvokePath}),
	}
	a.gw.LogPlaneDecision(r, resp, eval.HTTPStatus)
	w.Header().Set("X-Precinct-Decision-ID", decisionID)
	w.Header().Set("X-Precinct-Trace-ID", traceID)
	w.Header().Set("X-Precinct-Reason-Code", string(eval.Reason))

	if eval.Decision != gateway.DecisionAllow {
		writeToolError(w, eval.HTTPStatus, req.Tool, decisionID, traceID, eval.Reason, "tool invocation denied by policy")
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

func (a *Adapter) evaluateToolRequest(req gateway.PlaneRequestV2) gateway.ToolPlaneEvalResult {
	attrs := req.Policy.Attributes
	if attrs == nil {
		attrs = map[string]any{}
		req.Policy.Attributes = attrs
	}

	eval := a.gw.EvaluateToolRequest(req)
	if !eval.RequireStepUp {
		return eval
	}

	token := strings.TrimSpace(gateway.GetStringAttr(attrs, "approval_capability_token", ""))
	if token == "" {
		token = strings.TrimSpace(gateway.GetStringAttr(attrs, "step_up_token", ""))
	}
	if token == "" {
		token = strings.TrimSpace(gateway.GetStringAttr(attrs, "approval_token", ""))
	}

	if token == "" {
		eval.Metadata = gateway.MergeMetadata(eval.Metadata, map[string]any{"step_up_state": "missing_token"})
		return eval
	}
	if !a.gw.HasApprovalService() {
		eval.Metadata = gateway.MergeMetadata(eval.Metadata, map[string]any{"step_up_state": "approval_service_unavailable"})
		return eval
	}

	_, err := a.gw.ValidateAndConsumeApproval(token, middleware.ApprovalScope{
		Action:        strings.TrimSpace(req.Policy.Action),
		Resource:      strings.TrimSpace(req.Policy.Resource),
		ActorSPIFFEID: req.Envelope.ActorSPIFFEID,
		SessionID:     req.Envelope.SessionID,
	})
	if err != nil {
		eval.Metadata = gateway.MergeMetadata(eval.Metadata, map[string]any{"step_up_state": "invalid_or_expired_token"})
		return eval
	}

	eval.RequireStepUp = false
	eval.Decision = gateway.DecisionAllow
	eval.Reason = gateway.ReasonToolAllow
	eval.HTTPStatus = gateway.StatusForToolReason(gateway.ReasonToolAllow)
	eval.Metadata = gateway.MergeMetadata(eval.Metadata, map[string]any{"step_up_state": "approved_token_consumed"})
	return eval
}

func resolveSessionID(r *http.Request, req protocol.ToolsInvokeRequest) string {
	if strings.TrimSpace(req.SessionKey) != "" {
		return strings.TrimSpace(req.SessionKey)
	}
	if sessionID := strings.TrimSpace(middleware.GetSessionID(r.Context())); sessionID != "" {
		return sessionID
	}
	return "openclaw-session-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

func writeResponseError(w http.ResponseWriter, status int, model, decisionID, traceID string, reason gateway.ReasonCode, message string) {
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
		"usage":      map[string]any{"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
		"error": map[string]any{
			"code": "api_error", "message": message,
			"reason_code": reason, "decision_id": decisionID, "trace_id": traceID,
		},
	})
}

func writeToolError(w http.ResponseWriter, status int, tool, decisionID, traceID string, reason gateway.ReasonCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Precinct-Decision-ID", decisionID)
	w.Header().Set("X-Precinct-Trace-ID", traceID)
	w.Header().Set("X-Precinct-Reason-Code", string(reason))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": false,
		"error": map[string]any{
			"type": "policy_denied", "message": message,
			"tool": tool, "reason_code": reason,
			"decision_id": decisionID, "trace_id": traceID,
		},
	})
}

func parseOpenAIProviderResponse(body []byte) (string, *openClawFunctionCall, map[string]any) {
	defaultUsage := map[string]any{"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
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
	out := map[string]any{"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
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
	name := strings.TrimSpace(getStr(function, "name", ""))
	if name == "" {
		return nil
	}
	callID := strings.TrimSpace(getStr(first, "id", "call_"+strconv.FormatInt(time.Now().UnixNano(), 10)))
	arguments := getStr(function, "arguments", "{}")
	return &openClawFunctionCall{CallID: callID, Name: name, Arguments: arguments}
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
			if text := strings.TrimSpace(getStr(part, "text", "")); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

func buildResponseOutput(decisionID string, text string, functionCall *openClawFunctionCall, httpStatus int) ([]map[string]any, string) {
	if functionCall != nil {
		return []map[string]any{{
			"type": "function_call", "id": "call_" + decisionID,
			"call_id": functionCall.CallID, "name": functionCall.Name, "arguments": functionCall.Arguments,
		}}, "incomplete"
	}
	status := "completed"
	if httpStatus >= 400 {
		status = "failed"
	}
	return []map[string]any{{
		"type": "message", "id": "msg_" + decisionID, "role": "assistant",
		"content": []map[string]any{{"type": "output_text", "text": text}},
		"status":  status,
	}}, status
}

func getStr(m map[string]any, key, fallback string) string {
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

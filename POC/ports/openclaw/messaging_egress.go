package openclaw

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway"
	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
	"github.com/gorilla/websocket"
)

const reasonWSMessagingFailed gateway.ReasonCode = "WS_MESSAGING_FAILED"

// handleMessageSend processes a "message.send" WS frame by evaluating the
// tool request against gateway policy, then executing the messaging egress.
func (a *Adapter) handleMessageSend(_ context.Context, conn *websocket.Conn, frame wsRequestFrame, req *http.Request, session wsSession) {
	// Use a detached context for the egress HTTP call. The parent context
	// (req.Context()) is tied to the HTTP upgrade request lifecycle, which
	// may be canceled by the server while the WS connection is still active.
	ctx := context.Background()
	decisionID, traceID := wsCorrelationIDs(req)

	platform := getStringParam(frame.Params, "platform")
	recipient := getStringParam(frame.Params, "recipient")
	message := getStringParam(frame.Params, "message")

	if platform == "" || recipient == "" || message == "" {
		a.writeWSFailure(conn, frame.ID, http.StatusBadRequest, reasonWSPayloadMalformed,
			"message.send requires params: platform, recipient, message", decisionID, traceID)
		a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSPayloadMalformed,
			decisionID, traceID, http.StatusBadRequest)
		return
	}

	// Build a tool-plane request for policy evaluation.
	sessionID := strings.TrimSpace(middleware.GetSessionID(req.Context()))
	if sessionID == "" {
		sessionID = "openclaw-ws-msg-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	envelope := gateway.RunEnvelope{
		RunID:     "msg-run-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		SessionID: sessionID,
		Tenant:    "default",
		ActorSPIFFEID: strings.TrimSpace(middleware.GetSPIFFEID(req.Context())),
		Plane:     gateway.PlaneTool,
	}

	planeReq := gateway.PlaneRequestV2{
		Envelope: envelope,
		Policy: gateway.PolicyInputV2{
			Envelope: envelope,
			Action:   "tool.invoke",
			Resource: "messaging_send",
			Attributes: map[string]any{
				"capability_id": "tool.messaging.http",
				"tool_name":     "messaging_send",
				"platform":      platform,
				"recipient":     recipient,
			},
		},
	}

	eval := a.gw.EvaluateToolRequest(planeReq)
	if eval.Decision != gateway.DecisionAllow {
		a.writeWSFailure(conn, frame.ID, eval.HTTPStatus, eval.Reason,
			"message.send denied by policy", decisionID, traceID)
		a.logWSDecision(req, session, frame.Method, eval.Decision, eval.Reason,
			decisionID, traceID, eval.HTTPStatus)
		return
	}

	// Resolve auth header: prefer per-message auth_ref with SPIKE resolution,
	// fallback to upgrade request header.
	authRef := getStringParam(frame.Params, "auth_ref")
	fallbackAuth := strings.TrimSpace(req.Header.Get("Authorization"))
	authHeader, err := a.resolveSPIKERef(ctx, authRef, fallbackAuth)
	if err != nil {
		a.writeWSFailure(conn, frame.ID, http.StatusUnauthorized, reasonWSMessagingFailed,
			err.Error(), decisionID, traceID)
		a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSMessagingFailed,
			decisionID, traceID, http.StatusUnauthorized)
		return
	}

	// Build WhatsApp Cloud API payload.
	msgPayload, _ := json.Marshal(map[string]any{
		"messaging_product": "whatsapp",
		"to":                recipient,
		"type":              "text",
		"text":              map[string]string{"body": message},
	})

	attrs := map[string]string{
		"platform":  platform,
		"recipient": recipient,
	}

	result, err := a.gw.ExecuteMessagingEgress(ctx, attrs, msgPayload, authHeader)
	if err != nil {
		a.writeWSFailure(conn, frame.ID, http.StatusBadGateway, reasonWSMessagingFailed,
			"messaging egress failed: "+err.Error(), decisionID, traceID)
		a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSMessagingFailed,
			decisionID, traceID, http.StatusBadGateway)
		return
	}

	if result.StatusCode >= 400 {
		a.writeWSFailure(conn, frame.ID, result.StatusCode, reasonWSMessagingFailed,
			"messaging platform returned error", decisionID, traceID)
		a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSMessagingFailed,
			decisionID, traceID, result.StatusCode)
		return
	}

	_ = conn.WriteJSON(wsResponseFrame{
		Type: "res", ID: frame.ID, OK: true,
		Payload: map[string]any{
			"message_id":  result.MessageID,
			"platform":    result.Platform,
			"status_code": result.StatusCode,
			"decision_id": decisionID,
			"trace_id":    traceID,
		},
	})
	a.logWSDecision(req, session, frame.Method, gateway.DecisionAllow, reasonWSAllow,
		decisionID, traceID, http.StatusOK)
}

// resolveSPIKERef resolves a SPIKE token reference for per-message egress.
// If authRef is empty, returns fallbackAuth. If authRef is not a SPIKE ref ($SPIKE{...}),
// returns "Bearer " + authRef. Otherwise resolves via the gateway redeemer.
func (a *Adapter) resolveSPIKERef(ctx context.Context, authRef string, fallbackAuth string) (string, error) {
	if strings.TrimSpace(authRef) == "" {
		return fallbackAuth, nil
	}
	if strings.HasPrefix(authRef, "$SPIKE{") {
		resolved, err := a.gw.RedeemSPIKESecret(ctx, authRef)
		if err != nil {
			return "", fmt.Errorf("SPIKE token resolution failed: %w", err)
		}
		return "Bearer " + resolved, nil
	}
	// Non-SPIKE value -- use as Bearer token directly.
	return "Bearer " + authRef, nil
}

// handleMessageStatus processes a "message.status" WS frame.
// For POC, returns a simulated "delivered" status.
func (a *Adapter) handleMessageStatus(_ context.Context, conn *websocket.Conn, frame wsRequestFrame, req *http.Request, session wsSession) {
	decisionID, traceID := wsCorrelationIDs(req)

	platform := getStringParam(frame.Params, "platform")
	messageID := getStringParam(frame.Params, "message_id")

	if platform == "" || messageID == "" {
		a.writeWSFailure(conn, frame.ID, http.StatusBadRequest, reasonWSPayloadMalformed,
			"message.status requires params: platform, message_id", decisionID, traceID)
		a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSPayloadMalformed,
			decisionID, traceID, http.StatusBadRequest)
		return
	}

	// POC: Return simulated delivered status.
	_ = conn.WriteJSON(wsResponseFrame{
		Type: "res", ID: frame.ID, OK: true,
		Payload: map[string]any{
			"platform":    platform,
			"message_id":  messageID,
			"status":      "delivered",
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
			"decision_id": decisionID,
			"trace_id":    traceID,
		},
	})
	a.logWSDecision(req, session, frame.Method, gateway.DecisionAllow, reasonWSAllow,
		decisionID, traceID, http.StatusOK)
}

// handleConnectorRegister processes a "connector.register" WS frame.
// Operator-only. Does NOT use SPIKE resolution (no external egress).
func (a *Adapter) handleConnectorRegister(_ context.Context, conn *websocket.Conn, frame wsRequestFrame, req *http.Request, session wsSession) {
	decisionID, traceID := wsCorrelationIDs(req)

	connectorID := getStringParam(frame.Params, "connector_id")
	platform := getStringParam(frame.Params, "platform")

	if connectorID == "" || platform == "" {
		a.writeWSFailure(conn, frame.ID, http.StatusBadRequest, reasonWSPayloadMalformed,
			"connector.register requires params: connector_id, platform", decisionID, traceID)
		a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSPayloadMalformed,
			decisionID, traceID, http.StatusBadRequest)
		return
	}

	// POC: Return registration acknowledgment.
	_ = conn.WriteJSON(wsResponseFrame{
		Type: "res", ID: frame.ID, OK: true,
		Payload: map[string]any{
			"connector_id": connectorID,
			"platform":     platform,
			"status":       "registered",
			"decision_id":  decisionID,
			"trace_id":     traceID,
		},
	})
	a.logWSDecision(req, session, frame.Method, gateway.DecisionAllow, reasonWSAllow,
		decisionID, traceID, http.StatusOK)
}

// getStringParam safely extracts a string value from a params map.
func getStringParam(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	v, ok := params[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package openclaw

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"github.com/gorilla/websocket"
)

const middlewareNameWS = "v24_app_wrapper_ws"

const (
	reasonWSAllow            gateway.ReasonCode = "WS_ALLOW"
	reasonWSConnectRequired  gateway.ReasonCode = "WS_CONNECT_REQUIRED"
	reasonWSAuthInvalid      gateway.ReasonCode = "WS_AUTH_INVALID"
	reasonWSMethodForbidden  gateway.ReasonCode = "WS_METHOD_FORBIDDEN"
	reasonWSPayloadMalformed gateway.ReasonCode = "WS_PAYLOAD_MALFORMED"
	reasonWSDeviceRequired   gateway.ReasonCode = "WS_DEVICE_REQUIRED"
)

type wsRequestFrame struct {
	Type   string         `json:"type"`
	ID     string         `json:"id"`
	Method string         `json:"method"`
	Params map[string]any `json:"params,omitempty"`
}

type wsErrorShape struct {
	Code       string             `json:"code"`
	Message    string             `json:"message"`
	ReasonCode gateway.ReasonCode `json:"reason_code,omitempty"`
	Details    map[string]any     `json:"details,omitempty"`
}

type wsResponseFrame struct {
	Type    string         `json:"type"`
	ID      string         `json:"id"`
	OK      bool           `json:"ok"`
	Payload map[string]any `json:"payload,omitempty"`
	Error   *wsErrorShape  `json:"error,omitempty"`
}

type wsSession struct {
	Connected bool
	Role      string
	Scopes    map[string]struct{}
	DeviceID  string
}

var wsUpgrader = websocket.Upgrader{
	HandshakeTimeout: 10 * time.Second,
	CheckOrigin: func(r *http.Request) bool {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			return true
		}
		originURL, err := url.Parse(origin)
		if err != nil {
			return false
		}
		if strings.TrimSpace(originURL.Host) == "" {
			return false
		}
		return strings.EqualFold(originURL.Host, r.Host)
	},
}

func (a *Adapter) handleWSEntry(w http.ResponseWriter, r *http.Request) {
	if !websocket.IsWebSocketUpgrade(r) {
		a.gw.WriteGatewayError(w, r, http.StatusUpgradeRequired,
			middleware.ErrMCPInvalidRequest, "websocket upgrade required",
			middlewareNameWS, reasonWSAuthInvalid,
			map[string]any{"route": openClawWSPath})
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	go a.serveWSConnection(conn, r)
}

func (a *Adapter) serveWSConnection(conn *websocket.Conn, req *http.Request) {
	defer func() { _ = conn.Close() }()
	conn.SetReadLimit(1 << 20)

	spiffeID := strings.TrimSpace(middleware.GetSPIFFEID(req.Context()))
	session := wsSession{
		Connected: false,
		Role:      "",
		Scopes:    map[string]struct{}{},
	}

	for {
		var frame wsRequestFrame
		if err := conn.ReadJSON(&frame); err != nil {
			return
		}

		decisionID, traceID := wsCorrelationIDs(req)
		if strings.TrimSpace(frame.Type) != "req" || strings.TrimSpace(frame.ID) == "" || strings.TrimSpace(frame.Method) == "" {
			a.writeWSFailure(conn, frame.ID, http.StatusBadRequest, reasonWSPayloadMalformed, "invalid request frame", decisionID, traceID)
			a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSPayloadMalformed, decisionID, traceID, http.StatusBadRequest)
			continue
		}

		if !session.Connected {
			if frame.Method != "connect" {
				a.writeWSFailure(conn, frame.ID, http.StatusUnauthorized, reasonWSConnectRequired, "first request must be connect", decisionID, traceID)
				a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSConnectRequired, decisionID, traceID, http.StatusUnauthorized)
				continue
			}
			if err := a.handleWSConnect(req, &session, frame, spiffeID, decisionID, traceID, conn); err != nil {
				continue
			}
			continue
		}

		switch frame.Method {
		case "health":
			_ = conn.WriteJSON(wsResponseFrame{
				Type: "res", ID: frame.ID, OK: true,
				Payload: a.wsMethodSuccessPayload(session, frame, spiffeID, decisionID, traceID),
			})
			a.logWSDecision(req, session, frame.Method, gateway.DecisionAllow, reasonWSAllow, decisionID, traceID, http.StatusOK)
		case "devices.list":
			if !wsAllowed(session, frame.Method) {
				a.writeWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSMethodForbidden, "method forbidden for current role/scopes", decisionID, traceID)
				a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSMethodForbidden, decisionID, traceID, http.StatusForbidden)
				continue
			}
			_ = conn.WriteJSON(wsResponseFrame{
				Type: "res", ID: frame.ID, OK: true,
				Payload: a.wsMethodSuccessPayload(session, frame, spiffeID, decisionID, traceID),
			})
			a.logWSDecision(req, session, frame.Method, gateway.DecisionAllow, reasonWSAllow, decisionID, traceID, http.StatusOK)
		case "devices.ping":
			if !wsAllowed(session, frame.Method) {
				a.writeWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSMethodForbidden, "method forbidden for current role/scopes", decisionID, traceID)
				a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSMethodForbidden, decisionID, traceID, http.StatusForbidden)
				continue
			}
			deviceID := strings.TrimSpace(gateway.GetStringAttr(frame.Params, "device_id", ""))
			if deviceID == "" {
				a.writeWSFailure(conn, frame.ID, http.StatusBadRequest, reasonWSPayloadMalformed, "devices.ping requires params.device_id", decisionID, traceID)
				a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSPayloadMalformed, decisionID, traceID, http.StatusBadRequest)
				continue
			}
			_ = conn.WriteJSON(wsResponseFrame{
				Type: "res", ID: frame.ID, OK: true,
				Payload: a.wsMethodSuccessPayload(session, frame, spiffeID, decisionID, traceID),
			})
			a.logWSDecision(req, session, frame.Method, gateway.DecisionAllow, reasonWSAllow, decisionID, traceID, http.StatusOK)
		case "message.send":
			if !wsAllowed(session, frame.Method) {
				a.writeWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSMethodForbidden, "method forbidden for current role/scopes", decisionID, traceID)
				a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSMethodForbidden, decisionID, traceID, http.StatusForbidden)
				continue
			}
			a.handleMessageSend(req.Context(), conn, frame, req, session)
		case "message.status":
			if !wsAllowed(session, frame.Method) {
				a.writeWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSMethodForbidden, "method forbidden for current role/scopes", decisionID, traceID)
				a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSMethodForbidden, decisionID, traceID, http.StatusForbidden)
				continue
			}
			a.handleMessageStatus(req.Context(), conn, frame, req, session)
		case "connector.register":
			if !wsAllowed(session, frame.Method) {
				a.writeWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSMethodForbidden, "method forbidden for current role/scopes", decisionID, traceID)
				a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSMethodForbidden, decisionID, traceID, http.StatusForbidden)
				continue
			}
			a.handleConnectorRegister(req.Context(), conn, frame, req, session)
		default:
			a.writeWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSMethodForbidden, "unsupported control-plane method", decisionID, traceID)
			a.logWSDecision(req, session, frame.Method, gateway.DecisionDeny, reasonWSMethodForbidden, decisionID, traceID, http.StatusForbidden)
		}
	}
}

func (a *Adapter) handleWSConnect(req *http.Request, session *wsSession, frame wsRequestFrame, spiffeID, decisionID, traceID string, conn *websocket.Conn) error {
	role := strings.ToLower(strings.TrimSpace(gateway.GetStringAttr(frame.Params, "role", "operator")))
	if role != "operator" && role != "node" {
		a.writeWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSAuthInvalid, "invalid role", decisionID, traceID)
		a.logWSDecision(req, *session, frame.Method, gateway.DecisionDeny, reasonWSAuthInvalid, decisionID, traceID, http.StatusForbidden)
		return nil
	}
	if strings.TrimSpace(spiffeID) == "" {
		a.writeWSFailure(conn, frame.ID, http.StatusUnauthorized, reasonWSAuthInvalid, "missing SPIFFE identity in request context", decisionID, traceID)
		a.logWSDecision(req, *session, frame.Method, gateway.DecisionDeny, reasonWSAuthInvalid, decisionID, traceID, http.StatusUnauthorized)
		return nil
	}

	if role == "node" {
		device, hasDevice := frame.Params["device"].(map[string]any)
		nodeDeviceID := ""
		if hasDevice {
			nodeDeviceID = strings.TrimSpace(gateway.GetStringAttr(device, "id", ""))
		}
		if nodeDeviceID == "" {
			a.writeWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSDeviceRequired, "node role requires device identity", decisionID, traceID)
			a.logWSDecision(req, *session, frame.Method, gateway.DecisionDeny, reasonWSDeviceRequired, decisionID, traceID, http.StatusForbidden)
			return nil
		}
	}

	scopes := parseWSScopes(frame.Params["scopes"])
	deviceID := ""
	if device, ok := frame.Params["device"].(map[string]any); ok {
		deviceID = strings.TrimSpace(gateway.GetStringAttr(device, "id", ""))
		token := ""
		if auth, ok := frame.Params["auth"].(map[string]any); ok {
			token = strings.TrimSpace(gateway.GetStringAttr(auth, "token", ""))
		}
		if deviceID != "" && token == "" {
			a.writeWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSAuthInvalid, "device connect requires auth.token", decisionID, traceID)
			a.logWSDecision(req, *session, frame.Method, gateway.DecisionDeny, reasonWSAuthInvalid, decisionID, traceID, http.StatusForbidden)
			return nil
		}
	}

	session.Connected = true
	session.Role = role
	session.DeviceID = deviceID
	session.Scopes = scopes

	methods := []string{"health"}
	if wsAllowed(*session, "devices.list") {
		methods = append(methods, "devices.list")
	}
	if wsAllowed(*session, "devices.ping") {
		methods = append(methods, "devices.ping")
	}
	if wsAllowed(*session, "message.send") {
		methods = append(methods, "message.send")
	}
	if wsAllowed(*session, "message.status") {
		methods = append(methods, "message.status")
	}
	if wsAllowed(*session, "connector.register") {
		methods = append(methods, "connector.register")
	}

	_ = conn.WriteJSON(wsResponseFrame{
		Type: "res", ID: frame.ID, OK: true,
		Payload: map[string]any{
			"type":     "hello-ok",
			"protocol": 1,
			"server": map[string]any{
				"version": "poc-openclaw-ws-wrapper",
				"connId":  "conn-" + decisionID,
			},
			"features": map[string]any{
				"methods": methods,
				"events":  []string{"presence", "tick"},
			},
			"auth": map[string]any{
				"role": role, "scopes": stringSetToSlice(scopes),
				"spiffe": spiffeID, "device": deviceID,
			},
			"policy": map[string]any{
				"maxPayload":       1024 * 1024,
				"maxBufferedBytes": 1024 * 1024,
				"tickIntervalMs":   1000,
			},
			"decision_id": decisionID,
			"trace_id":    traceID,
		},
	})
	a.logWSDecision(req, *session, frame.Method, gateway.DecisionAllow, reasonWSAllow, decisionID, traceID, http.StatusOK)
	return nil
}

func (a *Adapter) wsMethodSuccessPayload(session wsSession, frame wsRequestFrame, spiffeID, decisionID, traceID string) map[string]any {
	switch frame.Method {
	case "health":
		return map[string]any{"status": "ok", "ts": time.Now().UnixMilli(), "decision_id": decisionID, "trace_id": traceID}
	case "devices.list":
		deviceID := session.DeviceID
		if deviceID == "" {
			deviceID = "unpaired"
		}
		return map[string]any{
			"devices":     []map[string]any{{"id": deviceID, "bound_spiffe": spiffeID, "state": "connected"}},
			"decision_id": decisionID, "trace_id": traceID,
		}
	case "devices.ping":
		return map[string]any{
			"pong": true, "device_id": strings.TrimSpace(gateway.GetStringAttr(frame.Params, "device_id", "")),
			"decision_id": decisionID, "trace_id": traceID,
		}
	default:
		return map[string]any{}
	}
}

func (a *Adapter) writeWSFailure(conn *websocket.Conn, frameID string, status int, reason gateway.ReasonCode, message, decisionID, traceID string) {
	id := strings.TrimSpace(frameID)
	if id == "" {
		id = "unknown"
	}
	_ = conn.WriteJSON(wsResponseFrame{
		Type: "res", ID: id, OK: false,
		Error: &wsErrorShape{
			Code: "ws_request_denied", Message: message, ReasonCode: reason,
			Details: map[string]any{"http_status": status, "decision_id": decisionID, "trace_id": traceID},
		},
	})
}

func (a *Adapter) logWSDecision(req *http.Request, session wsSession, method string, decision gateway.Decision, reason gateway.ReasonCode, decisionID, traceID string, statusCode int) {
	sessionID := strings.TrimSpace(middleware.GetSessionID(req.Context()))
	if sessionID == "" {
		sessionID = "openclaw-ws-" + decisionID
	}
	result := "decision=" + string(decision) + " reason_code=" + string(reason) + " role=" + session.Role
	if session.DeviceID != "" {
		result += " device_id=" + session.DeviceID
	}
	a.gw.AuditLog(middleware.AuditEvent{
		SessionID:  sessionID,
		DecisionID: decisionID,
		TraceID:    traceID,
		SPIFFEID:   middleware.GetSPIFFEID(req.Context()),
		Action:     "openclaw.ws." + strings.TrimSpace(method),
		Result:     result,
		Method:     http.MethodGet,
		Path:       openClawWSPath,
		StatusCode: statusCode,
	})
}

func wsCorrelationIDs(req *http.Request) (string, string) {
	now := strconv.FormatInt(time.Now().UnixNano(), 10)
	traceID := strings.TrimSpace(middleware.GetTraceID(req.Context()))
	if traceID == "" {
		traceID = "ws-trace-" + now
	}
	decisionID := strings.TrimSpace(middleware.GetDecisionID(req.Context()))
	if decisionID == "" {
		decisionID = "ws-decision-" + now
	}
	return decisionID, traceID
}

func parseWSScopes(raw any) map[string]struct{} {
	out := map[string]struct{}{}
	switch list := raw.(type) {
	case []any:
		for _, item := range list {
			value, ok := item.(string)
			if !ok {
				continue
			}
			value = strings.TrimSpace(strings.ToLower(value))
			if value == "" {
				continue
			}
			out[value] = struct{}{}
		}
	case []string:
		for _, item := range list {
			value := strings.TrimSpace(strings.ToLower(item))
			if value == "" {
				continue
			}
			out[value] = struct{}{}
		}
	}
	return out
}

func stringSetToSlice(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func wsAllowed(session wsSession, method string) bool {
	switch method {
	case "health":
		return true
	case "devices.list":
		if session.Role == "operator" {
			return true
		}
		_, ok := session.Scopes["devices:read"]
		return ok
	case "devices.ping":
		if session.Role == "operator" {
			return true
		}
		_, ok := session.Scopes["devices:write"]
		return ok
	case "message.send":
		if session.Role == "operator" {
			return true
		}
		_, ok := session.Scopes["tools.messaging.send"]
		return ok
	case "message.status":
		if session.Role == "operator" {
			return true
		}
		_, ok := session.Scopes["tools.messaging.status"]
		return ok
	case "connector.register":
		return session.Role == "operator"
	default:
		return false
	}
}

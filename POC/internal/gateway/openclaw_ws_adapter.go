package gateway

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
	"github.com/gorilla/websocket"
)

const openClawWSPath = "/openclaw/ws"

const (
	reasonWSAllow            ReasonCode = "WS_ALLOW"
	reasonWSConnectRequired  ReasonCode = "WS_CONNECT_REQUIRED"
	reasonWSAuthInvalid      ReasonCode = "WS_AUTH_INVALID"
	reasonWSMethodForbidden  ReasonCode = "WS_METHOD_FORBIDDEN"
	reasonWSPayloadMalformed ReasonCode = "WS_PAYLOAD_MALFORMED"
	reasonWSDeviceRequired   ReasonCode = "WS_DEVICE_REQUIRED"
)

type openClawWSRequestFrame struct {
	Type   string         `json:"type"`
	ID     string         `json:"id"`
	Method string         `json:"method"`
	Params map[string]any `json:"params,omitempty"`
}

type openClawWSErrorShape struct {
	Code       string         `json:"code"`
	Message    string         `json:"message"`
	ReasonCode ReasonCode     `json:"reason_code,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

type openClawWSResponseFrame struct {
	Type    string                `json:"type"`
	ID      string                `json:"id"`
	OK      bool                  `json:"ok"`
	Payload map[string]any        `json:"payload,omitempty"`
	Error   *openClawWSErrorShape `json:"error,omitempty"`
}

type openClawWSSession struct {
	Connected bool
	Role      string
	Scopes    map[string]struct{}
	DeviceID  string
}

var openClawWSUpgrader = websocket.Upgrader{
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

func (g *Gateway) wsMethodSuccessPayload(session openClawWSSession, frame openClawWSRequestFrame, spiffeID, decisionID, traceID string) map[string]any {
	switch frame.Method {
	case "health":
		return map[string]any{
			"status":      "ok",
			"ts":          time.Now().UnixMilli(),
			"decision_id": decisionID,
			"trace_id":    traceID,
		}
	case "devices.list":
		deviceID := session.DeviceID
		if deviceID == "" {
			deviceID = "unpaired"
		}
		return map[string]any{
			"devices": []map[string]any{
				{
					"id":           deviceID,
					"bound_spiffe": spiffeID,
					"state":        "connected",
				},
			},
			"decision_id": decisionID,
			"trace_id":    traceID,
		}
	case "devices.ping":
		return map[string]any{
			"pong":        true,
			"device_id":   strings.TrimSpace(getStringAttr(frame.Params, "device_id", "")),
			"decision_id": decisionID,
			"trace_id":    traceID,
		}
	default:
		return map[string]any{}
	}
}

func (g *Gateway) handleAppWSEntry(w http.ResponseWriter, r *http.Request) bool {
	if r == nil || r.URL == nil || r.URL.Path != openClawWSPath {
		return false
	}
	if !websocket.IsWebSocketUpgrade(r) {
		writeV24GatewayError(
			w,
			r,
			http.StatusUpgradeRequired,
			middleware.ErrMCPInvalidRequest,
			"websocket upgrade required",
			v24MiddlewareAppWrapperWS,
			reasonWSAuthInvalid,
			map[string]any{
				"route": openClawWSPath,
			},
		)
		return true
	}

	conn, err := openClawWSUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return true
	}

	go g.serveOpenClawWSConnection(conn, r)
	return true
}

func (g *Gateway) serveOpenClawWSConnection(conn *websocket.Conn, req *http.Request) {
	defer func() { _ = conn.Close() }()
	conn.SetReadLimit(1 << 20) // 1MB

	spiffeID := strings.TrimSpace(middleware.GetSPIFFEID(req.Context()))
	session := openClawWSSession{
		Connected: false,
		Role:      "",
		Scopes:    map[string]struct{}{},
	}

	for {
		var frame openClawWSRequestFrame
		if err := conn.ReadJSON(&frame); err != nil {
			return
		}

		decisionID, traceID := openClawWSCorrelationIDs(req)
		if strings.TrimSpace(frame.Type) != "req" || strings.TrimSpace(frame.ID) == "" || strings.TrimSpace(frame.Method) == "" {
			g.writeOpenClawWSFailure(conn, frame.ID, http.StatusBadRequest, reasonWSPayloadMalformed, "invalid request frame", decisionID, traceID)
			g.logOpenClawWSDecision(req, session, frame.Method, DecisionDeny, reasonWSPayloadMalformed, decisionID, traceID, http.StatusBadRequest)
			continue
		}

		if !session.Connected {
			if frame.Method != "connect" {
				g.writeOpenClawWSFailure(conn, frame.ID, http.StatusUnauthorized, reasonWSConnectRequired, "first request must be connect", decisionID, traceID)
				g.logOpenClawWSDecision(req, session, frame.Method, DecisionDeny, reasonWSConnectRequired, decisionID, traceID, http.StatusUnauthorized)
				continue
			}
			if err := g.handleOpenClawWSConnect(req, &session, frame, spiffeID, decisionID, traceID, conn); err != nil {
				continue
			}
			continue
		}

		switch frame.Method {
		case "health":
			_ = conn.WriteJSON(openClawWSResponseFrame{
				Type:    "res",
				ID:      frame.ID,
				OK:      true,
				Payload: g.wsMethodSuccessPayload(session, frame, spiffeID, decisionID, traceID),
			})
			g.logOpenClawWSDecision(req, session, frame.Method, DecisionAllow, reasonWSAllow, decisionID, traceID, http.StatusOK)
		case "devices.list":
			if !openClawWSAllowed(session, frame.Method) {
				g.writeOpenClawWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSMethodForbidden, "method forbidden for current role/scopes", decisionID, traceID)
				g.logOpenClawWSDecision(req, session, frame.Method, DecisionDeny, reasonWSMethodForbidden, decisionID, traceID, http.StatusForbidden)
				continue
			}
			_ = conn.WriteJSON(openClawWSResponseFrame{
				Type:    "res",
				ID:      frame.ID,
				OK:      true,
				Payload: g.wsMethodSuccessPayload(session, frame, spiffeID, decisionID, traceID),
			})
			g.logOpenClawWSDecision(req, session, frame.Method, DecisionAllow, reasonWSAllow, decisionID, traceID, http.StatusOK)
		case "devices.ping":
			if !openClawWSAllowed(session, frame.Method) {
				g.writeOpenClawWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSMethodForbidden, "method forbidden for current role/scopes", decisionID, traceID)
				g.logOpenClawWSDecision(req, session, frame.Method, DecisionDeny, reasonWSMethodForbidden, decisionID, traceID, http.StatusForbidden)
				continue
			}
			deviceID := strings.TrimSpace(getStringAttr(frame.Params, "device_id", ""))
			if deviceID == "" {
				g.writeOpenClawWSFailure(conn, frame.ID, http.StatusBadRequest, reasonWSPayloadMalformed, "devices.ping requires params.device_id", decisionID, traceID)
				g.logOpenClawWSDecision(req, session, frame.Method, DecisionDeny, reasonWSPayloadMalformed, decisionID, traceID, http.StatusBadRequest)
				continue
			}
			_ = conn.WriteJSON(openClawWSResponseFrame{
				Type:    "res",
				ID:      frame.ID,
				OK:      true,
				Payload: g.wsMethodSuccessPayload(session, frame, spiffeID, decisionID, traceID),
			})
			g.logOpenClawWSDecision(req, session, frame.Method, DecisionAllow, reasonWSAllow, decisionID, traceID, http.StatusOK)
		default:
			g.writeOpenClawWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSMethodForbidden, "unsupported control-plane method", decisionID, traceID)
			g.logOpenClawWSDecision(req, session, frame.Method, DecisionDeny, reasonWSMethodForbidden, decisionID, traceID, http.StatusForbidden)
		}
	}
}

func (g *Gateway) handleOpenClawWSConnect(
	req *http.Request,
	session *openClawWSSession,
	frame openClawWSRequestFrame,
	spiffeID string,
	decisionID string,
	traceID string,
	conn *websocket.Conn,
) error {
	role := strings.ToLower(strings.TrimSpace(getStringAttr(frame.Params, "role", "operator")))
	if role != "operator" && role != "node" {
		g.writeOpenClawWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSAuthInvalid, "invalid role", decisionID, traceID)
		g.logOpenClawWSDecision(req, *session, frame.Method, DecisionDeny, reasonWSAuthInvalid, decisionID, traceID, http.StatusForbidden)
		return nil
	}
	if strings.TrimSpace(spiffeID) == "" {
		g.writeOpenClawWSFailure(conn, frame.ID, http.StatusUnauthorized, reasonWSAuthInvalid, "missing SPIFFE identity in request context", decisionID, traceID)
		g.logOpenClawWSDecision(req, *session, frame.Method, DecisionDeny, reasonWSAuthInvalid, decisionID, traceID, http.StatusUnauthorized)
		return nil
	}

	// Enforce device-identity requirement for node role (upstream contract: ddcb2d79b).
	// Only operator role with shared-secret auth may omit device identity.
	if role == "node" {
		device, hasDevice := frame.Params["device"].(map[string]any)
		nodeDeviceID := ""
		if hasDevice {
			nodeDeviceID = strings.TrimSpace(getStringAttr(device, "id", ""))
		}
		if nodeDeviceID == "" {
			g.writeOpenClawWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSDeviceRequired, "node role requires device identity", decisionID, traceID)
			g.logOpenClawWSDecision(req, *session, frame.Method, DecisionDeny, reasonWSDeviceRequired, decisionID, traceID, http.StatusForbidden)
			return nil
		}
	}

	scopes := parseOpenClawWSScopes(frame.Params["scopes"])
	deviceID := ""
	if device, ok := frame.Params["device"].(map[string]any); ok {
		deviceID = strings.TrimSpace(getStringAttr(device, "id", ""))
		token := ""
		if auth, ok := frame.Params["auth"].(map[string]any); ok {
			token = strings.TrimSpace(getStringAttr(auth, "token", ""))
		}
		if deviceID != "" && token == "" {
			g.writeOpenClawWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSAuthInvalid, "device connect requires auth.token", decisionID, traceID)
			g.logOpenClawWSDecision(req, *session, frame.Method, DecisionDeny, reasonWSAuthInvalid, decisionID, traceID, http.StatusForbidden)
			return nil
		}
	}

	session.Connected = true
	session.Role = role
	session.DeviceID = deviceID
	session.Scopes = scopes

	methods := []string{"health"}
	if openClawWSAllowed(*session, "devices.list") {
		methods = append(methods, "devices.list")
	}
	if openClawWSAllowed(*session, "devices.ping") {
		methods = append(methods, "devices.ping")
	}

	_ = conn.WriteJSON(openClawWSResponseFrame{
		Type: "res",
		ID:   frame.ID,
		OK:   true,
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
				"role":   role,
				"scopes": stringSetToSlice(scopes),
				"spiffe": spiffeID,
				"device": deviceID,
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
	g.logOpenClawWSDecision(req, *session, frame.Method, DecisionAllow, reasonWSAllow, decisionID, traceID, http.StatusOK)
	return nil
}

func (g *Gateway) writeOpenClawWSFailure(
	conn *websocket.Conn,
	frameID string,
	status int,
	reason ReasonCode,
	message string,
	decisionID string,
	traceID string,
) {
	id := strings.TrimSpace(frameID)
	if id == "" {
		id = "unknown"
	}
	_ = conn.WriteJSON(openClawWSResponseFrame{
		Type: "res",
		ID:   id,
		OK:   false,
		Error: &openClawWSErrorShape{
			Code:       "ws_request_denied",
			Message:    message,
			ReasonCode: reason,
			Details: map[string]any{
				"http_status": status,
				"decision_id": decisionID,
				"trace_id":    traceID,
			},
		},
	})
}

func (g *Gateway) logOpenClawWSDecision(
	req *http.Request,
	session openClawWSSession,
	method string,
	decision Decision,
	reason ReasonCode,
	decisionID string,
	traceID string,
	statusCode int,
) {
	if g == nil || g.auditor == nil {
		return
	}
	sessionID := strings.TrimSpace(middleware.GetSessionID(req.Context()))
	if sessionID == "" {
		sessionID = "openclaw-ws-" + decisionID
	}
	result := "decision=" + string(decision) + " reason_code=" + string(reason) + " role=" + session.Role
	if session.DeviceID != "" {
		result += " device_id=" + session.DeviceID
	}
	g.auditor.Log(middleware.AuditEvent{
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

func openClawWSCorrelationIDs(req *http.Request) (string, string) {
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

func parseOpenClawWSScopes(raw any) map[string]struct{} {
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

func openClawWSAllowed(session openClawWSSession, method string) bool {
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
	default:
		return false
	}
}

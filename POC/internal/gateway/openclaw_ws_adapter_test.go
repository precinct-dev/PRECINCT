package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func openClawWSURL(serverURL string) string {
	return strings.Replace(serverURL, "http://", "ws://", 1) + openClawWSPath
}

func readWSResponse(t *testing.T, conn *websocket.Conn) openClawWSResponseFrame {
	t.Helper()
	var frame openClawWSResponseFrame
	if err := conn.ReadJSON(&frame); err != nil {
		t.Fatalf("read ws response: %v", err)
	}
	return frame
}

func TestOpenClawWSGatewayProtocol_AuthenticatedFlow(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	server := httptest.NewServer(gw.Handler())
	defer server.Close()

	headers := http.Header{}
	headers.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	conn, resp, err := websocket.DefaultDialer.Dial(openClawWSURL(server.URL), headers)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial websocket failed (status=%d): %v", status, err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(openClawWSRequestFrame{
		Type:   "req",
		ID:     "connect-1",
		Method: "connect",
		Params: map[string]any{
			"role":   "operator",
			"scopes": []string{"devices:read"},
		},
	}); err != nil {
		t.Fatalf("write connect frame: %v", err)
	}
	connectResp := readWSResponse(t, conn)
	if !connectResp.OK {
		t.Fatalf("expected connect success, got error=%+v", connectResp.Error)
	}

	if err := conn.WriteJSON(openClawWSRequestFrame{
		Type:   "req",
		ID:     "health-1",
		Method: "health",
	}); err != nil {
		t.Fatalf("write health frame: %v", err)
	}
	healthResp := readWSResponse(t, conn)
	if !healthResp.OK {
		t.Fatalf("expected health success, got error=%+v", healthResp.Error)
	}
	if healthResp.Payload["decision_id"] == nil || healthResp.Payload["trace_id"] == nil {
		t.Fatalf("expected decision/trace correlation in payload, got %+v", healthResp.Payload)
	}

	if err := conn.WriteJSON(openClawWSRequestFrame{
		Type:   "req",
		ID:     "devices-1",
		Method: "devices.list",
	}); err != nil {
		t.Fatalf("write devices.list frame: %v", err)
	}
	devicesResp := readWSResponse(t, conn)
	if !devicesResp.OK {
		t.Fatalf("expected devices.list success, got error=%+v", devicesResp.Error)
	}
}

func TestOpenClawWSGatewayProtocol_UnauthenticatedDenied(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	server := httptest.NewServer(gw.Handler())
	defer server.Close()

	_, resp, err := websocket.DefaultDialer.Dial(openClawWSURL(server.URL), nil)
	if err == nil {
		t.Fatal("expected websocket handshake failure without SPIFFE identity")
	}
	if resp == nil {
		t.Fatalf("expected HTTP response on failed handshake, got nil (err=%v)", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestOpenClawWSGatewayProtocol_AuthzAndMalformedDenied(t *testing.T) {
	t.Run("first request must be connect", func(t *testing.T) {
		gw, _ := newPhase3TestGateway(t)
		server := httptest.NewServer(gw.Handler())
		defer server.Close()

		headers := http.Header{}
		headers.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		conn, _, err := websocket.DefaultDialer.Dial(openClawWSURL(server.URL), headers)
		if err != nil {
			t.Fatalf("dial websocket failed: %v", err)
		}
		defer conn.Close()

		_ = conn.WriteJSON(openClawWSRequestFrame{
			Type:   "req",
			ID:     "health-before-connect",
			Method: "health",
		})
		denyResp := readWSResponse(t, conn)
		if denyResp.OK {
			t.Fatal("expected non-connect first request to be denied")
		}
		if denyResp.Error == nil || denyResp.Error.ReasonCode != reasonWSConnectRequired {
			t.Fatalf("expected reason %s, got %+v", reasonWSConnectRequired, denyResp.Error)
		}
	})

	t.Run("invalid connect role", func(t *testing.T) {
		gw, _ := newPhase3TestGateway(t)
		server := httptest.NewServer(gw.Handler())
		defer server.Close()

		headers := http.Header{}
		headers.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		conn, _, err := websocket.DefaultDialer.Dial(openClawWSURL(server.URL), headers)
		if err != nil {
			t.Fatalf("dial websocket failed: %v", err)
		}
		defer conn.Close()

		_ = conn.WriteJSON(openClawWSRequestFrame{
			Type:   "req",
			ID:     "connect-invalid-role",
			Method: "connect",
			Params: map[string]any{
				"role": "rogue",
			},
		})
		denyResp := readWSResponse(t, conn)
		if denyResp.OK {
			t.Fatal("expected invalid role to be denied")
		}
		if denyResp.Error == nil || denyResp.Error.ReasonCode != reasonWSAuthInvalid {
			t.Fatalf("expected reason %s, got %+v", reasonWSAuthInvalid, denyResp.Error)
		}
	})

	t.Run("forbidden method", func(t *testing.T) {
		gw, _ := newPhase3TestGateway(t)
		server := httptest.NewServer(gw.Handler())
		defer server.Close()

		headers := http.Header{}
		headers.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		conn, _, err := websocket.DefaultDialer.Dial(openClawWSURL(server.URL), headers)
		if err != nil {
			t.Fatalf("dial websocket failed: %v", err)
		}
		defer conn.Close()

		_ = conn.WriteJSON(openClawWSRequestFrame{
			Type:   "req",
			ID:     "connect-node",
			Method: "connect",
			Params: map[string]any{
				"role": "node",
			},
		})
		connectResp := readWSResponse(t, conn)
		if !connectResp.OK {
			t.Fatalf("expected connect success for node role, got error=%+v", connectResp.Error)
		}

		_ = conn.WriteJSON(openClawWSRequestFrame{
			Type:   "req",
			ID:     "forbidden-1",
			Method: "devices.list",
		})
		denyResp := readWSResponse(t, conn)
		if denyResp.OK {
			t.Fatal("expected devices.list denied for node without scope")
		}
		if denyResp.Error == nil || denyResp.Error.ReasonCode != reasonWSMethodForbidden {
			t.Fatalf("expected reason %s, got %+v", reasonWSMethodForbidden, denyResp.Error)
		}
	})

	t.Run("malformed payload", func(t *testing.T) {
		gw, _ := newPhase3TestGateway(t)
		server := httptest.NewServer(gw.Handler())
		defer server.Close()

		headers := http.Header{}
		headers.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		conn, _, err := websocket.DefaultDialer.Dial(openClawWSURL(server.URL), headers)
		if err != nil {
			t.Fatalf("dial websocket failed: %v", err)
		}
		defer conn.Close()

		_ = conn.WriteJSON(openClawWSRequestFrame{
			Type:   "req",
			ID:     "connect-op",
			Method: "connect",
			Params: map[string]any{
				"role": "operator",
			},
		})
		connectResp := readWSResponse(t, conn)
		if !connectResp.OK {
			t.Fatalf("expected connect success for operator role, got error=%+v", connectResp.Error)
		}

		_ = conn.WriteJSON(openClawWSRequestFrame{
			Type:   "req",
			ID:     "malformed-1",
			Method: "devices.ping",
			Params: map[string]any{},
		})
		denyResp := readWSResponse(t, conn)
		if denyResp.OK {
			t.Fatal("expected devices.ping with missing device_id to be denied")
		}
		if denyResp.Error == nil || denyResp.Error.ReasonCode != reasonWSPayloadMalformed {
			t.Fatalf("expected reason %s, got %+v", reasonWSPayloadMalformed, denyResp.Error)
		}
	})
}

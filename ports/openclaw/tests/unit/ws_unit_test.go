package unit

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/testutil"
	"github.com/precinct-dev/precinct/ports/openclaw"
	"github.com/gorilla/websocket"
)

type openClawWSRequestFrameIntegration struct {
	Type   string         `json:"type"`
	ID     string         `json:"id"`
	Method string         `json:"method"`
	Params map[string]any `json:"params,omitempty"`
}

type openClawWSErrorShapeIntegration struct {
	Code       string         `json:"code"`
	Message    string         `json:"message"`
	ReasonCode string         `json:"reason_code,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

type openClawWSResponseFrameIntegration struct {
	Type    string                           `json:"type"`
	ID      string                           `json:"id"`
	OK      bool                             `json:"ok"`
	Payload map[string]any                   `json:"payload,omitempty"`
	Error   *openClawWSErrorShapeIntegration `json:"error,omitempty"`
}

type openClawWSAuditRecord struct {
	Action     string `json:"action"`
	DecisionID string `json:"decision_id"`
	TraceID    string `json:"trace_id"`
	Result     string `json:"result"`
	Path       string `json:"path"`
}

type openClawWSTestEnv struct {
	server       *httptest.Server
	gateway      *gateway.Gateway
	auditLogPath string
}

func newOpenClawWSTestEnv(t *testing.T) *openClawWSTestEnv {
	t.Helper()

	tmpDir := t.TempDir()
	destinationsPath := filepath.Join(tmpDir, "destinations.yaml")
	if err := os.WriteFile(destinationsPath, []byte("allowed_destinations:\n  - \"127.0.0.1\"\n  - \"localhost\"\n  - \"::1\"\n"), 0644); err != nil {
		t.Fatalf("write destinations.yaml: %v", err)
	}

	auditLogPath := filepath.Join(tmpDir, "audit.log")
	cfg := &gateway.Config{
		Port:                   0,
		UpstreamURL:            "http://127.0.0.1:65535",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           auditLogPath,
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		RateLimitRPM:           100000,
		RateLimitBurst:         100000,
		SPIFFEMode:             "dev",
		DestinationsConfigPath: destinationsPath,
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("gateway.New failed: %v", err)
	}
	gw.RegisterPort(openclaw.NewAdapter(gw))

	server := httptest.NewServer(gw.Handler())
	t.Cleanup(func() {
		server.Close()
		_ = gw.Close()
	})

	return &openClawWSTestEnv{
		server:       server,
		gateway:      gw,
		auditLogPath: auditLogPath,
	}
}

func (e *openClawWSTestEnv) wsURL() string {
	return strings.Replace(e.server.URL, "http://", "ws://", 1) + "/openclaw/ws"
}

func readOpenClawWSResponseIntegration(t *testing.T, conn *websocket.Conn) openClawWSResponseFrameIntegration {
	t.Helper()
	var frame openClawWSResponseFrameIntegration
	if err := conn.ReadJSON(&frame); err != nil {
		t.Fatalf("read websocket response: %v", err)
	}
	return frame
}

func dialOpenClawWSIntegration(t *testing.T, wsURL, spiffeID string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	headers := http.Header{}
	if strings.TrimSpace(spiffeID) != "" {
		headers.Set("X-SPIFFE-ID", spiffeID)
	}
	return websocket.DefaultDialer.Dial(wsURL, headers)
}

func TestOpenClawWS_AuthenticatedSuccess_Integration(t *testing.T) {
	env := newOpenClawWSTestEnv(t)
	conn, resp, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial websocket failed (status=%d): %v", status, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type:   "req",
		ID:     "connect-1",
		Method: "connect",
		Params: map[string]any{
			"role":   "operator",
			"scopes": []string{"devices:read", "devices:write"},
		},
	}); err != nil {
		t.Fatalf("write connect frame: %v", err)
	}
	connectResp := readOpenClawWSResponseIntegration(t, conn)
	if !connectResp.OK {
		t.Fatalf("expected connect success, got error=%+v", connectResp.Error)
	}
	if connectResp.Payload["decision_id"] == nil || connectResp.Payload["trace_id"] == nil {
		t.Fatalf("expected connect correlation fields, got payload=%+v", connectResp.Payload)
	}

	if err := conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type:   "req",
		ID:     "ping-1",
		Method: "devices.ping",
		Params: map[string]any{"device_id": "device-alpha"},
	}); err != nil {
		t.Fatalf("write devices.ping frame: %v", err)
	}
	pingResp := readOpenClawWSResponseIntegration(t, conn)
	if !pingResp.OK {
		t.Fatalf("expected devices.ping success, got error=%+v", pingResp.Error)
	}
	if got, _ := pingResp.Payload["device_id"].(string); got != "device-alpha" {
		t.Fatalf("expected device_id=device-alpha, got %q", got)
	}
	if pingResp.Payload["decision_id"] == nil || pingResp.Payload["trace_id"] == nil {
		t.Fatalf("expected ping correlation fields, got payload=%+v", pingResp.Payload)
	}
}

func TestGatewayAuthz_OpenClawWSDenyMatrix_Integration(t *testing.T) {
	t.Run("unauthenticated handshake denied", func(t *testing.T) {
		env := newOpenClawWSTestEnv(t)
		_, resp, err := dialOpenClawWSIntegration(t, env.wsURL(), "")
		if err == nil {
			t.Fatal("expected handshake failure without SPIFFE identity")
		}
		if resp == nil || resp.StatusCode != http.StatusUnauthorized {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			t.Fatalf("expected 401 unauthorized, got %d", status)
		}
	})

	t.Run("node without device identity denied", func(t *testing.T) {
		env := newOpenClawWSTestEnv(t)
		conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		if err != nil {
			t.Fatalf("dial websocket failed: %v", err)
		}
		defer func() { _ = conn.Close() }()

		_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
			Type:   "req",
			ID:     "connect-node-no-device",
			Method: "connect",
			Params: map[string]any{"role": "node"},
		})
		denyResp := readOpenClawWSResponseIntegration(t, conn)
		if denyResp.OK {
			t.Fatal("expected node connect without device identity to be denied")
		}
		if denyResp.Error == nil || denyResp.Error.ReasonCode != "WS_DEVICE_REQUIRED" {
			t.Fatalf("expected WS_DEVICE_REQUIRED, got error=%+v", denyResp.Error)
		}
	})

	t.Run("node with device identity allowed", func(t *testing.T) {
		env := newOpenClawWSTestEnv(t)
		conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		if err != nil {
			t.Fatalf("dial websocket failed: %v", err)
		}
		defer func() { _ = conn.Close() }()

		_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
			Type:   "req",
			ID:     "connect-node-with-device",
			Method: "connect",
			Params: map[string]any{
				"role": "node",
				"device": map[string]any{
					"id": "device-integ-test",
				},
				"auth": map[string]any{
					"token": "tok-integ-test",
				},
			},
		})
		connectResp := readOpenClawWSResponseIntegration(t, conn)
		if !connectResp.OK {
			t.Fatalf("expected node connect with device identity to succeed, got error=%+v", connectResp.Error)
		}
		if connectResp.Payload == nil {
			t.Fatal("expected connect payload")
		}
		authBlock, _ := connectResp.Payload["auth"].(map[string]any)
		if authBlock == nil {
			t.Fatal("expected auth block in connect response")
		}
		if got, _ := authBlock["device"].(string); got != "device-integ-test" {
			t.Fatalf("expected device=device-integ-test in auth, got %q", got)
		}
	})

	t.Run("operator without device identity allowed", func(t *testing.T) {
		env := newOpenClawWSTestEnv(t)
		conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		if err != nil {
			t.Fatalf("dial websocket failed: %v", err)
		}
		defer func() { _ = conn.Close() }()

		_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
			Type:   "req",
			ID:     "connect-op-no-device",
			Method: "connect",
			Params: map[string]any{"role": "operator"},
		})
		connectResp := readOpenClawWSResponseIntegration(t, conn)
		if !connectResp.OK {
			t.Fatalf("expected operator connect without device identity to succeed, got error=%+v", connectResp.Error)
		}
	})

	t.Run("operator with device identity allowed", func(t *testing.T) {
		env := newOpenClawWSTestEnv(t)
		conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		if err != nil {
			t.Fatalf("dial websocket failed: %v", err)
		}
		defer func() { _ = conn.Close() }()

		_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
			Type:   "req",
			ID:     "connect-op-with-device",
			Method: "connect",
			Params: map[string]any{
				"role": "operator",
				"device": map[string]any{
					"id": "device-op-integ",
				},
				"auth": map[string]any{
					"token": "tok-op-integ",
				},
			},
		})
		connectResp := readOpenClawWSResponseIntegration(t, conn)
		if !connectResp.OK {
			t.Fatalf("expected operator connect with device identity to succeed, got error=%+v", connectResp.Error)
		}
	})

	t.Run("forbidden control method denied", func(t *testing.T) {
		env := newOpenClawWSTestEnv(t)
		conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		if err != nil {
			t.Fatalf("dial websocket failed: %v", err)
		}
		defer func() { _ = conn.Close() }()

		_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
			Type:   "req",
			ID:     "connect-node",
			Method: "connect",
			Params: map[string]any{
				"role": "node",
				"device": map[string]any{
					"id": "device-forbidden-test",
				},
				"auth": map[string]any{
					"token": "tok-forbidden-test",
				},
			},
		})
		connectResp := readOpenClawWSResponseIntegration(t, conn)
		if !connectResp.OK {
			t.Fatalf("expected node connect success, got error=%+v", connectResp.Error)
		}

		_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
			Type:   "req",
			ID:     "devices-list-deny",
			Method: "devices.list",
		})
		denyResp := readOpenClawWSResponseIntegration(t, conn)
		if denyResp.OK {
			t.Fatal("expected devices.list deny for node without scopes")
		}
		if denyResp.Error == nil || denyResp.Error.ReasonCode != "WS_METHOD_FORBIDDEN" {
			t.Fatalf("expected WS_METHOD_FORBIDDEN, got error=%+v", denyResp.Error)
		}
	})

	t.Run("message.send scope denied for node without scope", func(t *testing.T) {
		env := newOpenClawWSTestEnv(t)
		conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		if err != nil {
			t.Fatalf("dial websocket failed: %v", err)
		}
		defer func() { _ = conn.Close() }()

		_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
			Type: "req", ID: "connect-msg-deny", Method: "connect",
			Params: map[string]any{
				"role":   "node",
				"device": map[string]any{"id": "device-msg-deny"},
				"auth":   map[string]any{"token": "tok-msg-deny"},
			},
		})
		connectResp := readOpenClawWSResponseIntegration(t, conn)
		if !connectResp.OK {
			t.Fatalf("connect failed: %+v", connectResp.Error)
		}

		_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
			Type: "req", ID: "msg-send-deny", Method: "message.send",
			Params: map[string]any{
				"platform":  "whatsapp",
				"recipient": "+1234567890",
				"message":   "test",
			},
		})
		denyResp := readOpenClawWSResponseIntegration(t, conn)
		if denyResp.OK {
			t.Fatal("expected message.send deny for node without tools.messaging.send scope")
		}
		if denyResp.Error == nil || denyResp.Error.ReasonCode != "WS_METHOD_FORBIDDEN" {
			t.Fatalf("expected WS_METHOD_FORBIDDEN, got error=%+v", denyResp.Error)
		}
	})

	t.Run("malformed control payload denied", func(t *testing.T) {
		env := newOpenClawWSTestEnv(t)
		conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		if err != nil {
			t.Fatalf("dial websocket failed: %v", err)
		}
		defer func() { _ = conn.Close() }()

		_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
			Type:   "req",
			ID:     "connect-op",
			Method: "connect",
			Params: map[string]any{"role": "operator"},
		})
		connectResp := readOpenClawWSResponseIntegration(t, conn)
		if !connectResp.OK {
			t.Fatalf("expected operator connect success, got error=%+v", connectResp.Error)
		}

		_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
			Type:   "req",
			ID:     "malformed-ping",
			Method: "devices.ping",
			Params: map[string]any{},
		})
		denyResp := readOpenClawWSResponseIntegration(t, conn)
		if denyResp.OK {
			t.Fatal("expected malformed devices.ping deny")
		}
		if denyResp.Error == nil || denyResp.Error.ReasonCode != "WS_PAYLOAD_MALFORMED" {
			t.Fatalf("expected WS_PAYLOAD_MALFORMED, got error=%+v", denyResp.Error)
		}
	})
}

func TestAuditOpenClawWSCorrelation_Integration(t *testing.T) {
	t.Run("method forbidden audit", func(t *testing.T) {
		env := newOpenClawWSTestEnv(t)
		conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		if err != nil {
			t.Fatalf("dial websocket failed: %v", err)
		}

		_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
			Type:   "req",
			ID:     "connect-node",
			Method: "connect",
			Params: map[string]any{
				"role": "node",
				"device": map[string]any{
					"id": "device-audit-test",
				},
				"auth": map[string]any{
					"token": "tok-audit-test",
				},
			},
		})
		connectResp := readOpenClawWSResponseIntegration(t, conn)
		if !connectResp.OK {
			t.Fatalf("expected connect success, got error=%+v", connectResp.Error)
		}

		_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
			Type:   "req",
			ID:     "deny-devices-list",
			Method: "devices.list",
		})
		denyResp := readOpenClawWSResponseIntegration(t, conn)
		if denyResp.OK {
			t.Fatal("expected devices.list deny for node without scopes")
		}
		if denyResp.Error == nil {
			t.Fatalf("expected deny response with error payload, got %+v", denyResp)
		}
		_ = conn.Close()

		foundDenyEvent := false
		for i := 0; i < 30; i++ {
			file, err := os.Open(env.auditLogPath)
			if err == nil {
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" {
						continue
					}

					var record openClawWSAuditRecord
					if err := json.Unmarshal([]byte(line), &record); err != nil {
						continue
					}
					if record.Action != "openclaw.ws.devices.list" {
						continue
					}
					if record.DecisionID == "" || record.TraceID == "" {
						_ = file.Close()
						t.Fatalf("expected decision/trace IDs in audit record, got %+v", record)
					}
					if record.Path != "/openclaw/ws" {
						_ = file.Close()
						t.Fatalf("expected audit path /openclaw/ws, got %s", record.Path)
					}
					if !strings.Contains(record.Result, "reason_code=WS_METHOD_FORBIDDEN") {
						_ = file.Close()
						t.Fatalf("expected deny reason in audit result, got %q", record.Result)
					}
					foundDenyEvent = true
					break
				}
				_ = file.Close()
				if foundDenyEvent {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !foundDenyEvent {
			t.Fatalf("expected openclaw ws deny audit event in %s", env.auditLogPath)
		}
	})

	t.Run("device required audit", func(t *testing.T) {
		env := newOpenClawWSTestEnv(t)
		conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		if err != nil {
			t.Fatalf("dial websocket failed: %v", err)
		}

		_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
			Type:   "req",
			ID:     "connect-node-no-device-audit",
			Method: "connect",
			Params: map[string]any{"role": "node"},
		})
		denyResp := readOpenClawWSResponseIntegration(t, conn)
		if denyResp.OK {
			t.Fatal("expected node connect without device identity to be denied")
		}
		if denyResp.Error == nil || denyResp.Error.ReasonCode != "WS_DEVICE_REQUIRED" {
			t.Fatalf("expected WS_DEVICE_REQUIRED, got error=%+v", denyResp.Error)
		}
		_ = conn.Close()

		foundDeviceRequiredEvent := false
		for i := 0; i < 30; i++ {
			file, err := os.Open(env.auditLogPath)
			if err == nil {
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" {
						continue
					}

					var record openClawWSAuditRecord
					if err := json.Unmarshal([]byte(line), &record); err != nil {
						continue
					}
					if record.Action != "openclaw.ws.connect" {
						continue
					}
					if !strings.Contains(record.Result, "reason_code=WS_DEVICE_REQUIRED") {
						continue
					}
					if record.DecisionID == "" || record.TraceID == "" {
						_ = file.Close()
						t.Fatalf("expected decision/trace IDs in audit record, got %+v", record)
					}
					if record.Path != "/openclaw/ws" {
						_ = file.Close()
						t.Fatalf("expected audit path /openclaw/ws, got %s", record.Path)
					}
					foundDeviceRequiredEvent = true
					break
				}
				_ = file.Close()
				if foundDeviceRequiredEvent {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !foundDeviceRequiredEvent {
			t.Fatalf("expected openclaw ws device-required deny audit event in %s", env.auditLogPath)
		}
	})
}

// TestOpenClawWS_MessageSend_FullVerticalSlice exercises the complete path:
// WS frame -> port adapter -> OPA evaluation -> ExecuteMessagingEgress -> HTTP POST to messaging sim -> WS response
// This uses a real gateway, real OPA, and a real httptest messaging simulator. No mocks.
func TestOpenClawWS_MessageSend_FullVerticalSlice(t *testing.T) {
	// Start a real messaging simulator (httptest server with the same handler as cmd/messaging-sim).
	simMux := http.NewServeMux()
	simMux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"missing auth"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"messaging_product":"whatsapp","contacts":[{"input":"+1234567890","wa_id":"+1234567890"}],"messages":[{"id":"wamid.test123"}]}`))
	})
	simServer := httptest.NewServer(simMux)
	defer simServer.Close()

	// Set the env var so the gateway resolves WhatsApp endpoint to the simulator.
	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_WHATSAPP", simServer.URL+"/v1/messages")

	env := newOpenClawWSTestEnv(t)

	conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	if err != nil {
		t.Fatalf("dial websocket failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Connect as operator (has all permissions).
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "connect-msg-1", Method: "connect",
		Params: map[string]any{"role": "operator"},
	})
	connectResp := readOpenClawWSResponseIntegration(t, conn)
	if !connectResp.OK {
		t.Fatalf("connect failed: %+v", connectResp.Error)
	}

	// Send message.send frame with a plain auth token.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "msg-send-1", Method: "message.send",
		Params: map[string]any{
			"platform":  "whatsapp",
			"recipient": "+1234567890",
			"message":   "Hello from walking skeleton test",
			"auth_ref":  "my-api-key-12345",
		},
	})
	msgResp := readOpenClawWSResponseIntegration(t, conn)
	if !msgResp.OK {
		t.Fatalf("expected message.send success, got error=%+v", msgResp.Error)
	}
	messageID, _ := msgResp.Payload["message_id"].(string)
	if !strings.HasPrefix(messageID, "wamid.") {
		t.Fatalf("expected message_id starting with 'wamid.', got %q", messageID)
	}
	if got, _ := msgResp.Payload["platform"].(string); got != "whatsapp" {
		t.Fatalf("expected platform=whatsapp, got %q", got)
	}
	if msgResp.Payload["decision_id"] == nil || msgResp.Payload["trace_id"] == nil {
		t.Fatalf("expected correlation IDs, got payload=%+v", msgResp.Payload)
	}
}

// TestOpenClawWS_MessageSend_SPIKETokenResolution verifies per-message SPIKE token
// resolution: a $SPIKE{...} reference in auth_ref is resolved via the gateway's
// redeemer before being used as the Authorization header for the messaging egress.
func TestOpenClawWS_MessageSend_SPIKETokenResolution(t *testing.T) {
	// The simulator verifies that the Authorization header contains the resolved secret,
	// not the raw SPIKE token string.
	var receivedAuth string
	simMux := http.NewServeMux()
	simMux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"messaging_product":"whatsapp","contacts":[{"input":"+1","wa_id":"+1"}],"messages":[{"id":"wamid.spike-test"}]}`))
	})
	simServer := httptest.NewServer(simMux)
	defer simServer.Close()

	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_WHATSAPP", simServer.URL+"/v1/messages")

	env := newOpenClawWSTestEnv(t)

	conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	if err != nil {
		t.Fatalf("dial websocket failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "connect-spike", Method: "connect",
		Params: map[string]any{"role": "operator"},
	})
	connectResp := readOpenClawWSResponseIntegration(t, conn)
	if !connectResp.OK {
		t.Fatalf("connect failed: %+v", connectResp.Error)
	}

	// Send message.send with a SPIKE token reference.
	// The POCSecretRedeemer returns "secret-value-for-<ref>" for any ref.
	spikeToken := "$SPIKE{ref:7f3a9b2c,exp:3600,scope:tools.http.messaging}"
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "msg-spike-1", Method: "message.send",
		Params: map[string]any{
			"platform":  "whatsapp",
			"recipient": "+1",
			"message":   "SPIKE resolution test",
			"auth_ref":  spikeToken,
		},
	})
	msgResp := readOpenClawWSResponseIntegration(t, conn)
	if !msgResp.OK {
		t.Fatalf("expected message.send success with SPIKE token, got error=%+v", msgResp.Error)
	}

	// Verify the simulator received the RESOLVED secret, not the raw SPIKE token.
	expectedAuth := "Bearer secret-value-for-7f3a9b2c"
	if receivedAuth != expectedAuth {
		t.Fatalf("expected messaging-sim to receive auth=%q, got %q", expectedAuth, receivedAuth)
	}
}

// TestOpenClawWS_MessageSend_AllPlatformSPIKEReferences verifies that per-message
// SPIKE token resolution works for all three messaging platforms (WhatsApp, Telegram,
// Slack). Each platform uses a distinct hex reference (representing the seeded secret
// names whatsapp-api-key, telegram-bot-token, slack-bot-token in SPIKE Nexus).
// The POCSecretRedeemer returns "secret-value-for-<hex-ref>" generically, which the
// messaging simulator accepts as a valid Bearer token.
// RFA-ajf6: Proves AC5 (all three platform SPIKE references resolve correctly) and
// AC7 (unit test verifies all three platform SPIKE references resolve).
func TestOpenClawWS_MessageSend_AllPlatformSPIKEReferences(t *testing.T) {
	// Hex refs representing each platform's SPIKE secret. In production, these
	// hex refs map to named secrets (whatsapp-api-key, telegram-bot-token,
	// slack-bot-token) inside SPIKE Nexus. The POCSecretRedeemer resolves any
	// hex ref to "secret-value-for-<ref>".
	platforms := []struct {
		name        string
		hexRef      string
		envKey      string
		simEndpoint string
		simResponse string
		expectedID  string // prefix for message_id validation
	}{
		{
			name:        "whatsapp",
			hexRef:      "aa1100bb",
			envKey:      "MESSAGING_PLATFORM_ENDPOINT_WHATSAPP",
			simEndpoint: "/v1/messages",
			simResponse: `{"messaging_product":"whatsapp","contacts":[{"input":"+1","wa_id":"+1"}],"messages":[{"id":"wamid.wa-spike"}]}`,
			expectedID:  "wamid.",
		},
		{
			name:        "telegram",
			hexRef:      "cc2200dd",
			envKey:      "MESSAGING_PLATFORM_ENDPOINT_TELEGRAM",
			simEndpoint: "/v1/messages",
			simResponse: `{"ok":true,"result":{"message_id":42,"from":{"id":12345,"is_bot":true},"chat":{"id":67890},"date":1700000000,"text":"test"}}`,
			expectedID:  "42",
		},
		{
			name:        "slack",
			hexRef:      "ee3300ff",
			envKey:      "MESSAGING_PLATFORM_ENDPOINT_SLACK",
			simEndpoint: "/v1/messages",
			simResponse: `{"ok":true,"channel":"C123","ts":"1700000000.000001","message":{"text":"test","type":"message"}}`,
			expectedID:  "1700000000.",
		},
	}

	for _, plat := range platforms {
		t.Run(plat.name+"_spike_ref", func(t *testing.T) {
			// Track the auth header the simulator receives for this sub-test.
			var receivedAuth string
			simMux := http.NewServeMux()
			simMux.HandleFunc(plat.simEndpoint, func(w http.ResponseWriter, r *http.Request) {
				receivedAuth = r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(plat.simResponse))
			})
			simServer := httptest.NewServer(simMux)
			defer simServer.Close()

			t.Setenv(plat.envKey, simServer.URL+plat.simEndpoint)

			env := newOpenClawWSTestEnv(t)

			conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
			if err != nil {
				t.Fatalf("dial websocket failed: %v", err)
			}
			defer func() { _ = conn.Close() }()

			_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
				Type: "req", ID: "connect-" + plat.name, Method: "connect",
				Params: map[string]any{"role": "operator"},
			})
			connectResp := readOpenClawWSResponseIntegration(t, conn)
			if !connectResp.OK {
				t.Fatalf("connect failed: %+v", connectResp.Error)
			}

			// Build SPIKE token with platform-specific hex ref.
			spikeToken := "$SPIKE{ref:" + plat.hexRef + ",exp:3600,scope:tools.messaging.send}"
			_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
				Type: "req", ID: "msg-" + plat.name, Method: "message.send",
				Params: map[string]any{
					"platform":  plat.name,
					"recipient": "+1",
					"message":   "SPIKE " + plat.name + " resolution test",
					"auth_ref":  spikeToken,
				},
			})
			msgResp := readOpenClawWSResponseIntegration(t, conn)
			if !msgResp.OK {
				t.Fatalf("expected message.send success for %s with SPIKE token, got error=%+v", plat.name, msgResp.Error)
			}

			// Verify the simulator received the RESOLVED secret (not the raw $SPIKE{...} token).
			expectedAuth := "Bearer secret-value-for-" + plat.hexRef
			if receivedAuth != expectedAuth {
				t.Fatalf("[%s] expected auth=%q, got %q", plat.name, expectedAuth, receivedAuth)
			}

			// Verify response has a message_id.
			messageID, _ := msgResp.Payload["message_id"].(string)
			if !strings.HasPrefix(messageID, plat.expectedID) {
				t.Fatalf("[%s] expected message_id prefix %q, got %q", plat.name, plat.expectedID, messageID)
			}
		})
	}
}

// TestOpenClawWS_MessageStatus_Success verifies that an operator can call
// message.status and receive a simulated delivered status.
func TestOpenClawWS_MessageStatus_Success(t *testing.T) {
	env := newOpenClawWSTestEnv(t)
	conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	if err != nil {
		t.Fatalf("dial websocket failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Connect as operator.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "connect-status-1", Method: "connect",
		Params: map[string]any{"role": "operator"},
	})
	connectResp := readOpenClawWSResponseIntegration(t, conn)
	if !connectResp.OK {
		t.Fatalf("connect failed: %+v", connectResp.Error)
	}

	// Verify message.status is in the connect hello methods.
	features, _ := connectResp.Payload["features"].(map[string]any)
	if features == nil {
		t.Fatal("expected features in connect response")
	}
	methodsRaw, _ := features["methods"].([]any)
	foundMessageStatus := false
	for _, m := range methodsRaw {
		if s, ok := m.(string); ok && s == "message.status" {
			foundMessageStatus = true
			break
		}
	}
	if !foundMessageStatus {
		t.Fatalf("expected message.status in features.methods, got %v", methodsRaw)
	}

	// Send message.status frame.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "msg-status-1", Method: "message.status",
		Params: map[string]any{
			"platform":   "whatsapp",
			"message_id": "wamid.abc123",
		},
	})
	statusResp := readOpenClawWSResponseIntegration(t, conn)
	if !statusResp.OK {
		t.Fatalf("expected message.status success, got error=%+v", statusResp.Error)
	}
	if got, _ := statusResp.Payload["platform"].(string); got != "whatsapp" {
		t.Fatalf("expected platform=whatsapp, got %q", got)
	}
	if got, _ := statusResp.Payload["message_id"].(string); got != "wamid.abc123" {
		t.Fatalf("expected message_id=wamid.abc123, got %q", got)
	}
	if got, _ := statusResp.Payload["status"].(string); got != "delivered" {
		t.Fatalf("expected status=delivered, got %q", got)
	}
	if statusResp.Payload["timestamp"] == nil {
		t.Fatal("expected timestamp in message.status response")
	}
	if statusResp.Payload["decision_id"] == nil || statusResp.Payload["trace_id"] == nil {
		t.Fatalf("expected correlation IDs, got payload=%+v", statusResp.Payload)
	}
}

// TestOpenClawWS_MessageStatus_ScopeDenied verifies that a node without the
// tools.messaging.status scope is denied access to message.status.
func TestOpenClawWS_MessageStatus_ScopeDenied(t *testing.T) {
	env := newOpenClawWSTestEnv(t)
	conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	if err != nil {
		t.Fatalf("dial websocket failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Connect as node WITHOUT tools.messaging.status scope.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "connect-status-deny", Method: "connect",
		Params: map[string]any{
			"role":   "node",
			"device": map[string]any{"id": "device-status-deny"},
			"auth":   map[string]any{"token": "tok-status-deny"},
			"scopes": []string{"devices:read"},
		},
	})
	connectResp := readOpenClawWSResponseIntegration(t, conn)
	if !connectResp.OK {
		t.Fatalf("connect failed: %+v", connectResp.Error)
	}

	// Attempt message.status -- should be denied.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "msg-status-deny-1", Method: "message.status",
		Params: map[string]any{
			"platform":   "whatsapp",
			"message_id": "wamid.abc123",
		},
	})
	denyResp := readOpenClawWSResponseIntegration(t, conn)
	if denyResp.OK {
		t.Fatal("expected message.status deny for node without tools.messaging.status scope")
	}
	if denyResp.Error == nil || denyResp.Error.ReasonCode != "WS_METHOD_FORBIDDEN" {
		t.Fatalf("expected WS_METHOD_FORBIDDEN, got error=%+v", denyResp.Error)
	}
}

// TestOpenClawWS_MessageStatus_NodeWithScope verifies that a node WITH
// the tools.messaging.status scope can call message.status.
func TestOpenClawWS_MessageStatus_NodeWithScope(t *testing.T) {
	env := newOpenClawWSTestEnv(t)
	conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	if err != nil {
		t.Fatalf("dial websocket failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Connect as node WITH tools.messaging.status scope.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "connect-status-scoped", Method: "connect",
		Params: map[string]any{
			"role":   "node",
			"device": map[string]any{"id": "device-status-scoped"},
			"auth":   map[string]any{"token": "tok-status-scoped"},
			"scopes": []string{"tools.messaging.status"},
		},
	})
	connectResp := readOpenClawWSResponseIntegration(t, conn)
	if !connectResp.OK {
		t.Fatalf("connect failed: %+v", connectResp.Error)
	}

	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "msg-status-scoped-1", Method: "message.status",
		Params: map[string]any{
			"platform":   "whatsapp",
			"message_id": "wamid.scoped123",
		},
	})
	statusResp := readOpenClawWSResponseIntegration(t, conn)
	if !statusResp.OK {
		t.Fatalf("expected message.status success for node with scope, got error=%+v", statusResp.Error)
	}
	if got, _ := statusResp.Payload["status"].(string); got != "delivered" {
		t.Fatalf("expected status=delivered, got %q", got)
	}
}

// TestOpenClawWS_ConnectorRegister_Success verifies that an operator can call
// connector.register and receive a registration acknowledgment.
func TestOpenClawWS_ConnectorRegister_Success(t *testing.T) {
	env := newOpenClawWSTestEnv(t)
	conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	if err != nil {
		t.Fatalf("dial websocket failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Connect as operator.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "connect-reg-1", Method: "connect",
		Params: map[string]any{"role": "operator"},
	})
	connectResp := readOpenClawWSResponseIntegration(t, conn)
	if !connectResp.OK {
		t.Fatalf("connect failed: %+v", connectResp.Error)
	}

	// Verify connector.register is in the connect hello methods.
	features, _ := connectResp.Payload["features"].(map[string]any)
	if features == nil {
		t.Fatal("expected features in connect response")
	}
	methodsRaw, _ := features["methods"].([]any)
	foundConnectorRegister := false
	for _, m := range methodsRaw {
		if s, ok := m.(string); ok && s == "connector.register" {
			foundConnectorRegister = true
			break
		}
	}
	if !foundConnectorRegister {
		t.Fatalf("expected connector.register in features.methods, got %v", methodsRaw)
	}

	// Send connector.register frame.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "conn-reg-1", Method: "connector.register",
		Params: map[string]any{
			"connector_id": "whatsapp-prod-01",
			"platform":     "whatsapp",
		},
	})
	regResp := readOpenClawWSResponseIntegration(t, conn)
	if !regResp.OK {
		t.Fatalf("expected connector.register success, got error=%+v", regResp.Error)
	}
	if got, _ := regResp.Payload["connector_id"].(string); got != "whatsapp-prod-01" {
		t.Fatalf("expected connector_id=whatsapp-prod-01, got %q", got)
	}
	if got, _ := regResp.Payload["platform"].(string); got != "whatsapp" {
		t.Fatalf("expected platform=whatsapp, got %q", got)
	}
	if got, _ := regResp.Payload["status"].(string); got != "registered" {
		t.Fatalf("expected status=registered, got %q", got)
	}
	if regResp.Payload["decision_id"] == nil || regResp.Payload["trace_id"] == nil {
		t.Fatalf("expected correlation IDs, got payload=%+v", regResp.Payload)
	}
}

// TestOpenClawWS_ConnectorRegister_NodeDenied verifies that a node (non-operator)
// is denied access to connector.register regardless of scopes.
func TestOpenClawWS_ConnectorRegister_NodeDenied(t *testing.T) {
	env := newOpenClawWSTestEnv(t)
	conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	if err != nil {
		t.Fatalf("dial websocket failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Connect as node with all possible scopes -- connector.register is operator-only.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "connect-reg-deny", Method: "connect",
		Params: map[string]any{
			"role":   "node",
			"device": map[string]any{"id": "device-reg-deny"},
			"auth":   map[string]any{"token": "tok-reg-deny"},
			"scopes": []string{"devices:read", "devices:write", "tools.messaging.send", "tools.messaging.status"},
		},
	})
	connectResp := readOpenClawWSResponseIntegration(t, conn)
	if !connectResp.OK {
		t.Fatalf("connect failed: %+v", connectResp.Error)
	}

	// Verify connector.register is NOT in the connect hello methods for a node.
	features, _ := connectResp.Payload["features"].(map[string]any)
	if features != nil {
		methodsRaw, _ := features["methods"].([]any)
		for _, m := range methodsRaw {
			if s, ok := m.(string); ok && s == "connector.register" {
				t.Fatal("expected connector.register NOT to be in features.methods for node role")
			}
		}
	}

	// Attempt connector.register -- should be denied.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "conn-reg-deny-1", Method: "connector.register",
		Params: map[string]any{
			"connector_id": "whatsapp-prod-02",
			"platform":     "whatsapp",
		},
	})
	denyResp := readOpenClawWSResponseIntegration(t, conn)
	if denyResp.OK {
		t.Fatal("expected connector.register deny for node")
	}
	if denyResp.Error == nil || denyResp.Error.ReasonCode != "WS_METHOD_FORBIDDEN" {
		t.Fatalf("expected WS_METHOD_FORBIDDEN, got error=%+v", denyResp.Error)
	}
}

// TestOpenClawWS_MessageStatus_MissingParams verifies that message.status with
// missing required parameters returns a payload malformed error.
func TestOpenClawWS_MessageStatus_MissingParams(t *testing.T) {
	env := newOpenClawWSTestEnv(t)
	conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	if err != nil {
		t.Fatalf("dial websocket failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "connect-mp", Method: "connect",
		Params: map[string]any{"role": "operator"},
	})
	connectResp := readOpenClawWSResponseIntegration(t, conn)
	if !connectResp.OK {
		t.Fatalf("connect failed: %+v", connectResp.Error)
	}

	// Missing message_id.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "msg-status-mp-1", Method: "message.status",
		Params: map[string]any{"platform": "whatsapp"},
	})
	denyResp := readOpenClawWSResponseIntegration(t, conn)
	if denyResp.OK {
		t.Fatal("expected message.status deny for missing message_id")
	}
	if denyResp.Error == nil || denyResp.Error.ReasonCode != "WS_PAYLOAD_MALFORMED" {
		t.Fatalf("expected WS_PAYLOAD_MALFORMED, got error=%+v", denyResp.Error)
	}
}

// TestOpenClawWS_ConnectorRegister_MissingParams verifies that connector.register
// with missing required parameters returns a payload malformed error.
func TestOpenClawWS_ConnectorRegister_MissingParams(t *testing.T) {
	env := newOpenClawWSTestEnv(t)
	conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	if err != nil {
		t.Fatalf("dial websocket failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "connect-crmp", Method: "connect",
		Params: map[string]any{"role": "operator"},
	})
	connectResp := readOpenClawWSResponseIntegration(t, conn)
	if !connectResp.OK {
		t.Fatalf("connect failed: %+v", connectResp.Error)
	}

	// Missing platform.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "conn-reg-mp-1", Method: "connector.register",
		Params: map[string]any{"connector_id": "test-conn"},
	})
	denyResp := readOpenClawWSResponseIntegration(t, conn)
	if denyResp.OK {
		t.Fatal("expected connector.register deny for missing platform")
	}
	if denyResp.Error == nil || denyResp.Error.ReasonCode != "WS_PAYLOAD_MALFORMED" {
		t.Fatalf("expected WS_PAYLOAD_MALFORMED, got error=%+v", denyResp.Error)
	}
}

// TestOpenClawWS_ResolveSPIKERef_EmptyFallback verifies that sending message.send
// without auth_ref falls back to the upgrade-time Authorization header.
func TestOpenClawWS_ResolveSPIKERef_EmptyFallback(t *testing.T) {
	// Simulator captures the Authorization header it receives.
	var receivedAuth string
	simMux := http.NewServeMux()
	simMux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"messaging_product":"whatsapp","contacts":[{"input":"+1","wa_id":"+1"}],"messages":[{"id":"wamid.fallback-test"}]}`))
	})
	simServer := httptest.NewServer(simMux)
	defer simServer.Close()

	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_WHATSAPP", simServer.URL+"/v1/messages")

	env := newOpenClawWSTestEnv(t)

	// Dial with an Authorization header set on the upgrade request.
	headers := http.Header{}
	headers.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	headers.Set("Authorization", "Bearer fallback-upgrade-token")
	conn, _, err := websocket.DefaultDialer.Dial(env.wsURL(), headers)
	if err != nil {
		t.Fatalf("dial websocket failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "connect-fb", Method: "connect",
		Params: map[string]any{"role": "operator"},
	})
	connectResp := readOpenClawWSResponseIntegration(t, conn)
	if !connectResp.OK {
		t.Fatalf("connect failed: %+v", connectResp.Error)
	}

	// Send message.send WITHOUT auth_ref -- should fall back to upgrade header.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "msg-fb-1", Method: "message.send",
		Params: map[string]any{
			"platform":  "whatsapp",
			"recipient": "+1",
			"message":   "fallback test",
		},
	})
	msgResp := readOpenClawWSResponseIntegration(t, conn)
	if !msgResp.OK {
		t.Fatalf("expected message.send success, got error=%+v", msgResp.Error)
	}

	if receivedAuth != "Bearer fallback-upgrade-token" {
		t.Fatalf("expected messaging-sim to receive fallback auth=%q, got %q", "Bearer fallback-upgrade-token", receivedAuth)
	}
}

// TestOpenClawWS_ResolveSPIKERef_NonSPIKEPassthrough verifies that a non-SPIKE
// auth_ref value is passed through as a Bearer token.
func TestOpenClawWS_ResolveSPIKERef_NonSPIKEPassthrough(t *testing.T) {
	var receivedAuth string
	simMux := http.NewServeMux()
	simMux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"messaging_product":"whatsapp","contacts":[{"input":"+1","wa_id":"+1"}],"messages":[{"id":"wamid.plain-test"}]}`))
	})
	simServer := httptest.NewServer(simMux)
	defer simServer.Close()

	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_WHATSAPP", simServer.URL+"/v1/messages")

	env := newOpenClawWSTestEnv(t)
	conn, _, err := dialOpenClawWSIntegration(t, env.wsURL(), "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	if err != nil {
		t.Fatalf("dial websocket failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "connect-pt", Method: "connect",
		Params: map[string]any{"role": "operator"},
	})
	connectResp := readOpenClawWSResponseIntegration(t, conn)
	if !connectResp.OK {
		t.Fatalf("connect failed: %+v", connectResp.Error)
	}

	// Send message.send with a plain (non-SPIKE) auth_ref.
	_ = conn.WriteJSON(openClawWSRequestFrameIntegration{
		Type: "req", ID: "msg-pt-1", Method: "message.send",
		Params: map[string]any{
			"platform":  "whatsapp",
			"recipient": "+1",
			"message":   "passthrough test",
			"auth_ref":  "my-plain-api-key",
		},
	})
	msgResp := readOpenClawWSResponseIntegration(t, conn)
	if !msgResp.OK {
		t.Fatalf("expected message.send success, got error=%+v", msgResp.Error)
	}

	expectedAuth := "Bearer my-plain-api-key"
	if receivedAuth != expectedAuth {
		t.Fatalf("expected messaging-sim to receive auth=%q, got %q", expectedAuth, receivedAuth)
	}
}

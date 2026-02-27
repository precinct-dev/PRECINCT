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

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway"
	"github.com/RamXX/agentic_reference_architecture/POC/internal/testutil"
	"github.com/RamXX/agentic_reference_architecture/POC/ports/openclaw"
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

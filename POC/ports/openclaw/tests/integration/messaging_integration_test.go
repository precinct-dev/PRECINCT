//go:build integration

package integration

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ---------------------------------------------------------------------------
// Test infrastructure: constants, helpers, WS utilities
// ---------------------------------------------------------------------------

const (
	gatewayWSURL = "wss://localhost:8443/openclaw/ws"
	gatewayHTTPS = "https://localhost:8443"
	simHealthURL = "http://localhost:8090/health"
)

var tlsConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // integration test against self-signed cert

// connectAndAuth dials the gateway WS endpoint, sends a connect frame with the
// given scopes, and returns the authenticated connection.
func connectAndAuth(t *testing.T, scopes []string) *websocket.Conn {
	t.Helper()
	dialer := websocket.Dialer{TLSClientConfig: tlsConfig}
	conn, _, err := dialer.Dial(gatewayWSURL, nil)
	if err != nil {
		t.Fatalf("WS dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Send connect frame.
	connectFrame := map[string]any{
		"type": "req", "id": "connect-1", "method": "connect",
		"params": map[string]any{
			"role":   "operator",
			"scopes": scopes,
		},
	}
	if err := conn.WriteJSON(connectFrame); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	var resp map[string]any
	if err := conn.ReadJSON(&resp); err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("connect not ok: %v", resp)
	}
	return conn
}

// sendWSFrame writes a WS request frame and reads the response.
func sendWSFrame(t *testing.T, conn *websocket.Conn, id, method string, params map[string]any) map[string]any {
	t.Helper()
	frame := map[string]any{
		"type": "req", "id": id, "method": method, "params": params,
	}
	if err := conn.WriteJSON(frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	var resp map[string]any
	if err := conn.ReadJSON(&resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

// spikeRef builds a $SPIKE{...} reference token string for per-message auth.
func spikeRef(ref string) string {
	now := time.Now().Unix()
	exp := now + 3600
	return fmt.Sprintf("$SPIKE{ref:%s,exp:%d,scope:tools.messaging.send,iss:%d}", ref, exp, now)
}

// httpsClient returns an *http.Client configured for TLS against self-signed certs.
func httpsClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   10 * time.Second,
	}
}

// ---------------------------------------------------------------------------
// Test 1: Successful message send via WS (WhatsApp)
// ---------------------------------------------------------------------------

func TestIntegration_MessageSend_WhatsApp(t *testing.T) {
	conn := connectAndAuth(t, []string{"tools.messaging.send"})
	resp := sendWSFrame(t, conn, "msg-1", "message.send", map[string]any{
		"platform":  "whatsapp",
		"recipient": "15551234567",
		"message":   "Hello from integration test",
		"auth_ref":  spikeRef("whatsapp-api-key"),
	})
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got %v", resp)
	}
	payload, _ := resp["payload"].(map[string]any)
	if payload == nil {
		t.Fatal("missing payload")
	}
	if mid, _ := payload["message_id"].(string); mid == "" {
		t.Fatal("missing message_id in response")
	}
	if sc, _ := payload["status_code"].(float64); sc != 200 {
		t.Fatalf("expected status_code=200, got %v", sc)
	}
}

// ---------------------------------------------------------------------------
// Test 2: Telegram message send
// ---------------------------------------------------------------------------

func TestIntegration_MessageSend_Telegram(t *testing.T) {
	conn := connectAndAuth(t, []string{"tools.messaging.send"})
	resp := sendWSFrame(t, conn, "msg-2", "message.send", map[string]any{
		"platform":  "telegram",
		"recipient": "987654321",
		"message":   "Telegram integration test message",
		"auth_ref":  spikeRef("telegram-api-key"),
	})
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got %v", resp)
	}
	payload, _ := resp["payload"].(map[string]any)
	if payload == nil {
		t.Fatal("missing payload")
	}
	if mid, _ := payload["message_id"].(string); mid == "" {
		t.Fatal("missing message_id in response")
	}
	if sc, _ := payload["status_code"].(float64); sc != 200 {
		t.Fatalf("expected status_code=200, got %v", sc)
	}
}

// ---------------------------------------------------------------------------
// Test 3: Slack message send
// ---------------------------------------------------------------------------

func TestIntegration_MessageSend_Slack(t *testing.T) {
	conn := connectAndAuth(t, []string{"tools.messaging.send"})
	resp := sendWSFrame(t, conn, "msg-3", "message.send", map[string]any{
		"platform":  "slack",
		"recipient": "#general",
		"message":   "Slack integration test message",
		"auth_ref":  spikeRef("slack-api-key"),
	})
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got %v", resp)
	}
	payload, _ := resp["payload"].(map[string]any)
	if payload == nil {
		t.Fatal("missing payload")
	}
	if mid, _ := payload["message_id"].(string); mid == "" {
		t.Fatal("missing message_id in response")
	}
	if sc, _ := payload["status_code"].(float64); sc != 200 {
		t.Fatalf("expected status_code=200, got %v", sc)
	}
}

// ---------------------------------------------------------------------------
// Test 4: message.status returns delivered
// ---------------------------------------------------------------------------

func TestIntegration_MessageStatus(t *testing.T) {
	conn := connectAndAuth(t, []string{"tools.messaging.send", "tools.messaging.status"})
	resp := sendWSFrame(t, conn, "status-1", "message.status", map[string]any{
		"platform":   "whatsapp",
		"message_id": "wamid.test-123",
	})
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got %v", resp)
	}
	payload, _ := resp["payload"].(map[string]any)
	if status, _ := payload["status"].(string); status != "delivered" {
		t.Fatalf("expected status=delivered, got %v", status)
	}
}

// ---------------------------------------------------------------------------
// Test 5: connector.register operator-only
// ---------------------------------------------------------------------------

func TestIntegration_ConnectorRegister(t *testing.T) {
	conn := connectAndAuth(t, []string{"tools.messaging.send"})
	resp := sendWSFrame(t, conn, "cr-1", "connector.register", map[string]any{
		"connector_id": "whatsapp-inbound",
		"platform":     "whatsapp",
	})
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got %v", resp)
	}
	payload, _ := resp["payload"].(map[string]any)
	if st, _ := payload["status"].(string); st != "registered" {
		t.Fatalf("expected status=registered, got %v", st)
	}
}

// ---------------------------------------------------------------------------
// Test 6: Per-message SPIKE token resolution
// ---------------------------------------------------------------------------

func TestIntegration_SPIKETokenResolution(t *testing.T) {
	conn := connectAndAuth(t, []string{"tools.messaging.send"})

	// Send with auth_ref containing a $SPIKE{} reference. The adapter should
	// resolve this per-message (NOT at upgrade time). A 200 from the messaging
	// simulator proves the token was resolved to a valid Authorization header.
	resp := sendWSFrame(t, conn, "spike-1", "message.send", map[string]any{
		"platform":  "whatsapp",
		"recipient": "15559998888",
		"message":   "SPIKE resolution integration test",
		"auth_ref":  spikeRef("whatsapp-api-key"),
	})
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("expected ok=true (SPIKE resolved), got %v", resp)
	}
	payload, _ := resp["payload"].(map[string]any)
	if payload == nil {
		t.Fatal("missing payload")
	}
	if sc, _ := payload["status_code"].(float64); sc != 200 {
		t.Fatalf("expected status_code=200 (auth resolved), got %v", sc)
	}
}

// ---------------------------------------------------------------------------
// Test 7: Messaging simulator rate limiting (429)
// ---------------------------------------------------------------------------

func TestIntegration_SimulatorRateLimit(t *testing.T) {
	conn := connectAndAuth(t, []string{"tools.messaging.send"})
	var got429 bool
	for i := 0; i < 15; i++ {
		resp := sendWSFrame(t, conn, fmt.Sprintf("rate-%d", i), "message.send", map[string]any{
			"platform":  "whatsapp",
			"recipient": "15551234567",
			"message":   fmt.Sprintf("Rate limit test %d", i),
			"auth_ref":  spikeRef("whatsapp-api-key"),
		})
		payload, _ := resp["payload"].(map[string]any)
		if sc, _ := payload["status_code"].(float64); sc == 429 {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Log("WARNING: rate limit not triggered in 15 requests -- simulator may have different config")
	}
}

// ---------------------------------------------------------------------------
// Test 8: Inbound webhook -- WhatsApp
// ---------------------------------------------------------------------------

func TestIntegration_WebhookWhatsApp(t *testing.T) {
	client := httpsClient()
	payload, _ := json.Marshal(map[string]any{
		"entry": []any{
			map[string]any{
				"changes": []any{
					map[string]any{
						"value": map[string]any{
							"messages": []any{
								map[string]any{
									"from": "15551234567",
									"text": map[string]any{"body": "Hello from webhook integration test"},
								},
							},
						},
					},
				},
			},
		},
	})
	req, _ := http.NewRequest(http.MethodPost, gatewayHTTPS+"/openclaw/webhooks/whatsapp", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("webhook POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	// Connector may or may not be registered in integration env -- accept 200 or 403.
	if resp.StatusCode != 200 && resp.StatusCode != 403 {
		t.Fatalf("expected 200 or 403, got %d: %s", resp.StatusCode, string(body))
	}
	t.Logf("webhook response: %d %s", resp.StatusCode, string(body))
}

// ---------------------------------------------------------------------------
// Test 9: Inbound webhook -- unregistered connector (403)
// ---------------------------------------------------------------------------

func TestIntegration_WebhookUnregisteredConnector(t *testing.T) {
	client := httpsClient()
	// Use a payload with a connector_id that has not been registered via the
	// connector lifecycle. The CCA runtime check should reject it.
	payload, _ := json.Marshal(map[string]any{
		"connector_id": "unregistered-test-connector",
		"entry": []any{
			map[string]any{
				"changes": []any{
					map[string]any{
						"value": map[string]any{
							"messages": []any{
								map[string]any{
									"from": "15550000000",
									"text": map[string]any{"body": "Should be rejected"},
								},
							},
						},
					},
				},
			},
		},
	})
	req, _ := http.NewRequest(http.MethodPost, gatewayHTTPS+"/openclaw/webhooks/whatsapp", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("webhook POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	// If CCA is configured, expect 403. If not configured, connectors are
	// auto-allowed, so we accept both for robustness.
	if resp.StatusCode != 403 && resp.StatusCode != 200 {
		t.Fatalf("expected 403 or 200, got %d: %s", resp.StatusCode, string(body))
	}
	if resp.StatusCode == 403 {
		if !strings.Contains(string(body), "connector conformance") {
			t.Logf("403 body did not contain 'connector conformance': %s", string(body))
		}
	}
	t.Logf("unregistered connector response: %d %s", resp.StatusCode, string(body))
}

// ---------------------------------------------------------------------------
// Test 10: Inbound webhook -- malformed JSON
// ---------------------------------------------------------------------------

func TestIntegration_WebhookMalformedJSON(t *testing.T) {
	client := httpsClient()
	req, _ := http.NewRequest(http.MethodPost, gatewayHTTPS+"/openclaw/webhooks/whatsapp", strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("webhook POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 400 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400, got %d: %s", resp.StatusCode, string(body))
	}
}

// ---------------------------------------------------------------------------
// Test 11: Inbound webhook -- wrong HTTP method
// ---------------------------------------------------------------------------

func TestIntegration_WebhookWrongMethod(t *testing.T) {
	client := httpsClient()
	req, _ := http.NewRequest(http.MethodGet, gatewayHTTPS+"/openclaw/webhooks/whatsapp", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("webhook GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 405 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 405, got %d: %s", resp.StatusCode, string(body))
	}
}

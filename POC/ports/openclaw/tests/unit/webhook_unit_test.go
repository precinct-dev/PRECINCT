package unit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway"
	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
	"github.com/RamXX/agentic_reference_architecture/POC/ports/openclaw"
)

// mockWebhookGatewayServices implements gateway.PortGatewayServices for webhook unit tests.
// Only ValidateConnector and WriteGatewayError are exercised; others panic if called.
type mockWebhookGatewayServices struct {
	validateConnectorFunc func(connectorID, signature string) (bool, string)
	writeGatewayErrorFunc func(w http.ResponseWriter, r *http.Request, httpCode int, errorCode string, message string, middlewareName string, reason gateway.ReasonCode, details map[string]any)
}

func (m *mockWebhookGatewayServices) ValidateConnector(connectorID, signature string) (bool, string) {
	if m.validateConnectorFunc != nil {
		return m.validateConnectorFunc(connectorID, signature)
	}
	return true, "mock_allow"
}

func (m *mockWebhookGatewayServices) WriteGatewayError(w http.ResponseWriter, r *http.Request, httpCode int, errorCode string, message string, middlewareName string, reason gateway.ReasonCode, details map[string]any) {
	if m.writeGatewayErrorFunc != nil {
		m.writeGatewayErrorFunc(w, r, httpCode, errorCode, message, middlewareName, reason, details)
		return
	}
	// Default: write structured JSON error matching gateway error envelope shape.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error_code": errorCode,
		"message":    message,
		"middleware": middlewareName,
		"reason":     string(reason),
		"details":    details,
	})
}

// Unused interface methods -- panic if called so test fails loudly.
func (m *mockWebhookGatewayServices) BuildModelPlaneRequest(_ *http.Request, _ map[string]any) gateway.PlaneRequestV2 {
	panic("BuildModelPlaneRequest not expected in webhook unit tests")
}
func (m *mockWebhookGatewayServices) EvaluateModelPlaneDecision(_ *http.Request, _ gateway.PlaneRequestV2) (gateway.Decision, gateway.ReasonCode, int, map[string]any) {
	panic("EvaluateModelPlaneDecision not expected in webhook unit tests")
}
func (m *mockWebhookGatewayServices) ExecuteModelEgress(_ context.Context, _ map[string]any, _ map[string]any, _ string) (*gateway.ModelEgressResult, error) {
	panic("ExecuteModelEgress not expected in webhook unit tests")
}
func (m *mockWebhookGatewayServices) ShouldApplyPolicyIntentProjection() bool {
	panic("ShouldApplyPolicyIntentProjection not expected in webhook unit tests")
}
func (m *mockWebhookGatewayServices) EvaluateToolRequest(_ gateway.PlaneRequestV2) gateway.ToolPlaneEvalResult {
	panic("EvaluateToolRequest not expected in webhook unit tests")
}
func (m *mockWebhookGatewayServices) ExecuteMessagingEgress(_ context.Context, _ map[string]string, _ []byte, _ string) (*gateway.MessagingEgressResult, error) {
	panic("ExecuteMessagingEgress not expected in webhook unit tests")
}
func (m *mockWebhookGatewayServices) RedeemSPIKESecret(_ context.Context, _ string) (string, error) {
	panic("RedeemSPIKESecret not expected in webhook unit tests")
}
func (m *mockWebhookGatewayServices) LogPlaneDecision(_ *http.Request, _ gateway.PlaneDecisionV2, _ int) {
	// no-op for unit tests
}
func (m *mockWebhookGatewayServices) AuditLog(_ middleware.AuditEvent) {
	// no-op for unit tests
}
func (m *mockWebhookGatewayServices) ValidateAndConsumeApproval(_ string, _ middleware.ApprovalScope) (*middleware.ApprovalCapabilityClaims, error) {
	panic("ValidateAndConsumeApproval not expected in webhook unit tests")
}
func (m *mockWebhookGatewayServices) HasApprovalService() bool {
	return false
}

// Compile-time check that mock satisfies the interface.
var _ gateway.PortGatewayServices = (*mockWebhookGatewayServices)(nil)

// newWebhookTestAdapter creates an adapter with a mock gateway and a loopback URL
// pointing to the given loopback server (or empty string for tests that don't need it).
func newWebhookTestAdapter(mock *mockWebhookGatewayServices, loopbackURL string) *openclaw.Adapter {
	if loopbackURL != "" {
		// Set env var before NewAdapter reads it.
		// Callers must use t.Setenv for proper cleanup.
		return openclaw.NewAdapterWithLoopbackURL(mock, loopbackURL)
	}
	return openclaw.NewAdapterWithLoopbackURL(mock, "http://127.0.0.1:1") // unreachable, for tests that never reach loopback
}

// --- Test helpers ---

func whatsappPayload(content, sender string) map[string]any {
	return map[string]any{
		"entry": []any{
			map[string]any{
				"changes": []any{
					map[string]any{
						"value": map[string]any{
							"messages": []any{
								map[string]any{
									"from": sender,
									"text": map[string]any{
										"body": content,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func telegramPayload(content, sender string) map[string]any {
	return map[string]any{
		"message": map[string]any{
			"text": content,
			"from": map[string]any{
				"username": sender,
			},
		},
	}
}

func slackPayload(content, sender string) map[string]any {
	return map[string]any{
		"event": map[string]any{
			"text": content,
			"user": sender,
		},
	}
}

func postWebhook(t *testing.T, adapter *openclaw.Adapter, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	} else {
		bodyReader = strings.NewReader("")
	}

	req := httptest.NewRequest(http.MethodPost, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	adapter.TryServeHTTP(rec, req)
	return rec
}

func getWebhook(t *testing.T, adapter *openclaw.Adapter, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	adapter.TryServeHTTP(rec, req)
	return rec
}

// --- Tests ---

func TestWebhook_ConnectorConformanceRejection(t *testing.T) {
	mock := &mockWebhookGatewayServices{
		validateConnectorFunc: func(connectorID, signature string) (bool, string) {
			return false, "connector_not_registered"
		},
	}
	adapter := newWebhookTestAdapter(mock, "")

	platforms := []struct {
		path    string
		payload map[string]any
	}{
		{"/openclaw/webhooks/whatsapp", whatsappPayload("hello", "+1234")},
		{"/openclaw/webhooks/telegram", telegramPayload("hello", "testuser")},
		{"/openclaw/webhooks/slack", slackPayload("hello", "U123")},
	}

	for _, tc := range platforms {
		t.Run(tc.path, func(t *testing.T) {
			rec := postWebhook(t, adapter, tc.path, tc.payload)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d; body=%s", rec.Code, rec.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if msg, _ := body["message"].(string); !strings.Contains(msg, "connector conformance failed") {
				t.Fatalf("expected connector conformance error message, got %q", msg)
			}
		})
	}
}

func TestWebhook_MalformedJSON(t *testing.T) {
	mock := &mockWebhookGatewayServices{}
	adapter := newWebhookTestAdapter(mock, "")

	req := httptest.NewRequest(http.MethodPost, "/openclaw/webhooks/whatsapp", strings.NewReader("{invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	adapter.TryServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if msg, _ := body["message"].(string); !strings.Contains(msg, "invalid json") {
		t.Fatalf("expected 'invalid json' error, got %q", msg)
	}
}

func TestWebhook_WrongMethod(t *testing.T) {
	mock := &mockWebhookGatewayServices{}
	adapter := newWebhookTestAdapter(mock, "")

	paths := []string{
		"/openclaw/webhooks/whatsapp",
		"/openclaw/webhooks/telegram",
		"/openclaw/webhooks/slack",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			rec := getWebhook(t, adapter, path)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405, got %d; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestWebhook_UnknownPath(t *testing.T) {
	mock := &mockWebhookGatewayServices{}
	adapter := newWebhookTestAdapter(mock, "")

	rec := postWebhook(t, adapter, "/openclaw/webhooks/discord", map[string]any{"text": "hello"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

func TestWebhook_WhatsApp_SuccessfulLoopback(t *testing.T) {
	// Mock connector allows all.
	mock := &mockWebhookGatewayServices{
		validateConnectorFunc: func(connectorID, signature string) (bool, string) {
			return true, "connector_active"
		},
	}

	// Set up a local httptest server as the loopback target (simulates /v1/ingress/submit).
	var receivedBody []byte
	loopbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"decision":    "allow",
			"reason_code": "INGRESS_ALLOW",
		})
	}))
	defer loopbackServer.Close()

	adapter := newWebhookTestAdapter(mock, loopbackServer.URL)

	payload := whatsappPayload("Hello from webhook", "+15551234567")
	rec := postWebhook(t, adapter, "/openclaw/webhooks/whatsapp", payload)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", rec.Code, rec.Body.String())
	}

	// Verify the loopback received a valid PlaneRequestV2.
	var planeReq gateway.PlaneRequestV2
	if err := json.Unmarshal(receivedBody, &planeReq); err != nil {
		t.Fatalf("loopback did not receive valid PlaneRequestV2: %v", err)
	}
	if planeReq.Envelope.Plane != gateway.PlaneIngress {
		t.Fatalf("expected ingress plane, got %q", planeReq.Envelope.Plane)
	}
	if planeReq.Policy.Action != "webhook.inbound" {
		t.Fatalf("expected action webhook.inbound, got %q", planeReq.Policy.Action)
	}
	if planeReq.Policy.Resource != "whatsapp.message" {
		t.Fatalf("expected resource whatsapp.message, got %q", planeReq.Policy.Resource)
	}

	// Verify extracted message data is in the attributes.
	attrs := planeReq.Policy.Attributes
	if attrs["sender"] != "+15551234567" {
		t.Fatalf("expected sender +15551234567, got %v", attrs["sender"])
	}
	if attrs["content"] != "Hello from webhook" {
		t.Fatalf("expected content 'Hello from webhook', got %v", attrs["content"])
	}

	// Verify the response was forwarded from loopback.
	var respBody map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &respBody); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respBody["decision"] != "allow" {
		t.Fatalf("expected decision=allow in forwarded response, got %v", respBody["decision"])
	}
}

func TestWebhook_Telegram_SuccessfulLoopback(t *testing.T) {
	mock := &mockWebhookGatewayServices{
		validateConnectorFunc: func(connectorID, signature string) (bool, string) {
			return true, "connector_active"
		},
	}

	var receivedBody []byte
	loopbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"decision": "allow"})
	}))
	defer loopbackServer.Close()

	adapter := newWebhookTestAdapter(mock, loopbackServer.URL)

	payload := telegramPayload("Telegram test message", "bot_user")
	rec := postWebhook(t, adapter, "/openclaw/webhooks/telegram", payload)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", rec.Code, rec.Body.String())
	}

	var planeReq gateway.PlaneRequestV2
	if err := json.Unmarshal(receivedBody, &planeReq); err != nil {
		t.Fatalf("loopback did not receive valid PlaneRequestV2: %v", err)
	}
	attrs := planeReq.Policy.Attributes
	if attrs["sender"] != "bot_user" {
		t.Fatalf("expected sender bot_user, got %v", attrs["sender"])
	}
	if attrs["content"] != "Telegram test message" {
		t.Fatalf("expected content 'Telegram test message', got %v", attrs["content"])
	}
	if attrs["platform"] != "telegram" {
		t.Fatalf("expected platform telegram, got %v", attrs["platform"])
	}
}

func TestWebhook_Slack_SuccessfulLoopback(t *testing.T) {
	mock := &mockWebhookGatewayServices{
		validateConnectorFunc: func(connectorID, signature string) (bool, string) {
			return true, "connector_active"
		},
	}

	var receivedBody []byte
	loopbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"decision": "allow"})
	}))
	defer loopbackServer.Close()

	adapter := newWebhookTestAdapter(mock, loopbackServer.URL)

	payload := slackPayload("Slack channel message", "U98765")
	rec := postWebhook(t, adapter, "/openclaw/webhooks/slack", payload)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", rec.Code, rec.Body.String())
	}

	var planeReq gateway.PlaneRequestV2
	if err := json.Unmarshal(receivedBody, &planeReq); err != nil {
		t.Fatalf("loopback did not receive valid PlaneRequestV2: %v", err)
	}
	attrs := planeReq.Policy.Attributes
	if attrs["sender"] != "U98765" {
		t.Fatalf("expected sender U98765, got %v", attrs["sender"])
	}
	if attrs["content"] != "Slack channel message" {
		t.Fatalf("expected content 'Slack channel message', got %v", attrs["content"])
	}
	if attrs["platform"] != "slack" {
		t.Fatalf("expected platform slack, got %v", attrs["platform"])
	}
}

func TestWebhook_TryServeHTTP_Dispatches(t *testing.T) {
	mock := &mockWebhookGatewayServices{}
	adapter := newWebhookTestAdapter(mock, "")

	// Webhook paths should be claimed by TryServeHTTP.
	webhookPaths := []string{
		"/openclaw/webhooks/whatsapp",
		"/openclaw/webhooks/telegram",
		"/openclaw/webhooks/slack",
		"/openclaw/webhooks/discord", // unknown platform but prefix matches -- claimed, returns 404
	}
	for _, path := range webhookPaths {
		t.Run("claimed:"+path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			claimed := adapter.TryServeHTTP(rec, req)
			if !claimed {
				t.Fatalf("expected TryServeHTTP to claim path %s", path)
			}
		})
	}

	// Non-webhook paths should NOT be claimed.
	nonWebhookPaths := []string{
		"/some/other/path",
		"/openclaw/other",
	}
	for _, path := range nonWebhookPaths {
		t.Run("not_claimed:"+path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			claimed := adapter.TryServeHTTP(rec, req)
			if claimed {
				t.Fatalf("expected TryServeHTTP NOT to claim path %s", path)
			}
		})
	}
}

func TestWebhook_ConnectorIDFromPayload(t *testing.T) {
	// When payload contains connector_id, it should be used instead of derived ID.
	var capturedConnectorID string
	mock := &mockWebhookGatewayServices{
		validateConnectorFunc: func(connectorID, signature string) (bool, string) {
			capturedConnectorID = connectorID
			return false, "test_deny" // deny so we can inspect without needing loopback
		},
	}
	adapter := newWebhookTestAdapter(mock, "")

	payload := whatsappPayload("test", "+1234")
	payload["connector_id"] = "my-custom-connector"

	_ = postWebhook(t, adapter, "/openclaw/webhooks/whatsapp", payload)

	if capturedConnectorID != "my-custom-connector" {
		t.Fatalf("expected connector_id=my-custom-connector, got %q", capturedConnectorID)
	}
}

func TestWebhook_MalformedPlatformPayload(t *testing.T) {
	// Connector passes, but payload structure is wrong for the platform.
	mock := &mockWebhookGatewayServices{
		validateConnectorFunc: func(connectorID, signature string) (bool, string) {
			return true, "connector_active"
		},
	}
	adapter := newWebhookTestAdapter(mock, "")

	// WhatsApp payload missing required "entry" array.
	rec := postWebhook(t, adapter, "/openclaw/webhooks/whatsapp", map[string]any{"wrong": "shape"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed platform payload, got %d; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if msg, _ := body["message"].(string); !strings.Contains(msg, "failed to extract message") {
		t.Fatalf("expected extraction error, got %q", msg)
	}
}

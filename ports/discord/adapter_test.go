package discord

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

// mockGatewayServices captures calls to EvaluateToolRequest and can return
// configurable results. WriteGatewayError writes the HTTP status so test
// assertions on rr.Code work.
type mockGatewayServices struct {
	evalResult      gateway.ToolPlaneEvalResult
	evalCalled      bool
	evalRequest     gateway.PlaneRequestV2
	writeErrorCode  int
	writeErrorCalls int
}

func (m *mockGatewayServices) BuildModelPlaneRequest(_ *http.Request, _ map[string]any) gateway.PlaneRequestV2 {
	return gateway.PlaneRequestV2{}
}
func (m *mockGatewayServices) EvaluateModelPlaneDecision(_ *http.Request, _ gateway.PlaneRequestV2) (gateway.Decision, gateway.ReasonCode, int, map[string]any) {
	return "", "", 0, nil
}
func (m *mockGatewayServices) ExecuteModelEgress(_ context.Context, _ map[string]any, _ map[string]any, _ string) (*gateway.ModelEgressResult, error) {
	return nil, nil
}
func (m *mockGatewayServices) ShouldApplyPolicyIntentProjection() bool { return false }
func (m *mockGatewayServices) EvaluateToolRequest(req gateway.PlaneRequestV2) gateway.ToolPlaneEvalResult {
	m.evalCalled = true
	m.evalRequest = req
	return m.evalResult
}
func (m *mockGatewayServices) ExecuteMessagingEgress(_ context.Context, _ map[string]string, _ []byte, _ string) (*gateway.MessagingEgressResult, error) {
	return nil, nil
}
func (m *mockGatewayServices) RedeemSPIKESecret(_ context.Context, _ string) (string, error) {
	return "", nil
}
func (m *mockGatewayServices) LogPlaneDecision(_ *http.Request, _ gateway.PlaneDecisionV2, _ int) {}
func (m *mockGatewayServices) AuditLog(_ middleware.AuditEvent)                                   {}
func (m *mockGatewayServices) WriteGatewayError(w http.ResponseWriter, _ *http.Request, httpCode int, errorCode string, message string, _ string, _ gateway.ReasonCode, _ map[string]any) {
	m.writeErrorCalls++
	m.writeErrorCode = httpCode
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": errorCode, "message": message})
}
func (m *mockGatewayServices) ValidateAndConsumeApproval(_ string, _ middleware.ApprovalScope) (*middleware.ApprovalCapabilityClaims, error) {
	return nil, nil
}
func (m *mockGatewayServices) HasApprovalService() bool                       { return false }
func (m *mockGatewayServices) ValidateConnector(_ string, _ string) (bool, string) {
	return true, ""
}
func (m *mockGatewayServices) ScanContent(_ string) middleware.ScanResult {
	return middleware.ScanResult{}
}

var _ gateway.PortGatewayServices = (*mockGatewayServices)(nil)

func newMock(evalResult gateway.ToolPlaneEvalResult) (*Adapter, *mockGatewayServices) {
	m := &mockGatewayServices{evalResult: evalResult}
	return NewAdapter(m), m
}

func newTestAdapter() *Adapter {
	a, _ := newMock(gateway.ToolPlaneEvalResult{
		Decision:   gateway.DecisionAllow,
		Reason:     gateway.ReasonToolAllow,
		HTTPStatus: http.StatusOK,
	})
	return a
}

// --- AC1: Name ---

func TestAdapter_Name(t *testing.T) {
	a := newTestAdapter()
	if got := a.Name(); got != "discord" {
		t.Errorf("Name() = %q, want %q", got, "discord")
	}
}

// --- AC2: TryServeHTTP path claiming ---

func TestAdapter_TryServeHTTP_Claims_Discord_Paths(t *testing.T) {
	a := newTestAdapter()
	paths := []string{"/discord/send", "/discord/webhooks", "/discord/commands"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, p, strings.NewReader(`{"channel_id":"c","content":"hi","command":"test"}`))
			rr := httptest.NewRecorder()
			if !a.TryServeHTTP(rr, req) {
				t.Errorf("TryServeHTTP(%s) = false, want true", p)
			}
		})
	}
}

func TestAdapter_TryServeHTTP_Ignores_Other_Paths(t *testing.T) {
	a := newTestAdapter()
	paths := []string{"/", "/v1/chat", "/openclaw/ws", "/mcp", "/health", "/discord/unknown"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, p, nil)
			rr := httptest.NewRecorder()
			if a.TryServeHTTP(rr, req) {
				t.Errorf("TryServeHTTP(%s) = true, want false", p)
			}
		})
	}
}

// --- AC5: EvaluateToolRequest called for /discord/send (messaging_send) ---

func TestAdapter_HandleSend_CallsEvaluateToolRequest(t *testing.T) {
	adapter, mock := newMock(gateway.ToolPlaneEvalResult{
		Decision:   gateway.DecisionAllow,
		Reason:     gateway.ReasonToolAllow,
		HTTPStatus: http.StatusOK,
	})
	body := `{"channel_id":"ch-123","content":"hello world"}`
	req := httptest.NewRequest(http.MethodPost, "/discord/send", strings.NewReader(body))
	rr := httptest.NewRecorder()
	adapter.TryServeHTTP(rr, req)

	if !mock.evalCalled {
		t.Fatal("EvaluateToolRequest was not called for /discord/send")
	}
	if got := mock.evalRequest.Policy.Action; got != "messaging_send" {
		t.Errorf("action = %q, want %q", got, "messaging_send")
	}
	// When allowed, returns 501 with operation name (not yet implemented).
	if rr.Code != http.StatusNotImplemented {
		t.Errorf("/discord/send status = %d, want %d", rr.Code, http.StatusNotImplemented)
	}
	var respBody map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &respBody); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if op, _ := respBody["operation"].(string); op != "messaging_send" {
		t.Errorf("response operation = %q, want %q", op, "messaging_send")
	}
}

func TestAdapter_HandleSend_Denied(t *testing.T) {
	adapter, mock := newMock(gateway.ToolPlaneEvalResult{
		Decision:   gateway.DecisionDeny,
		Reason:     gateway.ReasonToolCapabilityDenied,
		HTTPStatus: http.StatusForbidden,
	})
	body := `{"channel_id":"ch-123","content":"hello world"}`
	req := httptest.NewRequest(http.MethodPost, "/discord/send", strings.NewReader(body))
	rr := httptest.NewRecorder()
	adapter.TryServeHTTP(rr, req)

	if !mock.evalCalled {
		t.Fatal("EvaluateToolRequest was not called for denied /discord/send")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("/discord/send denied status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// --- AC5: EvaluateToolRequest called for /discord/commands (discord_command) ---

func TestAdapter_HandleCommand_CallsEvaluateToolRequest(t *testing.T) {
	adapter, mock := newMock(gateway.ToolPlaneEvalResult{
		Decision:   gateway.DecisionAllow,
		Reason:     gateway.ReasonToolAllow,
		HTTPStatus: http.StatusOK,
	})
	body := `{"command":"deploy","guild_id":"g-1"}`
	req := httptest.NewRequest(http.MethodPost, "/discord/commands", strings.NewReader(body))
	rr := httptest.NewRecorder()
	adapter.TryServeHTTP(rr, req)

	if !mock.evalCalled {
		t.Fatal("EvaluateToolRequest was not called for /discord/commands")
	}
	if got := mock.evalRequest.Policy.Action; got != "discord_command" {
		t.Errorf("action = %q, want %q", got, "discord_command")
	}
	// When allowed, returns 501 with operation name (not yet implemented).
	if rr.Code != http.StatusNotImplemented {
		t.Errorf("/discord/commands status = %d, want %d", rr.Code, http.StatusNotImplemented)
	}
	var respBody map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &respBody); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if op, _ := respBody["operation"].(string); op != "discord_command" {
		t.Errorf("response operation = %q, want %q", op, "discord_command")
	}
}

func TestAdapter_HandleCommand_Denied(t *testing.T) {
	adapter, mock := newMock(gateway.ToolPlaneEvalResult{
		Decision:   gateway.DecisionDeny,
		Reason:     gateway.ReasonToolActionDenied,
		HTTPStatus: http.StatusForbidden,
	})
	body := `{"command":"deploy","guild_id":"g-1"}`
	req := httptest.NewRequest(http.MethodPost, "/discord/commands", strings.NewReader(body))
	rr := httptest.NewRecorder()
	adapter.TryServeHTTP(rr, req)

	if !mock.evalCalled {
		t.Fatal("EvaluateToolRequest was not called for denied /discord/commands")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("/discord/commands denied status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// --- AC6: Malformed JSON body tests ---

func TestAdapter_HandleSend_MalformedJSON(t *testing.T) {
	adapter, mock := newMock(gateway.ToolPlaneEvalResult{})
	req := httptest.NewRequest(http.MethodPost, "/discord/send", strings.NewReader(`{not json`))
	rr := httptest.NewRecorder()
	adapter.TryServeHTTP(rr, req)

	if mock.evalCalled {
		t.Error("EvaluateToolRequest should not be called for malformed JSON")
	}
	if rr.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdapter_HandleCommand_MalformedJSON(t *testing.T) {
	adapter, mock := newMock(gateway.ToolPlaneEvalResult{})
	req := httptest.NewRequest(http.MethodPost, "/discord/commands", strings.NewReader(`{not json`))
	rr := httptest.NewRecorder()
	adapter.TryServeHTTP(rr, req)

	if mock.evalCalled {
		t.Error("EvaluateToolRequest should not be called for malformed JSON")
	}
	if rr.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// --- AC6: Missing required fields tests ---

func TestAdapter_HandleSend_MissingChannelID(t *testing.T) {
	adapter, mock := newMock(gateway.ToolPlaneEvalResult{})
	req := httptest.NewRequest(http.MethodPost, "/discord/send", strings.NewReader(`{"content":"hello"}`))
	rr := httptest.NewRecorder()
	adapter.TryServeHTTP(rr, req)

	if mock.evalCalled {
		t.Error("EvaluateToolRequest should not be called when channel_id is missing")
	}
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing channel_id status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdapter_HandleSend_MissingContent(t *testing.T) {
	adapter, mock := newMock(gateway.ToolPlaneEvalResult{})
	req := httptest.NewRequest(http.MethodPost, "/discord/send", strings.NewReader(`{"channel_id":"ch-1"}`))
	rr := httptest.NewRecorder()
	adapter.TryServeHTTP(rr, req)

	if mock.evalCalled {
		t.Error("EvaluateToolRequest should not be called when content is missing")
	}
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing content status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAdapter_HandleCommand_MissingCommand(t *testing.T) {
	adapter, mock := newMock(gateway.ToolPlaneEvalResult{})
	req := httptest.NewRequest(http.MethodPost, "/discord/commands", strings.NewReader(`{"guild_id":"g-1"}`))
	rr := httptest.NewRecorder()
	adapter.TryServeHTTP(rr, req)

	if mock.evalCalled {
		t.Error("EvaluateToolRequest should not be called when command is missing")
	}
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing command status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// --- Webhook without valid signature returns 401 ---

func TestAdapter_HandleWebhook_NoSignature_Returns_401(t *testing.T) {
	a := newTestAdapter()
	req := httptest.NewRequest(http.MethodPost, "/discord/webhooks", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	a.TryServeHTTP(rr, req)

	// Without DISCORD_PUBLIC_KEY or valid signature, should fail closed with 401.
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("/discord/webhooks no-sig status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// --- Method not allowed tests ---

func TestAdapter_HandleSend_MethodNotAllowed(t *testing.T) {
	adapter, mock := newMock(gateway.ToolPlaneEvalResult{})
	req := httptest.NewRequest(http.MethodGet, "/discord/send", nil)
	rr := httptest.NewRecorder()
	adapter.TryServeHTTP(rr, req)

	if mock.evalCalled {
		t.Error("EvaluateToolRequest should not be called for GET")
	}
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /discord/send status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestAdapter_HandleCommand_MethodNotAllowed(t *testing.T) {
	adapter, mock := newMock(gateway.ToolPlaneEvalResult{})
	req := httptest.NewRequest(http.MethodGet, "/discord/commands", nil)
	rr := httptest.NewRecorder()
	adapter.TryServeHTTP(rr, req)

	if mock.evalCalled {
		t.Error("EvaluateToolRequest should not be called for GET")
	}
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /discord/commands status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

package discord

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway"
	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
)

// stubGatewayServices is a minimal implementation of PortGatewayServices
// sufficient to construct the adapter. The stub handlers do not call gateway
// services, so none of these methods are exercised.
type stubGatewayServices struct{}

func (s *stubGatewayServices) BuildModelPlaneRequest(_ *http.Request, _ map[string]any) gateway.PlaneRequestV2 {
	return gateway.PlaneRequestV2{}
}
func (s *stubGatewayServices) EvaluateModelPlaneDecision(_ *http.Request, _ gateway.PlaneRequestV2) (gateway.Decision, gateway.ReasonCode, int, map[string]any) {
	return "", "", 0, nil
}
func (s *stubGatewayServices) ExecuteModelEgress(_ context.Context, _ map[string]any, _ map[string]any, _ string) (*gateway.ModelEgressResult, error) {
	return nil, nil
}
func (s *stubGatewayServices) ShouldApplyPolicyIntentProjection() bool { return false }
func (s *stubGatewayServices) EvaluateToolRequest(_ gateway.PlaneRequestV2) gateway.ToolPlaneEvalResult {
	return gateway.ToolPlaneEvalResult{}
}
func (s *stubGatewayServices) ExecuteMessagingEgress(_ context.Context, _ map[string]string, _ []byte, _ string) (*gateway.MessagingEgressResult, error) {
	return nil, nil
}
func (s *stubGatewayServices) RedeemSPIKESecret(_ context.Context, _ string) (string, error) {
	return "", nil
}
func (s *stubGatewayServices) LogPlaneDecision(_ *http.Request, _ gateway.PlaneDecisionV2, _ int) {}
func (s *stubGatewayServices) AuditLog(_ middleware.AuditEvent)                                   {}
func (s *stubGatewayServices) WriteGatewayError(_ http.ResponseWriter, _ *http.Request, _ int, _ string, _ string, _ string, _ gateway.ReasonCode, _ map[string]any) {
}
func (s *stubGatewayServices) ValidateAndConsumeApproval(_ string, _ middleware.ApprovalScope) (*middleware.ApprovalCapabilityClaims, error) {
	return nil, nil
}
func (s *stubGatewayServices) HasApprovalService() bool                       { return false }
func (s *stubGatewayServices) ValidateConnector(_ string, _ string) (bool, string) {
	return true, ""
}

var _ gateway.PortGatewayServices = (*stubGatewayServices)(nil)

func newTestAdapter() *Adapter {
	return NewAdapter(&stubGatewayServices{})
}

// TestAdapter_Name verifies the adapter returns the correct port identifier.
func TestAdapter_Name(t *testing.T) {
	a := newTestAdapter()
	if got := a.Name(); got != "discord" {
		t.Errorf("Name() = %q, want %q", got, "discord")
	}
}

// TestAdapter_TryServeHTTP_Claims_Discord_Paths verifies TryServeHTTP returns true
// for all Discord-owned paths.
func TestAdapter_TryServeHTTP_Claims_Discord_Paths(t *testing.T) {
	a := newTestAdapter()
	paths := []string{"/discord/send", "/discord/webhooks", "/discord/commands"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, p, nil)
			rr := httptest.NewRecorder()
			if !a.TryServeHTTP(rr, req) {
				t.Errorf("TryServeHTTP(%s) = false, want true", p)
			}
		})
	}
}

// TestAdapter_TryServeHTTP_Ignores_Other_Paths verifies TryServeHTTP returns false
// for paths that do not belong to the Discord adapter.
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

// TestAdapter_HandleSend_Returns_501 verifies the send stub returns 501.
func TestAdapter_HandleSend_Returns_501(t *testing.T) {
	a := newTestAdapter()
	req := httptest.NewRequest(http.MethodPost, "/discord/send", nil)
	rr := httptest.NewRecorder()
	a.TryServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("/discord/send status = %d, want %d", rr.Code, http.StatusNotImplemented)
	}
}

// TestAdapter_HandleWebhook_Returns_501 verifies the webhook stub returns 501.
func TestAdapter_HandleWebhook_Returns_501(t *testing.T) {
	a := newTestAdapter()
	req := httptest.NewRequest(http.MethodPost, "/discord/webhooks", nil)
	rr := httptest.NewRecorder()
	a.TryServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("/discord/webhooks status = %d, want %d", rr.Code, http.StatusNotImplemented)
	}
}

// TestAdapter_HandleCommand_Returns_501 verifies the command stub returns 501.
func TestAdapter_HandleCommand_Returns_501(t *testing.T) {
	a := newTestAdapter()
	req := httptest.NewRequest(http.MethodPost, "/discord/commands", nil)
	rr := httptest.NewRecorder()
	a.TryServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("/discord/commands status = %d, want %d", rr.Code, http.StatusNotImplemented)
	}
}

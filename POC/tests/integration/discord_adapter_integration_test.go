//go:build integration
// +build integration

// Discord adapter integration tests.
// Confirms the discord adapter is reachable through the SPIFFE auth middleware,
// verifying that the adapter is correctly wired into the gateway's middleware chain.

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway"
	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
	"github.com/precinct-dev/PRECINCT/POC/ports/discord"
)

// integrationMockGateway satisfies gateway.PortGatewayServices with minimal
// behaviour: EvaluateToolRequest returns allow, WriteGatewayError writes a
// proper JSON error, everything else is a no-op.
type integrationMockGateway struct{}

var _ gateway.PortGatewayServices = (*integrationMockGateway)(nil)

func (m *integrationMockGateway) BuildModelPlaneRequest(_ *http.Request, _ map[string]any) gateway.PlaneRequestV2 {
	return gateway.PlaneRequestV2{}
}
func (m *integrationMockGateway) EvaluateModelPlaneDecision(_ *http.Request, _ gateway.PlaneRequestV2) (gateway.Decision, gateway.ReasonCode, int, map[string]any) {
	return "", "", 0, nil
}
func (m *integrationMockGateway) ExecuteModelEgress(_ context.Context, _ map[string]any, _ map[string]any, _ string) (*gateway.ModelEgressResult, error) {
	return nil, nil
}
func (m *integrationMockGateway) ShouldApplyPolicyIntentProjection() bool { return false }
func (m *integrationMockGateway) EvaluateToolRequest(_ gateway.PlaneRequestV2) gateway.ToolPlaneEvalResult {
	return gateway.ToolPlaneEvalResult{
		Decision:   gateway.DecisionAllow,
		Reason:     gateway.ReasonToolAllow,
		HTTPStatus: http.StatusOK,
	}
}
func (m *integrationMockGateway) ExecuteMessagingEgress(_ context.Context, _ map[string]string, _ []byte, _ string) (*gateway.MessagingEgressResult, error) {
	return nil, nil
}
func (m *integrationMockGateway) RedeemSPIKESecret(_ context.Context, _ string) (string, error) {
	return "", nil
}
func (m *integrationMockGateway) LogPlaneDecision(_ *http.Request, _ gateway.PlaneDecisionV2, _ int) {
}
func (m *integrationMockGateway) AuditLog(_ middleware.AuditEvent) {}
func (m *integrationMockGateway) WriteGatewayError(w http.ResponseWriter, _ *http.Request, httpCode int, errorCode string, message string, _ string, _ gateway.ReasonCode, _ map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": errorCode, "message": message})
}
func (m *integrationMockGateway) ValidateAndConsumeApproval(_ string, _ middleware.ApprovalScope) (*middleware.ApprovalCapabilityClaims, error) {
	return nil, nil
}
func (m *integrationMockGateway) HasApprovalService() bool { return false }
func (m *integrationMockGateway) ValidateConnector(_ string, _ string) (bool, string) {
	return true, ""
}
func (m *integrationMockGateway) ScanContent(_ string) middleware.ScanResult {
	return middleware.ScanResult{}
}

// buildDiscordChain constructs a middleware chain with real SPIFFE auth
// followed by the discord adapter dispatch. This exercises the real
// authentication middleware without requiring a running gateway.
func buildDiscordChain(t *testing.T) http.Handler {
	t.Helper()

	adapter := discord.NewAdapter(&integrationMockGateway{})

	// Terminal: dispatch to the discord adapter. If the adapter does not claim
	// the path, return 404 (simulating gateway fallthrough behavior).
	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !adapter.TryServeHTTP(w, r) {
			http.NotFound(w, r)
		}
	})

	// Build chain: SPIFFEAuth -> discord adapter dispatch
	handler := middleware.SPIFFEAuth(terminal, "dev")

	return handler
}

// TestDiscordAdapter_SPIFFEAuth_Denial verifies that a request to a discord
// endpoint WITHOUT a SPIFFE ID header is rejected by SPIFFE auth (401),
// proving the adapter sits behind the authentication middleware.
func TestDiscordAdapter_SPIFFEAuth_Denial(t *testing.T) {
	handler := buildDiscordChain(t)

	req := httptest.NewRequest(http.MethodPost, "/discord/send", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	// Intentionally omit X-SPIFFE-ID

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Expected HTTP 401 for missing SPIFFE ID on /discord/send, got %d: %s",
			rr.Code, rr.Body.String())
	}
	t.Logf("PASS: /discord/send without SPIFFE ID denied with 401")
}

// TestDiscordAdapter_SPIFFEAuth_Passthrough verifies that a request to
// /discord/send WITH a valid SPIFFE ID header traverses SPIFFE auth and
// reaches the discord adapter, which returns 501 (stub).
func TestDiscordAdapter_SPIFFEAuth_Passthrough(t *testing.T) {
	handler := buildDiscordChain(t)

	req := httptest.NewRequest(http.MethodPost, "/discord/send",
		strings.NewReader(`{"channel_id":"123","content":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("Expected HTTP 501 (stub) for /discord/send with valid SPIFFE ID, got %d: %s",
			rr.Code, rr.Body.String())
	}
	t.Logf("PASS: /discord/send with valid SPIFFE ID reached adapter stub (501)")
}

// TestDiscordAdapter_AllEndpoints_Behind_SPIFFE verifies all three discord
// endpoints are protected by SPIFFE auth and reachable when authenticated.
func TestDiscordAdapter_AllEndpoints_Behind_SPIFFE(t *testing.T) {
	handler := buildDiscordChain(t)

	// Valid request bodies per endpoint so requests pass contract validation
	// and reach the 501 stub (send and commands validate required fields).
	validBodies := map[string]string{
		"/discord/send":     `{"channel_id":"123","content":"hello"}`,
		"/discord/webhooks": `{}`,
		"/discord/commands": `{"command":"ping"}`,
	}

	endpoints := []string{"/discord/send", "/discord/webhooks", "/discord/commands"}

	for _, ep := range endpoints {
		t.Run("no_spiffe_"+ep, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, ep, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("%s without SPIFFE: got %d, want 401", ep, rr.Code)
			}
		})

		t.Run("with_spiffe_"+ep, func(t *testing.T) {
			body := validBodies[ep]
			req := httptest.NewRequest(http.MethodPost, ep, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if ep == "/discord/webhooks" {
				if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusNotImplemented {
					t.Errorf("%s with SPIFFE: got %d, want 401 or 501", ep, rr.Code)
				}
				return
			}
			if rr.Code != http.StatusNotImplemented {
				t.Errorf("%s with SPIFFE: got %d, want 501", ep, rr.Code)
			}
		})
	}
}

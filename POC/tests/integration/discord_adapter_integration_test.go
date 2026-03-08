//go:build integration
// +build integration

// Discord adapter integration tests.
// Confirms the discord adapter is reachable through the SPIFFE auth middleware,
// verifying that the adapter is correctly wired into the gateway's middleware chain.

package integration

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
	"github.com/RamXX/agentic_reference_architecture/POC/ports/discord"
)

// buildDiscordChain constructs a middleware chain with real SPIFFE auth
// followed by the discord adapter dispatch. This exercises the real
// authentication middleware without requiring a running gateway.
func buildDiscordChain(t *testing.T) http.Handler {
	t.Helper()

	adapter := discord.NewAdapter(nil) // stub handlers don't call gateway services

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

	req := httptest.NewRequest(http.MethodPost, "/discord/send", strings.NewReader(`{}`))
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
			req := httptest.NewRequest(http.MethodPost, ep, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusNotImplemented {
				t.Errorf("%s with SPIFFE: got %d, want 501", ep, rr.Code)
			}
		})
	}
}

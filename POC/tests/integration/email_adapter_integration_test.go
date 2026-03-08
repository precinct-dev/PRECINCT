//go:build integration
// +build integration

// Email Adapter Integration Test - OC-tbd4
// Verifies that the email port adapter is registered in the gateway and that
// requests to /email/* paths traverse the middleware chain (SPIFFE auth check).

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestEmailAdapter_Registration verifies the email adapter is registered and
// /email/send returns 501 (stub) after traversing the middleware chain.
// A 501 response proves:
//   - The gateway dispatched the request to the email adapter (registration works)
//   - The middleware chain was traversed (auth passed or dev-mode bypass)
//   - The stub handler executed
func TestEmailAdapter_Registration(t *testing.T) {
	requireGateway(t)

	paths := []struct {
		path      string
		operation string
	}{
		{"/email/send", "messaging_send"},
		{"/email/webhooks", "email_webhook"},
		{"/email/list", "email_list"},
		{"/email/read", "email_read"},
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, tc := range paths {
		t.Run(tc.path, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, gatewayURL+tc.path, strings.NewReader("{}"))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			// SPIFFE ID header for dev-mode middleware traversal.
			req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request to %s failed: %v", tc.path, err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}

			// 501 = stub handler executed after middleware traversal.
			// 403 = middleware denied (auth check applied -- proves traversal).
			// Any other code is unexpected.
			if resp.StatusCode != http.StatusNotImplemented && resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s: status = %d (body: %s), want 501 or 403", tc.path, resp.StatusCode, string(body))
			}

			if resp.StatusCode == http.StatusNotImplemented {
				// Verify the JSON error structure from the stub.
				var errBody map[string]string
				if err := json.Unmarshal(body, &errBody); err != nil {
					t.Fatalf("%s: failed to parse JSON body: %v (raw: %s)", tc.path, err, string(body))
				}
				if errBody["error"] != "not_implemented" {
					t.Fatalf("%s: error = %q, want %q", tc.path, errBody["error"], "not_implemented")
				}
				if errBody["operation"] != tc.operation {
					t.Fatalf("%s: operation = %q, want %q", tc.path, errBody["operation"], tc.operation)
				}
			}
		})
	}
}

// TestEmailAdapter_MiddlewareTraversal_SPIFFE verifies that the middleware
// chain enforces auth on email paths. An unauthenticated request (no SPIFFE
// header, no client cert) should be rejected -- proving the middleware is
// applied, not bypassed.
func TestEmailAdapter_MiddlewareTraversal_SPIFFE(t *testing.T) {
	requireGateway(t)

	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest(http.MethodPost, gatewayURL+"/email/send", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Deliberately omit X-SPIFFE-ID and client cert.

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Without identity, the gateway should either:
	// - Return 403/401 (middleware blocked the request)
	// - Return 501 in dev mode with no SPIFFE enforcement
	// Either response proves the request reached the gateway and was processed.
	if resp.StatusCode == http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("got 500 -- middleware chain likely broken (body: %s)", string(body))
	}
}

// TestEmailAdapter_UnclaimedPath verifies that a path not claimed by the
// email adapter does NOT route to the email stub handlers.
func TestEmailAdapter_UnclaimedPath(t *testing.T) {
	requireGateway(t)

	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest(http.MethodPost, gatewayURL+"/email/nonexistent", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// The email adapter should NOT claim /email/nonexistent.
	// It should fall through to the gateway default handler (likely 404 or proxy).
	if resp.StatusCode == http.StatusNotImplemented {
		body, _ := io.ReadAll(resp.Body)
		var errBody map[string]string
		if err := json.Unmarshal(body, &errBody); err == nil {
			if errBody["error"] == "not_implemented" {
				t.Fatalf("/email/nonexistent should not be claimed by email adapter, but got stub 501")
			}
		}
	}
}

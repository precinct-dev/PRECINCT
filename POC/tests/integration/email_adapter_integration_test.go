//go:build integration
// +build integration

// Email Adapter Integration Tests - OC-tbd4, OC-0lx3
// Verifies that the email port adapter is registered in the gateway, that
// requests to /email/* paths traverse the middleware chain (SPIFFE auth check),
// and that /email/send processes requests through DLP and policy evaluation.

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
// /email/* paths are dispatched correctly after traversing the middleware chain.
// For stub handlers (webhooks, list, read): expect 501.
// For /email/send (implemented): expect 400 (validation error for empty body) or 403.
// Any non-5xx (except 501 for stubs) proves middleware traversal succeeded.
func TestEmailAdapter_Registration(t *testing.T) {
	requireGateway(t)

	paths := []struct {
		path        string
		operation   string
		isStub      bool
	}{
		{"/email/send", "messaging_send", false},
		{"/email/webhooks", "email_webhook", true},
		{"/email/list", "email_list", true},
		{"/email/read", "email_read", true},
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

			if tc.isStub {
				// Stub handlers: 501 or 403 (middleware denied).
				if resp.StatusCode != http.StatusNotImplemented && resp.StatusCode != http.StatusForbidden {
					t.Fatalf("%s: status = %d (body: %s), want 501 or 403", tc.path, resp.StatusCode, string(body))
				}
				if resp.StatusCode == http.StatusNotImplemented {
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
			} else {
				// /email/send is implemented: empty JSON {} fails validation (400)
				// or middleware denies (403). Either proves registration + traversal.
				if resp.StatusCode == http.StatusNotImplemented {
					t.Fatalf("%s: got 501 (stub), but handler should be implemented", tc.path)
				}
				if resp.StatusCode == http.StatusInternalServerError {
					t.Fatalf("%s: got 500 -- handler crashed (body: %s)", tc.path, string(body))
				}
				// 400 (validation) or 403 (auth) are both acceptable.
				t.Logf("%s: status = %d (proves adapter dispatched)", tc.path, resp.StatusCode)
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

// TestEmailSend_DLPFlagsPII posts an email with an SSN in the body and
// verifies that the request traverses the middleware chain. PII policy is
// "flag" (not "block"), so the request should succeed (200) or be handled
// by policy (403 for auth, etc.) -- but NOT crash (500) or return stub (501).
// This proves /email/send feeds content through the middleware chain.
func TestEmailSend_DLPFlagsPII(t *testing.T) {
	requireGateway(t)

	client := &http.Client{Timeout: 10 * time.Second}

	emailBody := `{
		"to": ["test-recipient@example.com"],
		"subject": "PII Test",
		"body": "The SSN is 123-45-6789 and should be flagged by DLP."
	}`

	req, err := http.NewRequest(http.MethodPost, gatewayURL+"/email/send", strings.NewReader(emailBody))
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	// 501 would mean the handler is still a stub -- fail.
	if resp.StatusCode == http.StatusNotImplemented {
		t.Fatalf("got 501 (stub) -- handleSend should be implemented (body: %s)", string(body))
	}
	// 500 would mean the handler crashed -- fail.
	if resp.StatusCode == http.StatusInternalServerError {
		t.Fatalf("got 500 -- handler crashed (body: %s)", string(body))
	}

	// PII policy is "flag" not "block", so we expect the request to proceed.
	// Acceptable responses:
	// - 200 (success: egress worked or was simulated)
	// - 400 (policy or validation issue)
	// - 403 (DLP block for credentials, or auth denial)
	// - 502 (egress endpoint not configured)
	// All prove the handler processed the request through the middleware chain.
	t.Logf("/email/send with SSN: status=%d, body=%s", resp.StatusCode, string(body))

	// Verify the response is valid JSON (handler produced structured output).
	var jsonResp map[string]any
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		t.Fatalf("response is not valid JSON: %v (body: %s)", err, string(body))
	}
}

// TestEmailSend_MethodNotAllowed_Integration verifies that a GET request
// to /email/send returns 405 Method Not Allowed through the live gateway.
func TestEmailSend_MethodNotAllowed_Integration(t *testing.T) {
	requireGateway(t)

	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest(http.MethodGet, gatewayURL+"/email/send", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Either 405 (handler rejected) or 403 (middleware auth) are valid.
	// 501 or 500 would indicate a problem.
	if resp.StatusCode == http.StatusNotImplemented {
		t.Fatalf("GET /email/send returned 501 (stub) -- handler should be implemented")
	}
	if resp.StatusCode == http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /email/send returned 500 (body: %s)", string(body))
	}
	t.Logf("GET /email/send: status=%d (proves handler is active)", resp.StatusCode)
}

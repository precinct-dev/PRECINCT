package email

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdapter_Name(t *testing.T) {
	a := NewAdapter(nil)
	if got := a.Name(); got != "email" {
		t.Fatalf("Name() = %q, want %q", got, "email")
	}
}

func TestAdapter_TryServeHTTP_Claims_Email_Paths(t *testing.T) {
	// /email/send requires a non-nil gateway (it is implemented).
	// Stub paths (webhooks, list, read) work with nil.
	mock := newAllowMock()
	a := NewAdapter(mock)

	paths := []string{"/email/send", "/email/webhooks", "/email/list", "/email/read"}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			var body *strings.Reader
			if p == "/email/send" {
				// Provide a valid email body so handleSend doesn't panic on nil body.
				body = strings.NewReader(`{"to":["a@b.com"],"subject":"S","body":"B"}`)
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequest(http.MethodPost, p, body)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-SPIFFE-ID", "spiffe://test/agent")
			rr := httptest.NewRecorder()
			if !a.TryServeHTTP(rr, req) {
				t.Fatalf("TryServeHTTP(%s) returned false, want true", p)
			}
		})
	}
}

func TestAdapter_TryServeHTTP_Ignores_Other_Paths(t *testing.T) {
	a := NewAdapter(nil)

	paths := []string{"/", "/v1/chat", "/discord/send", "/mcp", "/health", "/openclaw/ws"}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, p, nil)
			rr := httptest.NewRecorder()
			if a.TryServeHTTP(rr, req) {
				t.Fatalf("TryServeHTTP(%s) returned true, want false", p)
			}
		})
	}
}

// TestAdapter_StubHandlers_Return_501_JSON verifies that stub handlers
// (webhooks, list, read) still return 501. /email/send is excluded because
// it is now implemented (OC-0lx3).
func TestAdapter_StubHandlers_Return_501_JSON(t *testing.T) {
	a := NewAdapter(nil)

	tests := []struct {
		path      string
		operation string
	}{
		{"/email/webhooks", "email_webhook"},
		{"/email/list", "email_list"},
		{"/email/read", "email_read"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			rr := httptest.NewRecorder()
			a.TryServeHTTP(rr, req)

			if rr.Code != http.StatusNotImplemented {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotImplemented)
			}

			ct := rr.Header().Get("Content-Type")
			if ct != "application/json" {
				t.Fatalf("Content-Type = %q, want %q", ct, "application/json")
			}

			var body map[string]string
			if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
				t.Fatalf("failed to decode JSON body: %v", err)
			}
			if body["error"] != "not_implemented" {
				t.Fatalf("error = %q, want %q", body["error"], "not_implemented")
			}
			if body["operation"] != tc.operation {
				t.Fatalf("operation = %q, want %q", body["operation"], tc.operation)
			}
		})
	}
}

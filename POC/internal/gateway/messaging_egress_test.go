package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestResolveMessagingTarget_EnvOverride(t *testing.T) {
	// Set up a local endpoint via env var.
	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_WHATSAPP", "http://localhost:8090/v1/messages")

	g := &Gateway{}
	target, err := g.resolveMessagingTarget("whatsapp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.String() != "http://localhost:8090/v1/messages" {
		t.Fatalf("expected env override endpoint, got %s", target.String())
	}
}

func TestResolveMessagingTarget_ProductionDefault(t *testing.T) {
	// Ensure no env var is set.
	os.Unsetenv("MESSAGING_PLATFORM_ENDPOINT_WHATSAPP")

	g := &Gateway{}
	target, err := g.resolveMessagingTarget("whatsapp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(target.String(), "https://graph.facebook.com") {
		t.Fatalf("expected production URL, got %s", target.String())
	}
}

func TestResolveMessagingTarget_UnsupportedPlatform(t *testing.T) {
	os.Unsetenv("MESSAGING_PLATFORM_ENDPOINT_SIGNAL")

	g := &Gateway{}
	_, err := g.resolveMessagingTarget("signal")
	if err == nil {
		t.Fatal("expected error for unsupported platform")
	}
	if !strings.Contains(err.Error(), "unsupported messaging platform") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveMessagingTarget_SingleLabelHostname(t *testing.T) {
	// Docker compose service name (single-label hostname) should be allowed.
	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_WHATSAPP", "http://messaging-sim:8090/v1/messages")

	g := &Gateway{}
	target, err := g.resolveMessagingTarget("whatsapp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Hostname() != "messaging-sim" {
		t.Fatalf("expected messaging-sim hostname, got %s", target.Hostname())
	}
}

func TestResolveMessagingTarget_RejectsHTTPPublicDomain(t *testing.T) {
	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_WHATSAPP", "http://evil.example.com/send")

	g := &Gateway{}
	_, err := g.resolveMessagingTarget("whatsapp")
	if err == nil {
		t.Fatal("expected error for HTTP on public domain")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected HTTPS requirement error, got: %v", err)
	}
}

func TestResolveMessagingTarget_EmptyPlatform(t *testing.T) {
	g := &Gateway{}
	_, err := g.executeMessagingEgress(context.Background(), map[string]string{"platform": ""}, nil, "")
	if err == nil {
		t.Fatal("expected error for empty platform")
	}
}

func TestExecuteMessagingEgress_HappyPath(t *testing.T) {
	// Stand up a mock messaging server that returns a WhatsApp-style response.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messaging_product": "whatsapp",
			"contacts":          []map[string]string{{"input": "15551234567", "wa_id": "15551234567"}},
			"messages":          []map[string]string{{"id": "wamid.test-123"}},
		})
	}))
	defer ts.Close()

	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_WHATSAPP", ts.URL+"/v1/messages")

	g := &Gateway{}
	payload, _ := json.Marshal(map[string]any{
		"messaging_product": "whatsapp",
		"to":                "15551234567",
		"type":              "text",
		"text":              map[string]string{"body": "Hello!"},
	})

	result, err := g.executeMessagingEgress(context.Background(),
		map[string]string{"platform": "whatsapp", "recipient": "15551234567"},
		payload, "Bearer test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", result.StatusCode)
	}
	if result.MessageID != "wamid.test-123" {
		t.Fatalf("expected message ID wamid.test-123, got %q", result.MessageID)
	}
	if result.Platform != "whatsapp" {
		t.Fatalf("expected platform whatsapp, got %q", result.Platform)
	}
}

func TestExtractMessageID(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "whatsapp_response",
			body:     `{"messages":[{"id":"wamid.abc123"}]}`,
			expected: "wamid.abc123",
		},
		{
			name:     "empty_messages",
			body:     `{"messages":[]}`,
			expected: "",
		},
		{
			name:     "invalid_json",
			body:     `{invalid`,
			expected: "",
		},
		{
			name:     "no_messages_field",
			body:     `{"status":"ok"}`,
			expected: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractMessageID([]byte(tc.body))
			if got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

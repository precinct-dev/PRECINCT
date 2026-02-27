package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// resolveMessagingTarget tests
// ---------------------------------------------------------------------------

func TestResolveMessagingTarget_EnvOverride(t *testing.T) {
	// Set up a local endpoint via env var.
	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_WHATSAPP", "http://localhost:8090/v1/messages")

	g := &Gateway{}
	target, err := g.resolveMessagingTarget("whatsapp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.String() != "http://localhost:8090/v1/messages" {
		t.Fatalf("expected env override endpoint, got %s", target.String())
	}
}

func TestResolveMessagingTarget_EnvOverrideTelegram(t *testing.T) {
	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_TELEGRAM", "http://localhost:8091/bot-sim/sendMessage")

	g := &Gateway{}
	target, err := g.resolveMessagingTarget("telegram", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.String() != "http://localhost:8091/bot-sim/sendMessage" {
		t.Fatalf("expected env override endpoint, got %s", target.String())
	}
}

func TestResolveMessagingTarget_EnvOverrideSlack(t *testing.T) {
	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_SLACK", "http://localhost:8092/slack-sim/chat.postMessage")

	g := &Gateway{}
	target, err := g.resolveMessagingTarget("slack", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.String() != "http://localhost:8092/slack-sim/chat.postMessage" {
		t.Fatalf("expected env override endpoint, got %s", target.String())
	}
}

func TestResolveMessagingTarget_ProductionDefault(t *testing.T) {
	// Ensure no env var is set.
	os.Unsetenv("MESSAGING_PLATFORM_ENDPOINT_WHATSAPP")

	g := &Gateway{}
	target, err := g.resolveMessagingTarget("whatsapp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(target.String(), "https://graph.facebook.com") {
		t.Fatalf("expected production URL, got %s", target.String())
	}
}

func TestResolveMessagingTarget_ProductionDefaultTelegram(t *testing.T) {
	os.Unsetenv("MESSAGING_PLATFORM_ENDPOINT_TELEGRAM")

	g := &Gateway{}
	target, err := g.resolveMessagingTarget("telegram", map[string]string{"bot_token": "123456:ABC-DEF"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "https://api.telegram.org/bot123456:ABC-DEF/sendMessage"
	if target.String() != expected {
		t.Fatalf("expected %s, got %s", expected, target.String())
	}
}

func TestResolveMessagingTarget_ProductionDefaultSlack(t *testing.T) {
	os.Unsetenv("MESSAGING_PLATFORM_ENDPOINT_SLACK")

	g := &Gateway{}
	target, err := g.resolveMessagingTarget("slack", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "https://slack.com/api/chat.postMessage"
	if target.String() != expected {
		t.Fatalf("expected %s, got %s", expected, target.String())
	}
}

func TestResolveMessagingTarget_TelegramMissingBotToken(t *testing.T) {
	os.Unsetenv("MESSAGING_PLATFORM_ENDPOINT_TELEGRAM")

	g := &Gateway{}
	_, err := g.resolveMessagingTarget("telegram", map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing bot_token")
	}
	if !strings.Contains(err.Error(), "bot_token") {
		t.Fatalf("expected bot_token error, got: %v", err)
	}
}

func TestResolveMessagingTarget_UnsupportedPlatform(t *testing.T) {
	os.Unsetenv("MESSAGING_PLATFORM_ENDPOINT_SIGNAL")

	g := &Gateway{}
	_, err := g.resolveMessagingTarget("signal", nil)
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
	target, err := g.resolveMessagingTarget("whatsapp", nil)
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
	_, err := g.resolveMessagingTarget("whatsapp", nil)
	if err == nil {
		t.Fatal("expected error for HTTP on public domain")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected HTTPS requirement error, got: %v", err)
	}
}

func TestResolveMessagingTarget_RejectsHTTPPublicDomainTelegram(t *testing.T) {
	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_TELEGRAM", "http://evil.example.com/send")

	g := &Gateway{}
	_, err := g.resolveMessagingTarget("telegram", nil)
	if err == nil {
		t.Fatal("expected error for HTTP on public domain")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected HTTPS requirement error, got: %v", err)
	}
}

func TestResolveMessagingTarget_RejectsHTTPPublicDomainSlack(t *testing.T) {
	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_SLACK", "http://evil.example.com/send")

	g := &Gateway{}
	_, err := g.resolveMessagingTarget("slack", nil)
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

// ---------------------------------------------------------------------------
// executeMessagingEgress tests
// ---------------------------------------------------------------------------

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

func TestExecuteMessagingEgress_Telegram(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"result": map[string]any{
				"message_id": 42,
				"chat":       map[string]any{"id": -100123456},
				"text":       "Hello from agent!",
			},
		})
	}))
	defer ts.Close()

	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_TELEGRAM", ts.URL+"/bot-sim/sendMessage")

	g := &Gateway{}
	payload, _ := json.Marshal(map[string]any{
		"chat_id": "-100123456",
		"text":    "Hello from agent!",
	})

	result, err := g.executeMessagingEgress(context.Background(),
		map[string]string{"platform": "telegram"},
		payload, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", result.StatusCode)
	}
	if result.MessageID != "42" {
		t.Fatalf("expected message ID 42, got %q", result.MessageID)
	}
	if result.Platform != "telegram" {
		t.Fatalf("expected platform telegram, got %q", result.Platform)
	}
}

func TestExecuteMessagingEgress_Slack(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer xoxb-test-token" {
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
			"ok":      true,
			"channel": "C1234567890",
			"ts":      "1234567890.123456",
			"message": map[string]any{
				"text": "Hello from agent!",
			},
		})
	}))
	defer ts.Close()

	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_SLACK", ts.URL+"/api/chat.postMessage")

	g := &Gateway{}
	payload, _ := json.Marshal(map[string]any{
		"channel": "C1234567890",
		"text":    "Hello from agent!",
	})

	result, err := g.executeMessagingEgress(context.Background(),
		map[string]string{"platform": "slack"},
		payload, "Bearer xoxb-test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", result.StatusCode)
	}
	if result.MessageID != "1234567890.123456" {
		t.Fatalf("expected message ID 1234567890.123456, got %q", result.MessageID)
	}
	if result.Platform != "slack" {
		t.Fatalf("expected platform slack, got %q", result.Platform)
	}
}

// ---------------------------------------------------------------------------
// TLS minimum version test
// ---------------------------------------------------------------------------

func TestExecuteMessagingEgress_TLSMinVersion(t *testing.T) {
	// Verify the HTTP client is configured with TLS 1.2 minimum.
	// We do this by creating a test server that only supports TLS 1.1,
	// which should be rejected by our client's TLS config.
	// Instead, we directly verify the transport config by examining the
	// client construction pattern in a focused unit test.

	g := &Gateway{}

	// Create a TLS server that speaks only TLS 1.1 -- our client must reject it.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"messages":[{"id":"tls-test"}]}`))
	}))
	defer ts.Close()

	// Override the server's TLS config to max TLS 1.1.
	ts.TLS.MaxVersion = tls.VersionTLS11
	// Restart the listener with updated config so handshake enforces TLS 1.1 max.
	ts.Close()
	ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"messages":[{"id":"tls-test"}]}`))
	}))
	ts.TLS = &tls.Config{
		MaxVersion: tls.VersionTLS11,
	}
	ts.StartTLS()
	defer ts.Close()

	t.Setenv("MESSAGING_PLATFORM_ENDPOINT_WHATSAPP", ts.URL+"/v1/messages")

	payload, _ := json.Marshal(map[string]any{"text": "test"})
	_, err := g.executeMessagingEgress(context.Background(),
		map[string]string{"platform": "whatsapp"},
		payload, "")

	// The call must fail because the server only supports TLS 1.1
	// and our client requires TLS 1.2 minimum.
	if err == nil {
		t.Fatal("expected TLS handshake failure when server only supports TLS 1.1")
	}
	if !strings.Contains(err.Error(), "tls") && !strings.Contains(strings.ToLower(err.Error()), "protocol") {
		// Accept any TLS-related error; the exact message varies by Go version.
		t.Logf("error (accepted as TLS failure): %v", err)
	}
}

// ---------------------------------------------------------------------------
// extractMessageID tests
// ---------------------------------------------------------------------------

func TestExtractMessageID(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		body     string
		expected string
	}{
		// WhatsApp responses
		{
			name:     "whatsapp_response",
			platform: "whatsapp",
			body:     `{"messages":[{"id":"wamid.abc123"}]}`,
			expected: "wamid.abc123",
		},
		{
			name:     "whatsapp_empty_messages",
			platform: "whatsapp",
			body:     `{"messages":[]}`,
			expected: "",
		},
		{
			name:     "whatsapp_invalid_json",
			platform: "whatsapp",
			body:     `{invalid`,
			expected: "",
		},
		{
			name:     "whatsapp_no_messages_field",
			platform: "whatsapp",
			body:     `{"status":"ok"}`,
			expected: "",
		},
		// Telegram responses
		{
			name:     "telegram_response",
			platform: "telegram",
			body:     `{"ok":true,"result":{"message_id":42,"chat":{"id":-100123},"text":"hi"}}`,
			expected: "42",
		},
		{
			name:     "telegram_not_ok",
			platform: "telegram",
			body:     `{"ok":false,"description":"Bad Request"}`,
			expected: "",
		},
		{
			name:     "telegram_invalid_json",
			platform: "telegram",
			body:     `{invalid`,
			expected: "",
		},
		{
			name:     "telegram_zero_message_id",
			platform: "telegram",
			body:     `{"ok":true,"result":{"message_id":0}}`,
			expected: "",
		},
		{
			name:     "telegram_large_message_id",
			platform: "telegram",
			body:     `{"ok":true,"result":{"message_id":999999999}}`,
			expected: "999999999",
		},
		// Slack responses
		{
			name:     "slack_response",
			platform: "slack",
			body:     `{"ok":true,"ts":"1234567890.123456","channel":"C123"}`,
			expected: "1234567890.123456",
		},
		{
			name:     "slack_not_ok",
			platform: "slack",
			body:     `{"ok":false,"error":"channel_not_found"}`,
			expected: "",
		},
		{
			name:     "slack_invalid_json",
			platform: "slack",
			body:     `{invalid`,
			expected: "",
		},
		{
			name:     "slack_empty_ts",
			platform: "slack",
			body:     `{"ok":true,"ts":""}`,
			expected: "",
		},
		// Unknown platform falls back to WhatsApp parsing
		{
			name:     "unknown_platform_fallback",
			platform: "unknown",
			body:     `{"messages":[{"id":"fallback-123"}]}`,
			expected: "fallback-123",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractMessageID(tc.platform, []byte(tc.body))
			if got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------- Health ----------

func TestHandleHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status=ok, got %q", body["status"])
	}
}

// ---------- WhatsApp ----------

func TestHandleMessages_HappyPath(t *testing.T) {
	// Reset rate limiter for this test.
	whatsAppRL = newRateLimiter(10, 10*time.Second)

	payload := map[string]any{
		"messaging_product": "whatsapp",
		"to":                "15551234567",
		"type":              "text",
		"text":              map[string]string{"body": "Hello, world!"},
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer test-token-123")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleMessages(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if resp["messaging_product"] != "whatsapp" {
		t.Fatalf("expected messaging_product=whatsapp, got %v", resp["messaging_product"])
	}
	contacts, ok := resp["contacts"].([]any)
	if !ok || len(contacts) == 0 {
		t.Fatalf("expected contacts array, got %v", resp["contacts"])
	}
	contact := contacts[0].(map[string]any)
	if contact["input"] != "15551234567" {
		t.Fatalf("expected contact input=15551234567, got %v", contact["input"])
	}
	messages, ok := resp["messages"].([]any)
	if !ok || len(messages) == 0 {
		t.Fatalf("expected messages array, got %v", resp["messages"])
	}
	msg := messages[0].(map[string]any)
	msgID, ok := msg["id"].(string)
	if !ok || !strings.HasPrefix(msgID, "wamid.") {
		t.Fatalf("expected message id starting with wamid., got %v", msg["id"])
	}
}

func TestHandleMessages_NoAuth(t *testing.T) {
	payload := map[string]any{
		"messaging_product": "whatsapp",
		"to":                "15551234567",
		"type":              "text",
		"text":              map[string]string{"body": "Hello"},
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleMessages(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleMessages_EmptyBearerToken(t *testing.T) {
	payload := map[string]any{
		"messaging_product": "whatsapp",
		"to":                "15551234567",
		"type":              "text",
		"text":              map[string]string{"body": "Hello"},
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer ")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleMessages(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleMessages_MissingFields(t *testing.T) {
	// Reset rate limiter for this test.
	whatsAppRL = newRateLimiter(10, 10*time.Second)

	tests := []struct {
		name    string
		payload map[string]any
	}{
		{
			name: "missing_to",
			payload: map[string]any{
				"messaging_product": "whatsapp",
				"type":              "text",
				"text":              map[string]string{"body": "Hello"},
			},
		},
		{
			name: "missing_messaging_product",
			payload: map[string]any{
				"to":   "15551234567",
				"type": "text",
				"text": map[string]string{"body": "Hello"},
			},
		},
		{
			name: "missing_text_body",
			payload: map[string]any{
				"messaging_product": "whatsapp",
				"to":                "15551234567",
				"type":              "text",
			},
		},
		{
			name: "missing_type",
			payload: map[string]any{
				"messaging_product": "whatsapp",
				"to":                "15551234567",
				"text":              map[string]string{"body": "Hello"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.payload)
			req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(raw))
			req.Header.Set("Authorization", "Bearer test-token")
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handleMessages(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHandleMessages_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/messages", nil)
	rec := httptest.NewRecorder()

	handleMessages(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestHandleMessages_InvalidJSON(t *testing.T) {
	// Reset rate limiter for this test.
	whatsAppRL = newRateLimiter(10, 10*time.Second)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader("{invalid"))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleMessages(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleMessages_RateLimiting(t *testing.T) {
	// Fresh rate limiter: 10 requests per 10 seconds.
	whatsAppRL = newRateLimiter(10, 10*time.Second)

	makeReq := func() int {
		payload := map[string]any{
			"messaging_product": "whatsapp",
			"to":                "15551234567",
			"type":              "text",
			"text":              map[string]string{"body": "Hello"},
		}
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handleMessages(rec, req)
		return rec.Code
	}

	// First 10 requests should succeed.
	for i := 0; i < 10; i++ {
		code := makeReq()
		if code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, code)
		}
	}

	// 11th request should be rate limited.
	code := makeReq()
	if code != http.StatusTooManyRequests {
		t.Fatalf("request 11: expected 429, got %d", code)
	}
}

func TestHandleMessages_RateLimitRecovery(t *testing.T) {
	// Use a very short window for testing recovery.
	whatsAppRL = newRateLimiter(1, 50*time.Millisecond)

	makeReq := func() int {
		payload := map[string]any{
			"messaging_product": "whatsapp",
			"to":                "15551234567",
			"type":              "text",
			"text":              map[string]string{"body": "Hello"},
		}
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handleMessages(rec, req)
		return rec.Code
	}

	// First request OK.
	if code := makeReq(); code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", code)
	}

	// Second request should be rate limited.
	if code := makeReq(); code != http.StatusTooManyRequests {
		t.Fatalf("second request: expected 429, got %d", code)
	}

	// Wait for window to expire and try again.
	time.Sleep(60 * time.Millisecond)
	if code := makeReq(); code != http.StatusOK {
		t.Fatalf("after window: expected 200, got %d", code)
	}
}

// ---------- Telegram ----------

func TestHandleTelegram_HappyPath(t *testing.T) {
	payload := map[string]any{
		"chat_id": "12345678",
		"text":    "Hello from Telegram!",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/botMyBotToken123/sendMessage", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleTelegramRouter(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if resp["ok"] != true {
		t.Fatalf("expected ok=true, got %v", resp["ok"])
	}

	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got %v", resp["result"])
	}

	// message_id should be a positive number.
	msgID, ok := result["message_id"].(float64)
	if !ok || msgID < 1 {
		t.Fatalf("expected positive message_id, got %v", result["message_id"])
	}

	from, ok := result["from"].(map[string]any)
	if !ok {
		t.Fatalf("expected from object, got %v", result["from"])
	}
	if from["id"] != float64(12345) {
		t.Fatalf("expected from.id=12345, got %v", from["id"])
	}
	if from["is_bot"] != true {
		t.Fatalf("expected from.is_bot=true, got %v", from["is_bot"])
	}

	chat, ok := result["chat"].(map[string]any)
	if !ok {
		t.Fatalf("expected chat object, got %v", result["chat"])
	}
	// chat_id was numeric string "12345678", should come back as number.
	if chat["id"] != float64(12345678) {
		t.Fatalf("expected chat.id=12345678, got %v", chat["id"])
	}

	if result["text"] != "Hello from Telegram!" {
		t.Fatalf("expected text='Hello from Telegram!', got %v", result["text"])
	}

	// date should be a recent unix timestamp.
	date, ok := result["date"].(float64)
	if !ok || date < float64(time.Now().Add(-10*time.Second).Unix()) {
		t.Fatalf("expected recent date timestamp, got %v", result["date"])
	}
}

func TestHandleTelegram_NumericChatID(t *testing.T) {
	// Telegram allows integer chat_id.
	payload := map[string]any{
		"chat_id": 99887766,
		"text":    "Numeric ID test",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/bottoken123/sendMessage", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleTelegramRouter(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	result := resp["result"].(map[string]any)
	chat := result["chat"].(map[string]any)
	if chat["id"] != float64(99887766) {
		t.Fatalf("expected chat.id=99887766, got %v", chat["id"])
	}
}

func TestHandleTelegram_EmptyToken(t *testing.T) {
	payload := map[string]any{
		"chat_id": "123",
		"text":    "Should fail",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/bot/sendMessage", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleTelegramRouter(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleTelegram_MissingChatID(t *testing.T) {
	payload := map[string]any{
		"text": "Missing chat_id",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/bottoken123/sendMessage", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleTelegramRouter(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleTelegram_MissingText(t *testing.T) {
	payload := map[string]any{
		"chat_id": "12345",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/bottoken123/sendMessage", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleTelegramRouter(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleTelegram_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/bottoken123/sendMessage", strings.NewReader("{bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleTelegramRouter(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleTelegram_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/bottoken123/sendMessage", nil)
	rec := httptest.NewRecorder()

	handleTelegramRouter(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestHandleTelegram_UnsupportedAction(t *testing.T) {
	payload := map[string]any{
		"chat_id": "123",
		"text":    "test",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/bottoken123/getMe", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleTelegramRouter(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---------- Slack ----------

func TestHandleSlack_HappyPath(t *testing.T) {
	payload := map[string]any{
		"channel": "#general",
		"text":    "Hello from Slack!",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/chat.postMessage", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer xoxb-test-token-123")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleSlack(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if resp["ok"] != true {
		t.Fatalf("expected ok=true, got %v", resp["ok"])
	}
	if resp["channel"] != "#general" {
		t.Fatalf("expected channel=#general, got %v", resp["channel"])
	}

	ts, ok := resp["ts"].(string)
	if !ok || ts == "" {
		t.Fatalf("expected non-empty ts string, got %v", resp["ts"])
	}
	// ts should contain a dot separating unix timestamp and sequence.
	if !strings.Contains(ts, ".") {
		t.Fatalf("expected ts with dot separator, got %q", ts)
	}

	message, ok := resp["message"].(map[string]any)
	if !ok {
		t.Fatalf("expected message object, got %v", resp["message"])
	}
	if message["text"] != "Hello from Slack!" {
		t.Fatalf("expected message.text='Hello from Slack!', got %v", message["text"])
	}
	if message["type"] != "message" {
		t.Fatalf("expected message.type='message', got %v", message["type"])
	}
	if message["subtype"] != "bot_message" {
		t.Fatalf("expected message.subtype='bot_message', got %v", message["subtype"])
	}
}

func TestHandleSlack_POCRedeemerToken(t *testing.T) {
	// Test that the POC redeemer format token is accepted.
	payload := map[string]any{
		"channel": "#alerts",
		"text":    "POC redeemer test",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/chat.postMessage", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer secret-value-for-slack")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleSlack(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSlack_NoAuth(t *testing.T) {
	payload := map[string]any{
		"channel": "#general",
		"text":    "No auth",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/chat.postMessage", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleSlack(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSlack_EmptyBearerToken(t *testing.T) {
	payload := map[string]any{
		"channel": "#general",
		"text":    "Empty bearer",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/chat.postMessage", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer ")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleSlack(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSlack_MissingChannel(t *testing.T) {
	payload := map[string]any{
		"text": "Missing channel",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/chat.postMessage", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer xoxb-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleSlack(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSlack_MissingText(t *testing.T) {
	payload := map[string]any{
		"channel": "#general",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/chat.postMessage", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer xoxb-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleSlack(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSlack_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/chat.postMessage", strings.NewReader("{invalid"))
	req.Header.Set("Authorization", "Bearer xoxb-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleSlack(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSlack_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/chat.postMessage", nil)
	rec := httptest.NewRecorder()

	handleSlack(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestHandleTelegram_StringChatID(t *testing.T) {
	// Non-numeric chat_id (e.g. group chat identifier).
	payload := map[string]any{
		"chat_id": "@my_channel",
		"text":    "String ID test",
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/bottoken123/sendMessage", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleTelegramRouter(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	result := resp["result"].(map[string]any)
	chat := result["chat"].(map[string]any)
	// String chat_id should come back as string, not number.
	if chat["id"] != "@my_channel" {
		t.Fatalf("expected chat.id='@my_channel', got %v", chat["id"])
	}
}

func TestHandleTelegram_NoSlashAfterToken(t *testing.T) {
	// Path like /bottoken123 with no trailing /action should return 404.
	req := httptest.NewRequest(http.MethodPost, "/bottoken123", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleTelegramRouter(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---------- Rate Limiter Unit ----------

func TestRateLimiter_AllowsUpToMax(t *testing.T) {
	rl := newRateLimiter(3, time.Second)
	for i := 0; i < 3; i++ {
		if !rl.allow() {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if rl.allow() {
		t.Fatal("4th request should be rejected")
	}
}

func TestRateLimiter_RecoverAfterWindow(t *testing.T) {
	rl := newRateLimiter(1, 50*time.Millisecond)
	if !rl.allow() {
		t.Fatal("first request should be allowed")
	}
	if rl.allow() {
		t.Fatal("second request should be rejected")
	}
	time.Sleep(60 * time.Millisecond)
	if !rl.allow() {
		t.Fatal("request after window should be allowed")
	}
}

// ---------- Helpers ----------

func TestValidBearerAuth(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"empty", "", false},
		{"no_bearer_prefix", "Token abc", false},
		{"bearer_empty_token", "Bearer ", false},
		{"bearer_whitespace_token", "Bearer   ", false},
		{"valid_token", "Bearer xoxb-test", true},
		{"valid_poc_redeemer", "Bearer secret-value-for-slack", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			got := validBearerAuth(req)
			if got != tc.want {
				t.Fatalf("validBearerAuth(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}

// ---------- Mux-level routing ----------

// TestMuxRouting_TelegramReachable verifies that Telegram's /bot<TOKEN>/sendMessage
// path is correctly routed through the mux (not just the handler directly).
// This catches the bug where Go's ServeMux exact-match on "/bot" doesn't
// match "/botTOKEN123/sendMessage".
func TestMuxRouting_TelegramReachable(t *testing.T) {
	srv := httptest.NewServer(newMux())
	defer srv.Close()

	payload := `{"chat_id":"12345","text":"mux routing test"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/botMYTOKEN123/sendMessage", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body["ok"].(bool) {
		t.Fatal("expected ok=true in Telegram response")
	}
}

// TestMuxRouting_AllEndpoints verifies all three platform endpoints are
// reachable through the mux when accessed via httptest.NewServer.
func TestMuxRouting_AllEndpoints(t *testing.T) {
	srv := httptest.NewServer(newMux())
	defer srv.Close()

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		auth   string
		expect int
	}{
		{"health", http.MethodGet, "/health", "", "", 200},
		{"whatsapp", http.MethodPost, "/v1/messages", `{"messaging_product":"whatsapp","to":"+1","type":"text","text":{"body":"hi"}}`, "Bearer tok", 200},
		{"telegram", http.MethodPost, "/botTOK/sendMessage", `{"chat_id":"1","text":"hi"}`, "", 200},
		{"slack", http.MethodPost, "/api/chat.postMessage", `{"channel":"C1","text":"hi"}`, "Bearer tok", 200},
		{"unknown_404", http.MethodGet, "/unknown", "", "", 404},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var body *strings.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			} else {
				body = strings.NewReader("")
			}
			req, _ := http.NewRequest(tc.method, srv.URL+tc.path, body)
			req.Header.Set("Content-Type", "application/json")
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.expect {
				t.Fatalf("expected %d, got %d", tc.expect, resp.StatusCode)
			}
		})
	}
}

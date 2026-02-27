package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

func TestHandleMessages_HappyPath(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader("{invalid"))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleMessages(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// Messaging Simulator -- WhatsApp, Telegram, and Slack API compatible stub for POC.
// Provides POST /v1/messages (WhatsApp), POST /bot<token>/sendMessage (Telegram),
// POST /api/chat.postMessage (Slack), and GET /health.
// Usage:
//
//	messaging-sim               # listen on PORT (default 8090)
//	messaging-sim -healthcheck  # GET /health and exit 0/1
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// rateLimiter tracks request timestamps for sliding-window rate limiting.
type rateLimiter struct {
	mu         sync.Mutex
	timestamps []time.Time
	maxReqs    int
	window     time.Duration
}

// newRateLimiter creates a rate limiter allowing maxReqs in the given window.
func newRateLimiter(maxReqs int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		maxReqs: maxReqs,
		window:  window,
	}
}

// allow checks whether a new request is permitted. Returns true if allowed.
func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Evict expired timestamps.
	valid := 0
	for _, ts := range rl.timestamps {
		if ts.After(cutoff) {
			rl.timestamps[valid] = ts
			valid++
		}
	}
	rl.timestamps = rl.timestamps[:valid]

	if len(rl.timestamps) >= rl.maxReqs {
		return false
	}

	rl.timestamps = append(rl.timestamps, now)
	return true
}

// whatsAppRL is the rate limiter for the WhatsApp endpoint: >10 in 10s triggers 429.
var whatsAppRL = newRateLimiter(10, 10*time.Second)

// telegramMsgSeq is a monotonic counter for Telegram message IDs.
var telegramMsgSeq atomic.Int64

// slackTsSeq is a monotonic counter for Slack message timestamps.
var slackTsSeq atomic.Int64

func main() {
	healthcheck := flag.Bool("healthcheck", false, "perform a health check and exit 0/1")
	flag.Parse()

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8090"
	}

	if *healthcheck {
		resp, err := http.Get("http://127.0.0.1:" + port + "/health")
		if err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "healthcheck returned %d\n", resp.StatusCode)
			os.Exit(1)
		}
		os.Exit(0)
	}

	mux := newMux()

	addr := ":" + port
	slog.Info("messaging-sim starting", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

// newMux builds the HTTP handler with all routes. Exported for testing.
func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/messages", handleMessages)
	mux.HandleFunc("/api/chat.postMessage", handleSlack)
	// Telegram Bot API: /bot<TOKEN>/sendMessage -- the token is concatenated
	// directly after "/bot" with no separator, so Go's ServeMux exact-match
	// on "/bot" won't work. Use a catch-all "/" handler that dispatches by prefix.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/bot") {
			handleTelegramRouter(w, r)
			return
		}
		http.NotFound(w, r)
	})
	return mux
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// ---------- WhatsApp ----------

func handleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Require Authorization header with a non-empty Bearer token.
	if !validBearerAuth(r) {
		jsonError(w, http.StatusUnauthorized, "missing or empty authorization token")
		return
	}

	// Rate limiting: 429 if >10 requests in 10 seconds.
	if !whatsAppRL.allow() {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "10")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate limit exceeded","retry_after_secs":10}`))
		return
	}

	var body struct {
		MessagingProduct string `json:"messaging_product"`
		To               string `json:"to"`
		Type             string `json:"type"`
		Text             *struct {
			Body string `json:"body"`
		} `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate required fields.
	var missing []string
	if strings.TrimSpace(body.MessagingProduct) == "" {
		missing = append(missing, "messaging_product")
	}
	if strings.TrimSpace(body.To) == "" {
		missing = append(missing, "to")
	}
	if strings.TrimSpace(body.Type) == "" {
		missing = append(missing, "type")
	}
	if body.Text == nil || strings.TrimSpace(body.Text.Body) == "" {
		missing = append(missing, "text.body")
	}
	if len(missing) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		resp, _ := json.Marshal(map[string]any{
			"error":          "missing required fields",
			"missing_fields": missing,
		})
		_, _ = w.Write(resp)
		return
	}

	// Return WhatsApp Cloud API-compatible response.
	messageID := "wamid." + uuid.New().String()
	resp := map[string]any{
		"messaging_product": "whatsapp",
		"contacts": []map[string]string{
			{"input": body.To, "wa_id": body.To},
		},
		"messages": []map[string]string{
			{"id": messageID},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ---------- Telegram Bot API ----------

// handleTelegramRouter routes /bot<token>/sendMessage requests.
// Go 1.22+ ServeMux matches /bot as a prefix for /bot<anything>.
func handleTelegramRouter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Parse path: expect /bot<token>/sendMessage
	path := r.URL.Path
	if !strings.HasPrefix(path, "/bot") {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}

	// Strip "/bot" prefix to get "<token>/sendMessage"
	rest := path[len("/bot"):]

	// Split into token and action.
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}

	token := rest[:slashIdx]
	action := rest[slashIdx+1:]

	// Validate token is non-empty (auth).
	if strings.TrimSpace(token) == "" {
		jsonError(w, http.StatusUnauthorized, "missing or empty bot token")
		return
	}

	if action != "sendMessage" {
		jsonError(w, http.StatusNotFound, "unsupported action")
		return
	}

	handleTelegramSendMessage(w, r)
}

func handleTelegramSendMessage(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChatID json.RawMessage `json:"chat_id"`
		Text   string          `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// chat_id can be string or integer in Telegram API; normalize to string.
	chatID := strings.Trim(strings.TrimSpace(string(body.ChatID)), `"`)
	if chatID == "" || chatID == "null" {
		jsonError(w, http.StatusBadRequest, "missing required field: chat_id")
		return
	}
	if strings.TrimSpace(body.Text) == "" {
		jsonError(w, http.StatusBadRequest, "missing required field: text")
		return
	}

	msgID := telegramMsgSeq.Add(1)
	now := time.Now().Unix()

	resp := map[string]any{
		"ok": true,
		"result": map[string]any{
			"message_id": msgID,
			"from": map[string]any{
				"id":     12345,
				"is_bot": true,
			},
			"chat": map[string]any{
				"id": chatIDValue(chatID),
			},
			"date": now,
			"text": body.Text,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// chatIDValue attempts to return chat_id as an integer if possible, else string.
func chatIDValue(s string) any {
	// Try to parse as integer for realistic Telegram response.
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
		return n
	}
	return s
}

// ---------- Slack Web API ----------

func handleSlack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Require Authorization header with a non-empty Bearer token.
	if !validBearerAuth(r) {
		jsonError(w, http.StatusUnauthorized, "missing or empty authorization token")
		return
	}

	var body struct {
		Channel string `json:"channel"`
		Text    string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if strings.TrimSpace(body.Channel) == "" {
		jsonError(w, http.StatusBadRequest, "missing required field: channel")
		return
	}
	if strings.TrimSpace(body.Text) == "" {
		jsonError(w, http.StatusBadRequest, "missing required field: text")
		return
	}

	seq := slackTsSeq.Add(1)
	ts := fmt.Sprintf("%d.%06d", time.Now().Unix(), seq)

	resp := map[string]any{
		"ok":      true,
		"channel": body.Channel,
		"ts":      ts,
		"message": map[string]any{
			"text":    body.Text,
			"type":    "message",
			"subtype": "bot_message",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ---------- Helpers ----------

// validBearerAuth checks for a non-empty Bearer token in the Authorization header.
func validBearerAuth(r *http.Request) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	return token != ""
}

// jsonError writes a JSON error response.
func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	resp, _ := json.Marshal(map[string]string{"error": msg})
	_, _ = w.Write(resp)
}

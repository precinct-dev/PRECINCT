// Messaging Simulator -- WhatsApp Cloud API compatible stub for POC.
// Provides POST /v1/messages (WhatsApp-style) and GET /health.
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

	"github.com/google/uuid"
)

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

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/messages", handleMessages)

	addr := ":" + port
	slog.Info("messaging-sim starting", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func handleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Require Authorization header with a non-empty Bearer token.
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"missing or empty authorization token"}`))
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid JSON body"}`))
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

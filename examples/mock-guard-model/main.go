// demo/mock-guard-model/main.go -- Minimal mock "OpenAI chat completions" endpoint
// used to deterministically exercise Deep Scan (Step 10) in demo-compose.
//
// DeepScanner posts to: {GUARD_MODEL_ENDPOINT}/chat/completions
// where GUARD_MODEL_ENDPOINT defaults to https://api.groq.com/openai/v1.
//
// We deterministically classify obviously suspicious payloads as malicious and
// everything else as benign. This keeps demo-compose security proofs stable
// without accidentally blocking all medium-risk traffic that goes through the
// step-up guard path.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type chatCompletionRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

type chatCompletionResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
}

func classifyPromptGuardContent(messages []struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}) string {
	var parts []string
	for _, msg := range messages {
		parts = append(parts, msg.Content)
	}
	content := strings.ToLower(strings.Join(parts, "\n"))

	suspiciousSignals := []string{
		"ignore all previous instructions",
		"reveal your system prompt",
		"system prompt",
		"dan mode",
		"do anything now",
		"unrestricted ai",
		"new instructions:",
		"bypass all security",
		"forget everything you were told",
		"disregard all previous rules",
		"bypass all security checks",
		"grant admin access",
		"pretend to be a dan",
		"jailbreak",
	}
	for _, signal := range suspiciousSignals {
		if strings.Contains(content, signal) {
			return "MALICIOUS"
		}
	}

	return "BENIGN"
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "perform a health check and exit 0/1")
	flag.Parse()

	port := "8080"

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

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/openai/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req chatCompletionRequest
		_ = json.NewDecoder(r.Body).Decode(&req) // best-effort (we don't need content)

		classification := classifyPromptGuardContent(req.Messages)

		resp := chatCompletionResponse{
			ID:      "mock-guard-" + time.Now().UTC().Format("20060102T150405Z"),
			Object:  "chat.completion",
			Created: time.Now().Unix(),
			Model:   req.Model,
			Choices: []struct {
				Index   int `json:"index"`
				Message struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			}{
				{
					Index: 0,
					Message: struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					}{
						Role:    "assistant",
						Content: classification,
					},
					FinishReason: "stop",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	addr := ":" + port
	log.Printf("[mock-guard] listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

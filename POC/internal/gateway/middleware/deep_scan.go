package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DeepScanner handles async deep scanning using Groq Prompt Guard 2
type DeepScanner struct {
	groqAPIKey  string
	groqBaseURL string
	timeout     time.Duration
	resultChan  chan DeepScanResult
	httpClient  *http.Client
}

// DeepScanResult contains the results of a deep scan
type DeepScanResult struct {
	RequestID      string
	TraceID        string
	Timestamp      time.Time
	InjectionScore float64 // 0.0 to 1.0
	JailbreakScore float64 // 0.0 to 1.0
	ModelUsed      string
	LatencyMs      int64
	Error          error
}

// GroqClassificationResponse is the response from Groq API
type GroqClassificationResponse struct {
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
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// PromptGuardResponse is the parsed classification result
type PromptGuardResponse struct {
	InjectionProbability float64
	JailbreakProbability float64
}

// NewDeepScanner creates a new deep scanner with Groq API
func NewDeepScanner(apiKey string, timeout time.Duration) *DeepScanner {
	return &DeepScanner{
		groqAPIKey:  apiKey,
		groqBaseURL: "https://api.groq.com/openai/v1",
		timeout:     timeout,
		resultChan:  make(chan DeepScanResult, 100), // Buffered channel
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// DispatchAsync dispatches a deep scan asynchronously
func (d *DeepScanner) DispatchAsync(ctx context.Context, content string, traceID string) {
	go func() {
		result := d.scan(ctx, content, traceID)
		select {
		case d.resultChan <- result:
			// Result queued
		default:
			// Channel full, drop result (fail open)
		}
	}()
}

// Scan performs a deep scan and returns the result (public method for testing)
func (d *DeepScanner) Scan(ctx context.Context, content string, traceID string) DeepScanResult {
	return d.scan(ctx, content, traceID)
}

// scan performs the actual deep scan using Groq Prompt Guard 2
func (d *DeepScanner) scan(ctx context.Context, content string, traceID string) DeepScanResult {
	start := time.Now()
	result := DeepScanResult{
		TraceID:   traceID,
		Timestamp: start,
		ModelUsed: "meta-llama/Prompt-Guard-86M",
	}

	// If no API key, fail open
	if d.groqAPIKey == "" {
		result.Error = fmt.Errorf("no Groq API key configured")
		return result
	}

	// Call Groq API for Prompt Guard 2 classification
	pgResult, err := d.classifyWithPromptGuard(ctx, content)
	if err != nil {
		result.Error = err
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}

	result.InjectionScore = pgResult.InjectionProbability
	result.JailbreakScore = pgResult.JailbreakProbability
	result.LatencyMs = time.Since(start).Milliseconds()

	return result
}

// classifyWithPromptGuard calls Groq API with Prompt Guard 2 model
func (d *DeepScanner) classifyWithPromptGuard(ctx context.Context, content string) (PromptGuardResponse, error) {
	// Construct request to Groq API
	reqBody := map[string]interface{}{
		"model": "meta-llama/Prompt-Guard-86M",
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": content,
			},
		},
		"max_tokens": 10,
		"temperature": 0.0,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return PromptGuardResponse{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", d.groqBaseURL+"/chat/completions", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return PromptGuardResponse{}, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+d.groqAPIKey)
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return PromptGuardResponse{}, fmt.Errorf("failed to call Groq API: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return PromptGuardResponse{}, fmt.Errorf("groq API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var groqResp GroqClassificationResponse
	if err := json.NewDecoder(resp.Body).Decode(&groqResp); err != nil {
		return PromptGuardResponse{}, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract classification from response
	// Prompt Guard 2 returns probabilities in the response content
	if len(groqResp.Choices) == 0 {
		return PromptGuardResponse{}, fmt.Errorf("no choices in response")
	}

	// Parse the classification response
	// Prompt Guard 2 format: "INJECTION: 0.85, JAILBREAK: 0.12"
	// For simplicity in POC, we'll use a heuristic based on model response
	content = groqResp.Choices[0].Message.Content

	// Simple heuristic: If model flags injection patterns, assign higher score
	// In production, Prompt Guard 2 provides structured output
	pgResp := PromptGuardResponse{
		InjectionProbability: 0.0,
		JailbreakProbability: 0.0,
	}

	// Parse structured output if available, otherwise use heuristic
	// For POC, we use a simple keyword-based heuristic
	if containsKeyword(content, []string{"injection", "malicious", "attack", "exploit"}) {
		pgResp.InjectionProbability = 0.7
	}
	if containsKeyword(content, []string{"jailbreak", "bypass", "override", "ignore"}) {
		pgResp.JailbreakProbability = 0.7
	}

	return pgResp, nil
}

// containsKeyword checks if content contains any of the keywords
func containsKeyword(content string, keywords []string) bool {
	for _, keyword := range keywords {
		if len(content) >= len(keyword) {
			for i := 0; i <= len(content)-len(keyword); i++ {
				if content[i:i+len(keyword)] == keyword {
					return true
				}
			}
		}
	}
	return false
}

// DeepScanMiddleware creates middleware for async deep scanning
// Position: Step 10, after step-up gating
func DeepScanMiddleware(next http.Handler, scanner *DeepScanner) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get security flags from context (set by DLP middleware)
		flags := GetSecurityFlags(ctx)

		// Determine if deep scan should be dispatched
		if shouldDispatchDeepScan(flags) {
			// Get request body and trace ID
			body := GetRequestBody(ctx)
			traceID := GetTraceID(ctx)

			if body != nil {
				// Dispatch async - does NOT block the fast path
				scanner.DispatchAsync(ctx, string(body), traceID)
			}
		}

		// Continue fast path immediately (async dispatch above)
		next.ServeHTTP(w, r)
	})
}

// shouldDispatchDeepScan determines if a deep scan should be dispatched
func shouldDispatchDeepScan(flags []string) bool {
	if flags == nil {
		return false
	}

	// Dispatch if potential_injection flag is present
	for _, flag := range flags {
		if flag == "potential_injection" {
			return true
		}
	}

	return false
}

// shouldTriggerAlert determines if high scores warrant an alert
func shouldTriggerAlert(injectionScore, jailbreakScore float64) bool {
	// Alert threshold: 0.8 or higher
	return injectionScore > 0.8 || jailbreakScore > 0.8
}

// Context keys for deep scan
const contextKeyDeepScanResult contextKey = "deep_scan_result"

// WithDeepScanResult adds deep scan result to context
func WithDeepScanResult(ctx context.Context, result DeepScanResult) context.Context {
	return context.WithValue(ctx, contextKeyDeepScanResult, result)
}

// GetDeepScanResult retrieves deep scan result from context
func GetDeepScanResult(ctx context.Context) *DeepScanResult {
	if v := ctx.Value(contextKeyDeepScanResult); v != nil {
		result := v.(DeepScanResult)
		return &result
	}
	return nil
}

// ResultProcessor processes deep scan results asynchronously
// This runs as a goroutine in the background
func (d *DeepScanner) ResultProcessor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case result := <-d.resultChan:
			// Process result
			if result.Error != nil {
				// Log error but continue (fail open)
				continue
			}

			// Check for high scores and trigger alerts
			if shouldTriggerAlert(result.InjectionScore, result.JailbreakScore) {
				// In production: send to alert system
				// For POC: log to stdout
				fmt.Printf("ALERT: High injection/jailbreak scores detected - RequestID: %s, InjectionScore: %.2f, JailbreakScore: %.2f\n",
					result.RequestID, result.InjectionScore, result.JailbreakScore)
			}

			// Store result for audit (in production: write to audit log)
			// For POC: this is a placeholder
		}
	}
}

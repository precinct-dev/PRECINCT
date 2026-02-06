package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DeepScanFallbackMode defines behavior when the Groq API is unavailable
type DeepScanFallbackMode string

const (
	// FailClosed blocks the request when Groq API is unavailable
	FailClosed DeepScanFallbackMode = "fail_closed"
	// FailOpen allows the request when Groq API is unavailable
	FailOpen DeepScanFallbackMode = "fail_open"
)

// DeepScanner handles deep scanning using Groq Prompt Guard 2.
// When DLP flags a request as potential_injection, the deep scanner calls the
// Groq API synchronously to classify the payload and block confirmed injections.
type DeepScanner struct {
	groqAPIKey   string
	groqBaseURL  string
	timeout      time.Duration
	fallbackMode DeepScanFallbackMode
	resultChan   chan DeepScanResult
	httpClient   *http.Client
	auditor      *Auditor
}

// Chunking constants for Prompt Guard 2 model constraints.
// The 512-token context window is a model limit, not configurable.
const (
	// maxChunkTokens is the maximum tokens per chunk (model context window).
	maxChunkTokens = 512
	// overlapTokens is the overlap between consecutive chunks to catch
	// injection patterns spanning chunk boundaries.
	overlapTokens = 64
	// maxChunkConcurrency is the maximum number of concurrent Groq API calls
	// for chunk classification, to avoid overwhelming the rate limit.
	maxChunkConcurrency = 3
	// tokensPerWord is the approximate token-to-word ratio for whitespace-based
	// token estimation. Exact tokenization is unnecessary for chunking boundaries.
	tokensPerWord = 1.3
)

// ChunkResult contains the classification result for a single chunk.
type ChunkResult struct {
	ChunkIndex     int
	InjectionScore float64
	JailbreakScore float64
	Error          error
}

// DeepScanResult contains the results of a deep scan
type DeepScanResult struct {
	RequestID      string
	TraceID        string
	Timestamp      time.Time
	InjectionScore float64 // 0.0 to 1.0 (highest across all chunks)
	JailbreakScore float64 // 0.0 to 1.0 (highest across all chunks)
	ModelUsed      string
	LatencyMs      int64
	ChunkCount     int           // number of chunks (1 for short payloads)
	ChunkResults   []ChunkResult // per-chunk results (nil for single-chunk)
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

// DeepScannerConfig holds configuration for creating a DeepScanner
type DeepScannerConfig struct {
	APIKey       string
	Timeout      time.Duration
	FallbackMode string // "fail_closed" or "fail_open"
	Auditor      *Auditor
}

// NewDeepScanner creates a new deep scanner with Groq API
func NewDeepScanner(apiKey string, timeout time.Duration) *DeepScanner {
	return NewDeepScannerWithConfig(DeepScannerConfig{
		APIKey:       apiKey,
		Timeout:      timeout,
		FallbackMode: "fail_closed",
	})
}

// NewDeepScannerWithConfig creates a new deep scanner with full configuration
func NewDeepScannerWithConfig(cfg DeepScannerConfig) *DeepScanner {
	fallback := FailClosed
	if cfg.FallbackMode == "fail_open" {
		fallback = FailOpen
	}

	return &DeepScanner{
		groqAPIKey:   cfg.APIKey,
		groqBaseURL:  "https://api.groq.com/openai/v1",
		timeout:      cfg.Timeout,
		fallbackMode: fallback,
		resultChan:   make(chan DeepScanResult, 100),
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		auditor: cfg.Auditor,
	}
}

// HasAPIKey returns true if the scanner has a configured API key
func (d *DeepScanner) HasAPIKey() bool {
	return d.groqAPIKey != ""
}

// FallbackMode returns the configured fallback mode
func (d *DeepScanner) FallbackMode() DeepScanFallbackMode {
	return d.fallbackMode
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

// scan performs the actual deep scan using Groq Prompt Guard 2.
// For payloads exceeding 512 estimated tokens, the content is split into
// overlapping chunks and classified in parallel. The highest probability
// across all chunks is used (any flagged chunk flags the entire request).
func (d *DeepScanner) scan(ctx context.Context, content string, traceID string) DeepScanResult {
	start := time.Now()
	result := DeepScanResult{
		TraceID:    traceID,
		Timestamp:  start,
		ModelUsed:  "meta-llama/llama-prompt-guard-2-86m",
		ChunkCount: 1,
	}

	// If no API key, report error (caller determines fail behavior)
	if d.groqAPIKey == "" {
		result.Error = fmt.Errorf("no Groq API key configured")
		return result
	}

	tokenCount := estimateTokens(content)

	if tokenCount <= maxChunkTokens {
		// AC5: Short payloads -- single API call, no chunking overhead
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

	// AC1: Split into overlapping chunks for large payloads
	chunks := chunkContent(content, maxChunkTokens, overlapTokens)
	result.ChunkCount = len(chunks)

	// AC2/AC3/AC4: Classify chunks in parallel, aggregate results
	pgResult, chunkResults, err := d.classifyChunksParallel(ctx, chunks)
	if err != nil {
		result.Error = err
		result.ChunkResults = chunkResults
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}

	result.InjectionScore = pgResult.InjectionProbability
	result.JailbreakScore = pgResult.JailbreakProbability
	result.ChunkResults = chunkResults
	result.LatencyMs = time.Since(start).Milliseconds()

	return result
}

// classifyWithPromptGuard calls Groq API with Prompt Guard 2 model.
// Prompt Guard 2 86M is a text classification model served via the chat
// completions API on Groq. It returns a text response that is either:
//   - A label string like "BENIGN", "INJECTION", or "JAILBREAK"
//   - A numeric score between 0.0 and 1.0
//
// We handle both formats for robustness.
func (d *DeepScanner) classifyWithPromptGuard(ctx context.Context, content string) (PromptGuardResponse, error) {
	// Construct request to Groq API
	reqBody := map[string]interface{}{
		"model": "meta-llama/llama-prompt-guard-2-86m",
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": content,
			},
		},
		"max_tokens":  10,
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

	// Check status code -- surface HTTP status for fallback logic
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
	if len(groqResp.Choices) == 0 {
		return PromptGuardResponse{}, fmt.Errorf("no choices in response")
	}

	return parsePromptGuardContent(groqResp.Choices[0].Message.Content)
}

// parsePromptGuardContent parses the model's response content into probabilities.
// Prompt Guard 2 86M may return:
//   - A class label: "BENIGN", "INJECTION", "JAILBREAK", or "MALICIOUS"
//   - A numeric score string: "0.9995" or similar
//
// For label outputs, we map to probability scores:
//   - "BENIGN" -> injection=0.0, jailbreak=0.0
//   - "INJECTION" -> injection=1.0, jailbreak=0.0
//   - "JAILBREAK" -> injection=0.0, jailbreak=1.0
//   - "MALICIOUS" -> injection=1.0, jailbreak=1.0 (unified binary classifier)
//
// For numeric outputs, we use the score for both fields (unified threat score).
func parsePromptGuardContent(content string) (PromptGuardResponse, error) {
	trimmed := strings.TrimSpace(content)
	upper := strings.ToUpper(trimmed)

	// Check for known class labels first
	switch upper {
	case "BENIGN":
		return PromptGuardResponse{
			InjectionProbability: 0.0,
			JailbreakProbability: 0.0,
		}, nil
	case "INJECTION":
		return PromptGuardResponse{
			InjectionProbability: 1.0,
			JailbreakProbability: 0.0,
		}, nil
	case "JAILBREAK":
		return PromptGuardResponse{
			InjectionProbability: 0.0,
			JailbreakProbability: 1.0,
		}, nil
	case "MALICIOUS":
		return PromptGuardResponse{
			InjectionProbability: 1.0,
			JailbreakProbability: 1.0,
		}, nil
	}

	// Try parsing as numeric score
	var score float64
	if _, err := fmt.Sscanf(trimmed, "%f", &score); err != nil {
		return PromptGuardResponse{}, fmt.Errorf("failed to parse score from content %q: %w", trimmed, err)
	}

	// Clamp score to valid range [0.0, 1.0]
	if score < 0.0 {
		score = 0.0
	} else if score > 1.0 {
		score = 1.0
	}

	// Unified threat score used for both fields
	return PromptGuardResponse{
		InjectionProbability: score,
		JailbreakProbability: score,
	}, nil
}

// estimateTokens returns an approximate token count for a string using
// whitespace-based word counting with a 1.3 tokens/word multiplier.
// This is intentionally approximate -- exact tokenization is unnecessary
// for chunking boundary decisions.
func estimateTokens(content string) int {
	words := len(strings.Fields(content))
	return int(math.Ceil(float64(words) * tokensPerWord))
}

// chunkContent splits content into overlapping chunks sized for the
// Prompt Guard 2 context window. Each chunk contains at most maxTokens
// estimated tokens, with overlapToks token overlap between consecutive
// chunks to ensure injection patterns spanning boundaries are detected.
//
// Returns a single-element slice if content fits in one chunk.
func chunkContent(content string, maxToks int, overlapToks int) []string {
	words := strings.Fields(content)
	if len(words) == 0 {
		return []string{""}
	}

	// Convert token limits to word counts
	maxWords := int(float64(maxToks) / tokensPerWord)
	if maxWords < 1 {
		maxWords = 1
	}
	overlapWords := int(float64(overlapToks) / tokensPerWord)
	if overlapWords < 0 {
		overlapWords = 0
	}

	// Step size: how many NEW words each chunk advances
	step := maxWords - overlapWords
	if step < 1 {
		step = 1
	}

	// If all words fit in one chunk, return as-is
	if len(words) <= maxWords {
		return []string{strings.Join(words, " ")}
	}

	var chunks []string
	for start := 0; start < len(words); start += step {
		end := start + maxWords
		if end > len(words) {
			end = len(words)
		}
		chunks = append(chunks, strings.Join(words[start:end], " "))
		// If we've reached the end of words, stop
		if end == len(words) {
			break
		}
	}

	return chunks
}

// classifyChunksParallel classifies multiple content chunks against the
// Groq Prompt Guard 2 API with bounded concurrency. Returns the aggregated
// result: the highest injection/jailbreak probability across all chunks.
// If ANY chunk returns an error, the entire classification fails.
func (d *DeepScanner) classifyChunksParallel(ctx context.Context, chunks []string) (PromptGuardResponse, []ChunkResult, error) {
	chunkResults := make([]ChunkResult, len(chunks))

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxChunkConcurrency)

	// Track first error for early reporting
	var firstErr error
	var errOnce sync.Once

	for i, chunk := range chunks {
		wg.Add(1)
		go func(idx int, content string) {
			defer wg.Done()

			// Acquire semaphore slot (bounded concurrency)
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				chunkResults[idx] = ChunkResult{
					ChunkIndex: idx,
					Error:      ctx.Err(),
				}
				errOnce.Do(func() { firstErr = ctx.Err() })
				return
			}

			pgResult, err := d.classifyWithPromptGuard(ctx, content)
			if err != nil {
				chunkResults[idx] = ChunkResult{
					ChunkIndex: idx,
					Error:      err,
				}
				errOnce.Do(func() { firstErr = err })
				return
			}

			chunkResults[idx] = ChunkResult{
				ChunkIndex:     idx,
				InjectionScore: pgResult.InjectionProbability,
				JailbreakScore: pgResult.JailbreakProbability,
			}
		}(i, chunk)
	}

	wg.Wait()

	// Check for any errors
	if firstErr != nil {
		return PromptGuardResponse{}, chunkResults, firstErr
	}

	// Aggregate: highest probability across all chunks
	var maxInjection, maxJailbreak float64
	for _, cr := range chunkResults {
		if cr.InjectionScore > maxInjection {
			maxInjection = cr.InjectionScore
		}
		if cr.JailbreakScore > maxJailbreak {
			maxJailbreak = cr.JailbreakScore
		}
	}

	return PromptGuardResponse{
		InjectionProbability: maxInjection,
		JailbreakProbability: maxJailbreak,
	}, chunkResults, nil
}

// DeepScanMiddleware creates middleware for deep scanning of requests flagged
// by DLP as potential_injection.
//
// Behavior:
//   - If GROQ_API_KEY is empty, pass-through (no API call).
//   - If DLP flags potential_injection, perform synchronous Groq API call.
//   - If Groq returns an error and fallback=fail_closed, block the request.
//   - If Groq returns an error and fallback=fail_open, allow with audit event.
//   - If Groq classifies as injection (score > threshold), store result in context
//     for step-up gating to consume.
//
// Position: Step 10, after step-up gating
func DeepScanMiddleware(next http.Handler, scanner *DeepScanner) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get security flags from context (set by DLP middleware)
		flags := GetSecurityFlags(ctx)

		// Determine if deep scan should be dispatched
		if !shouldDispatchDeepScan(flags) {
			// No injection concern, fast path
			next.ServeHTTP(w, r)
			return
		}

		// If no API key, pass-through (AC4)
		if !scanner.HasAPIKey() {
			next.ServeHTTP(w, r)
			return
		}

		// Get request body and trace ID
		body := GetRequestBody(ctx)
		traceID := GetTraceID(ctx)

		if body == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Perform synchronous deep scan
		result := scanner.Scan(ctx, string(body), traceID)

		// Handle scan errors with fallback logic (AC5, AC6)
		if result.Error != nil {
			scanner.emitAuditEvent(ctx, result, "guard_model_unavailable")

			if scanner.fallbackMode == FailClosed {
				// AC5: Block the request
				http.Error(w, "deepscan_unavailable_fail_closed", http.StatusServiceUnavailable)
				return
			}
			// AC6: fail_open -- allow the request, audit event already emitted
			next.ServeHTTP(w, r)
			return
		}

		// Emit audit event with guard model decision (AC7)
		scanner.emitAuditEvent(ctx, result, "guard_model_classified")

		// Store result in context for step-up gating to consume (AC3)
		ctx = WithDeepScanResult(ctx, result)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// emitAuditEvent records a guard model decision in the audit log.
// When chunks are used, the audit event includes chunk_count and
// per-chunk probabilities for forensic analysis.
func (d *DeepScanner) emitAuditEvent(ctx context.Context, result DeepScanResult, reason string) {
	if d.auditor == nil {
		return
	}

	auditResult := fmt.Sprintf(
		"reason=%s injection_probability=%.4f jailbreak_probability=%.4f model=%s latency_ms=%d chunk_count=%d",
		reason, result.InjectionScore, result.JailbreakScore, result.ModelUsed, result.LatencyMs, result.ChunkCount,
	)

	// Append per-chunk probabilities when chunking was used
	if len(result.ChunkResults) > 0 {
		var chunkDetails []string
		for _, cr := range result.ChunkResults {
			if cr.Error != nil {
				chunkDetails = append(chunkDetails, fmt.Sprintf("chunk_%d=error(%s)", cr.ChunkIndex, cr.Error.Error()))
			} else {
				chunkDetails = append(chunkDetails, fmt.Sprintf("chunk_%d=inj:%.4f/jb:%.4f", cr.ChunkIndex, cr.InjectionScore, cr.JailbreakScore))
			}
		}
		auditResult += " chunks=[" + strings.Join(chunkDetails, ",") + "]"
	}

	d.auditor.Log(AuditEvent{
		SessionID:  GetSessionID(ctx),
		DecisionID: GetDecisionID(ctx),
		TraceID:    result.TraceID,
		SPIFFEID:   GetSPIFFEID(ctx),
		Action:     "deep_scan",
		Result:     auditResult,
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

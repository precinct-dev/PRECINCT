// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// Transport resilience: timeouts, retry with backoff, response validation,
// and size limiting for the MCP transport layer.
//
// RFA-xhr: Hardens the MCP transport against production failure modes:
// - Per-probe and overall detection timeouts
// - Per-request timeouts
// - Retry with exponential backoff on session loss
// - JSON-RPC response validation
// - Response size limiting
package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

// DetectConfig holds timeout configuration for transport detection.
type DetectConfig struct {
	// ProbeTimeout is the timeout for each individual probe attempt
	// (Streamable HTTP and Legacy SSE). Default: 5s.
	ProbeTimeout time.Duration

	// OverallTimeout is the timeout for the entire detection process
	// (all probes combined). Default: 15s.
	OverallTimeout time.Duration
}

// DefaultDetectConfig returns the default detection configuration.
func DefaultDetectConfig() DetectConfig {
	return DetectConfig{
		ProbeTimeout:   5 * time.Second,
		OverallTimeout: 15 * time.Second,
	}
}

// RetryConfig holds configuration for retry with exponential backoff.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts. Default: 3.
	MaxRetries int

	// InitialBackoff is the delay before the first retry. Default: 100ms.
	InitialBackoff time.Duration

	// BackoffFactor is the multiplier applied to the backoff after each retry. Default: 2.0.
	BackoffFactor float64

	// MaxBackoff is the maximum backoff duration. Default: 2s.
	MaxBackoff time.Duration
}

// DefaultRetryConfig returns the default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 100 * time.Millisecond,
		BackoffFactor:  2.0,
		MaxBackoff:     2 * time.Second,
	}
}

// backoffDuration calculates the backoff duration for a given attempt (0-indexed).
func (rc RetryConfig) backoffDuration(attempt int) time.Duration {
	if attempt <= 0 {
		return rc.InitialBackoff
	}
	backoff := float64(rc.InitialBackoff) * math.Pow(rc.BackoffFactor, float64(attempt))
	if backoff > float64(rc.MaxBackoff) {
		backoff = float64(rc.MaxBackoff)
	}
	return time.Duration(backoff)
}

// SendWithRetry sends a JSON-RPC request via the transport with retry and backoff
// on session loss. Session loss is indicated by errors containing "404" or
// "session" keywords. On session loss, the transport is re-initialized before
// retrying.
//
// The reinitFn is called to re-initialize the transport when session loss is
// detected. For StreamableHTTPTransport, this is reInitialize. For
// LegacySSETransport, this would be a reconnect.
//
// Returns the response from the first successful attempt, or the last error
// if all retries are exhausted.
func SendWithRetry(
	ctx context.Context,
	transport Transport,
	req *JSONRPCRequest,
	retryCfg RetryConfig,
	reinitFn func(ctx context.Context) error,
) (*JSONRPCResponse, error) {
	var lastErr error

	for attempt := 0; attempt <= retryCfg.MaxRetries; attempt++ {
		if attempt > 0 {
			// Wait with backoff before retrying
			backoff := retryCfg.backoffDuration(attempt - 1)
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("retry cancelled: %w", ctx.Err())
			case <-time.After(backoff):
			}

			// Re-initialize transport before retry
			if reinitFn != nil {
				if err := reinitFn(ctx); err != nil {
					lastErr = fmt.Errorf("re-initialize on retry %d failed: %w", attempt, err)
					continue
				}
			}
		}

		resp, err := transport.Send(ctx, req)
		if err == nil {
			return resp, nil
		}

		lastErr = err

		// Check if this is a session-loss error worth retrying
		if !isSessionLossError(err) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("all %d retries exhausted: %w", retryCfg.MaxRetries, lastErr)
}

// isSessionLossError checks whether the error indicates a session loss
// condition that should trigger a retry. Session loss is indicated by:
// - HTTP 404 (session not found / expired)
// - SSE stream disconnection
// - Session expiry errors
func isSessionLossError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "404") ||
		strings.Contains(msg, "session") ||
		strings.Contains(msg, "stream") ||
		strings.Contains(msg, "sse transport closed")
}

// ValidateResponse validates a JSON-RPC response against the request.
// Checks:
//  1. jsonrpc version is "2.0"
//  2. Response ID matches request ID
//  3. Exactly one of result or error is present (XOR)
//  4. If error is present, code must be a valid JSON-RPC error code
//
// Returns nil if valid, or an error describing the validation failure.
func ValidateResponse(req *JSONRPCRequest, resp *JSONRPCResponse) error {
	if resp.JSONRPC != "2.0" {
		return fmt.Errorf("invalid jsonrpc version: expected \"2.0\", got %q", resp.JSONRPC)
	}

	if resp.ID != req.ID {
		return fmt.Errorf("response ID mismatch: expected %d, got %d", req.ID, resp.ID)
	}

	hasResult := len(resp.Result) > 0
	hasError := resp.Error != nil

	if hasResult == hasError {
		if hasResult {
			return fmt.Errorf("response has both result and error (must have exactly one)")
		}
		return fmt.Errorf("response has neither result nor error (must have exactly one)")
	}

	if hasError {
		// Validate error code is in a recognized range.
		// JSON-RPC 2.0 spec: -32768 to -32000 are reserved for implementation.
		// Custom error codes are outside this range.
		code := resp.Error.Code
		if code == 0 {
			return fmt.Errorf("error code 0 is not a valid JSON-RPC error code")
		}
	}

	return nil
}

// LimitedReadResponse reads the response body with a size limit.
// If the body exceeds maxBytes, it returns an error with a snippet of
// the oversized data for diagnostics.
func LimitedReadResponse(body io.Reader, maxBytes int64) ([]byte, error) {
	limited := io.LimitReader(body, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if int64(len(data)) > maxBytes {
		// Truncate to first 128 bytes for diagnostics
		snippetLen := 128
		if len(data) < snippetLen {
			snippetLen = len(data)
		}
		return nil, fmt.Errorf("response body exceeds maximum size of %d bytes (got at least %d bytes, preview: %s)",
			maxBytes, len(data), string(data[:snippetLen]))
	}

	return data, nil
}

// ParseLimitedJSONResponse reads a response body with size limits and parses
// it as a JSONRPCResponse. Combines size limiting with JSON parsing.
func ParseLimitedJSONResponse(body io.Reader, maxBytes int64) (*JSONRPCResponse, error) {
	data, err := LimitedReadResponse(body, maxBytes)
	if err != nil {
		return nil, err
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		// Include a snippet of the malformed data for diagnostics
		snippetLen := 128
		if len(data) < snippetLen {
			snippetLen = len(data)
		}
		return nil, fmt.Errorf("malformed JSON-RPC response (preview: %s): %w",
			string(data[:snippetLen]), err)
	}

	return &resp, nil
}

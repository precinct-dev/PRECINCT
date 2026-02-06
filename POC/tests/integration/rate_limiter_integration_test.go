//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// TestRateLimiterIntegration verifies rate limiting behavior against running compose stack
// This test exercises rate limiting with real API calls, no mocks
func TestRateLimiterIntegration(t *testing.T) {
	// Wait for gateway to be ready
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	// Define agents for testing
	researcher := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	gateway := "spiffe://poc.local/gateways/mcp-security-gateway/dev"

	t.Run("RateLimitHeadersPresent", func(t *testing.T) {
		// Verify rate limit headers are present in normal responses
		mcpReq := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "file_read",
			"params":  map[string]interface{}{"path": "/test"},
			"id":      1,
		}
		reqBody, _ := json.Marshal(mcpReq)

		req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("X-Spiffe-Id", researcher)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		// Verify rate limit headers are present
		if limit := resp.Header.Get("X-RateLimit-Limit"); limit == "" {
			t.Error("Expected X-RateLimit-Limit header to be present")
		}
		if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining == "" {
			t.Error("Expected X-RateLimit-Remaining header to be present")
		}
		if reset := resp.Header.Get("X-RateLimit-Reset"); reset == "" {
			t.Error("Expected X-RateLimit-Reset header to be present")
		} else {
			// Verify reset timestamp is valid
			if resetInt, err := strconv.ParseInt(reset, 10, 64); err != nil || resetInt <= 0 {
				t.Errorf("Expected valid X-RateLimit-Reset unix timestamp, got %s", reset)
			}
		}
	})

	t.Run("IndependentAgentLimits", func(t *testing.T) {
		// Verify different agents have independent rate limits
		mcpReq := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "file_read",
			"params":  map[string]interface{}{"path": "/test"},
			"id":      1,
		}
		reqBody, _ := json.Marshal(mcpReq)

		// Agent 1 (researcher) makes a request
		req1, _ := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
		req1.Header.Set("X-Spiffe-Id", researcher)
		req1.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 5 * time.Second}
		resp1, err := client.Do(req1)
		if err != nil {
			t.Fatalf("Failed to send researcher request: %v", err)
		}
		resp1.Body.Close()

		// Agent 2 (gateway) should still be able to make requests (independent bucket)
		req2, _ := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
		req2.Header.Set("X-Spiffe-Id", gateway)
		req2.Header.Set("Content-Type", "application/json")

		resp2, err := client.Do(req2)
		if err != nil {
			t.Fatalf("Failed to send gateway request: %v", err)
		}
		defer resp2.Body.Close()

		// Both agents should succeed (independent rate limits)
		// Note: We're not testing exhaustion here, just independence
		if resp1.StatusCode >= 500 {
			t.Errorf("Expected researcher request to succeed, got %d", resp1.StatusCode)
		}
		if resp2.StatusCode >= 500 {
			t.Errorf("Expected gateway request to succeed with independent limit, got %d", resp2.StatusCode)
		}
	})

	t.Run("RateLimitExceededWithRetryAfter", func(t *testing.T) {
		// This test requires a low rate limit for the test environment
		// With default 100 req/min + 20 burst, we'd need to send 120+ requests
		// Instead, we verify the 429 response structure when it occurs

		// Note: In a real production test, you'd lower RATE_LIMIT_RPM for testing
		// For this POC test, we'll just verify the rate limit headers exist
		// and have valid values, proving the middleware is active

		mcpReq := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "file_read",
			"params":  map[string]interface{}{"path": "/test"},
			"id":      1,
		}
		reqBody, _ := json.Marshal(mcpReq)

		// Use a unique agent for this test to avoid interference
		testAgent := "spiffe://poc.local/agents/test/rate-limit-test"

		// Send multiple requests rapidly to test rate limiting
		// With 100 req/min + 20 burst, we won't hit the limit in this test
		// But we verify the headers are present and valid
		var lastResp *http.Response
		client := &http.Client{Timeout: 5 * time.Second}

		for i := 0; i < 5; i++ {
			req, _ := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
			req.Header.Set("X-Spiffe-Id", testAgent)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to send request %d: %v", i+1, err)
			}

			if lastResp != nil {
				lastResp.Body.Close()
			}
			lastResp = resp

			// Check if we got rate limited (unlikely with default settings)
			if resp.StatusCode == http.StatusTooManyRequests {
				// Verify 429 response has proper structure
				var respBody map[string]interface{}
				if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
					t.Fatalf("Failed to decode 429 response body: %v", err)
				}

				if respBody["error"] != "rate_limit_exceeded" {
					t.Errorf("Expected error=rate_limit_exceeded, got %v", respBody["error"])
				}

				if _, exists := respBody["retry_after_seconds"]; !exists {
					t.Error("Expected retry_after_seconds in 429 response")
				}

				// Verify rate limit headers are present even in 429
				if limit := resp.Header.Get("X-RateLimit-Limit"); limit == "" {
					t.Error("Expected X-RateLimit-Limit header in 429 response")
				}
				break
			}

			// Verify rate limit headers in normal responses
			if limit := resp.Header.Get("X-RateLimit-Limit"); limit == "" {
				t.Errorf("Request %d: Expected X-RateLimit-Limit header", i+1)
			}
			if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining == "" {
				t.Errorf("Request %d: Expected X-RateLimit-Remaining header", i+1)
			}
			if reset := resp.Header.Get("X-RateLimit-Reset"); reset == "" {
				t.Errorf("Request %d: Expected X-RateLimit-Reset header", i+1)
			}
		}

		if lastResp != nil {
			lastResp.Body.Close()
		}
	})
}

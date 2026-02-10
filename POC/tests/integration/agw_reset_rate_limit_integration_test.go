//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestAgwResetRateLimitIntegration(t *testing.T) {
	// Requires a running compose stack (make -C POC up).
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	// Use a known-allowed identity from the compose stack so we can reach the
	// rate limiter stage (step 11) instead of failing earlier on authz.
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"

	// KeyDB in compose (default).
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	t.Cleanup(func() { _ = rdb.Close() })

	tokensKey := "ratelimit:" + spiffeID + ":tokens"
	lastFillKey := "ratelimit:" + spiffeID + ":last_fill"

	// Ensure we start unblocked: delete any existing bucket state.
	_, _ = rdb.Del(t.Context(), tokensKey, lastFillKey).Result()

	// 1) Send a request (should not be 429 under fresh bucket)
	if code := postMCP(t, spiffeID); code == http.StatusTooManyRequests {
		t.Fatalf("expected initial request not rate-limited, got 429")
	}

	// 2) Force a rate-limited state deterministically (tokens=0, last_fill=now)
	now := time.Now().UnixNano()
	if err := rdb.Set(t.Context(), tokensKey, "0", 2*time.Minute).Err(); err != nil {
		t.Fatalf("set tokens: %v", err)
	}
	if err := rdb.Set(t.Context(), lastFillKey, fmt.Sprintf("%d", now), 2*time.Minute).Err(); err != nil {
		t.Fatalf("set last_fill: %v", err)
	}

	if code := postMCP(t, spiffeID); code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after forcing tokens=0, got %d", code)
	}

	// 3) Reset via CLI (must delete the keys)
	cmd := exec.Command("go", "run", "./cmd/agw", "reset", "rate-limit", spiffeID, "--confirm", "--keydb-url", "redis://localhost:6379")
	cmd.Dir = pocDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agw reset rate-limit failed: %v\nOutput:\n%s", err, string(out))
	}

	// Verify keys are gone
	if err := rdb.Get(t.Context(), tokensKey).Err(); err != redis.Nil {
		t.Fatalf("expected tokensKey deleted (redis.Nil), got %v", err)
	}
	if err := rdb.Get(t.Context(), lastFillKey).Err(); err != redis.Nil {
		t.Fatalf("expected lastFillKey deleted (redis.Nil), got %v", err)
	}

	// 4) Post-reset, request should not be rate-limited
	if code := postMCP(t, spiffeID); code == http.StatusTooManyRequests {
		t.Fatalf("expected request unblocked after reset, got 429")
	}
}

func postMCP(t *testing.T, spiffeID string) int {
	t.Helper()
	mcpReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tavily_search",
		"params":  map[string]interface{}{"query": "rate limit test"},
		"id":      1,
	}
	reqBody, _ := json.Marshal(mcpReq)
	req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Spiffe-Id", spiffeID)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

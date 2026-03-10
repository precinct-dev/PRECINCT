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
)

func TestAgwResetRateLimitIntegration(t *testing.T) {
	// Requires a running compose stack (make -C POC up).
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	// Use a known-allowed identity from the compose stack so we can reach the
	// rate limiter stage (step 11) instead of failing earlier on authz.
	spiffeID := "spiffe://poc.local/agents/mcp-client/reset-researcher/dev"

	keydbURL := integrationKeyDBURL()

	tokensKey := "ratelimit:" + spiffeID + ":tokens"
	lastFillKey := "ratelimit:" + spiffeID + ":last_fill"

	// Ensure we start unblocked: delete any existing bucket state.
	keydbDeleteKeys(t, tokensKey, lastFillKey)

	// 1) Send a request (should not be 429 under fresh bucket)
	if code := postMCP(t, spiffeID); code == http.StatusTooManyRequests {
		t.Fatalf("expected initial request not rate-limited, got 429")
	}

	// 2) Force a rate-limited state deterministically (tokens=0, last_fill=now)
	now := time.Now().Add(30 * time.Second).UnixNano()
	keydbSetValue(t, tokensKey, "0", 2*time.Minute)
	keydbSetValue(t, lastFillKey, fmt.Sprintf("%d", now), 2*time.Minute)

	if code := postMCP(t, spiffeID); code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after forcing tokens=0, got %d", code)
	}

	// 3) Reset via CLI (must delete the keys)
	cmd := exec.Command("go", "run", "./cmd/agw", "reset", "rate-limit", spiffeID, "--confirm", "--keydb-url", keydbURL)
	cmd.Dir = pocDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agw reset rate-limit failed: %v\nOutput:\n%s", err, string(out))
	}

	// Verify keys are gone
	if exists := keydbExists(t, tokensKey, lastFillKey); exists != 0 {
		t.Fatalf("expected rate limit keys deleted, exists=%d", exists)
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

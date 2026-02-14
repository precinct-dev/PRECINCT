//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestAgwPolicyTestRuntimeIntegration_Full13LayersAllowed(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	keydbURL := getEnvOrDefault("AGW_KEYDB_URL", "redis://localhost:6379")
	opt, err := redis.ParseURL(keydbURL)
	if err != nil {
		t.Fatalf("parse keydb url %q: %v", keydbURL, err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(t.Context()).Err(); err != nil {
		t.Fatalf("KeyDB not reachable at %s: %v", keydbURL, err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resetBody, err := json.Marshal(map[string]string{"tool": "tavily_search"})
	if err != nil {
		t.Fatalf("marshal reset request: %v", err)
	}
	resetReq, err := http.NewRequest(http.MethodPost, gatewayURL+"/admin/circuit-breakers/reset", bytes.NewReader(resetBody))
	if err != nil {
		t.Fatalf("build reset request: %v", err)
	}
	resetReq.Header.Set("Content-Type", "application/json")
	resetReq.Header.Set("X-SPIFFE-ID", adminSPIFFEID)
	resetResp, err := client.Do(resetReq)
	if err != nil {
		t.Fatalf("reset circuit breaker: %v", err)
	}
	defer resetResp.Body.Close()
	if resetResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected reset status=%d", resetResp.StatusCode)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := "sid-policy-runtime-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	sessionKey := "session:" + spiffeID + ":" + sessionID
	tokensKey := "ratelimit:" + spiffeID + ":tokens"
	lastFillKey := "ratelimit:" + spiffeID + ":last_fill"

	if err := rdb.Set(t.Context(), sessionKey, `{"RiskScore":0.15}`, 2*time.Minute).Err(); err != nil {
		t.Fatalf("seed session key: %v", err)
	}
	if err := rdb.Set(t.Context(), tokensKey, "55.0", 2*time.Minute).Err(); err != nil {
		t.Fatalf("seed ratelimit tokens: %v", err)
	}
	if err := rdb.Set(t.Context(), lastFillKey, strconv.FormatInt(time.Now().UnixNano(), 10), 2*time.Minute).Err(); err != nil {
		t.Fatalf("seed ratelimit last_fill: %v", err)
	}

	cmd := exec.Command(
		"go", "run", "./cmd/agw", "policy", "test",
		spiffeID,
		"tavily_search",
		"--runtime",
		"--session-id", sessionID,
		"--gateway-url", gatewayURL,
		"--keydb-url", keydbURL,
		"--params", `{"query":"runtime-policy-allowed"}`,
		"--format", "json",
	)
	cmd.Dir = pocDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("runtime policy test command failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var parsed struct {
		Mode          string `json:"mode"`
		Verdict       string `json:"verdict"`
		BlockingLayer int    `json:"blocking_layer"`
		Note          string `json:"note"`
		Layers        []struct {
			Step   int    `json:"step"`
			Result string `json:"result"`
			Detail string `json:"detail"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid runtime JSON: %v raw=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	if parsed.Mode != "full" {
		t.Fatalf("expected mode=full, got %+v", parsed)
	}
	if parsed.Verdict != "ALLOWED" {
		t.Fatalf("expected ALLOWED verdict, got %+v", parsed)
	}
	if parsed.BlockingLayer != 0 {
		t.Fatalf("expected blocking_layer=0 for allowed run, got %+v", parsed)
	}
	if parsed.Note != "" {
		t.Fatalf("expected empty runtime note, got %+v", parsed)
	}
	if len(parsed.Layers) != 13 {
		t.Fatalf("expected 13 layers, got %+v", parsed)
	}

	layerByStep := map[int]string{}
	for _, l := range parsed.Layers {
		layerByStep[l.Step] = l.Result
	}
	if layerByStep[7] != "PASS" {
		t.Fatalf("expected layer 7 PASS, got %+v", parsed.Layers)
	}
	if layerByStep[8] != "PASS" {
		t.Fatalf("expected layer 8 PASS, got %+v", parsed.Layers)
	}
	if layerByStep[10] != "PASS" {
		t.Fatalf("expected layer 10 PASS, got %+v", parsed.Layers)
	}
	if layerByStep[11] != "PASS" {
		t.Fatalf("expected layer 11 PASS, got %+v", parsed.Layers)
	}
	if layerByStep[12] != "PASS" {
		t.Fatalf("expected layer 12 PASS, got %+v", parsed.Layers)
	}
	if layerByStep[13] != "PASS" {
		t.Fatalf("expected layer 13 PASS, got %+v", parsed.Layers)
	}
	if layerByStep[9] != "PASS" && layerByStep[9] != "SKIP" {
		t.Fatalf("expected layer 9 PASS or SKIP, got %+v", parsed.Layers)
	}
}

// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

func TestPrecinctResetCircuitBreakerIntegration_OpenThenResetClosed(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	tool := "tavily_search"
	adminSPIFFEID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"

	adminTokensKey := "ratelimit:admin-approvals:" + adminSPIFFEID + ":tokens"
	adminLastFillKey := "ratelimit:admin-approvals:" + adminSPIFFEID + ":last_fill"
	keydbDeleteKeys(t, adminTokensKey, adminLastFillKey)

	if code := postGatewayMethod(t, spiffeID, "tools/list", map[string]any{}); code != http.StatusOK {
		t.Fatalf("tools/list bootstrap failed, expected 200 got %d", code)
	}

	stop := composeCommand("stop", "mock-mcp-server")
	if out, err := stop.CombinedOutput(); err != nil {
		t.Fatalf("docker compose stop mock-mcp-server failed: %v output=%q", err, string(out))
	}
	t.Cleanup(func() {
		up := composeCommand("up", "-d", "mock-mcp-server")
		_, _ = up.CombinedOutput()
	})

	opened := false
	for i := 0; i < 12; i++ {
		// Use tools/list to force an upstream failure through the same global
		// circuit breaker without tripping step-up gating or the mock guard model.
		code := postGatewayMethod(t, spiffeID, "tools/list", map[string]any{})
		if code == http.StatusServiceUnavailable {
			opened = true
			break
		}
		if code < 500 {
			t.Fatalf("expected 5xx while forcing upstream failures, got %d", code)
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !opened {
		t.Fatalf("expected circuit breaker to open and return 503 after repeated failures")
	}

	recoverUp := composeCommand("up", "-d", "mock-mcp-server")
	if out, err := recoverUp.CombinedOutput(); err != nil {
		t.Fatalf("docker compose up mock-mcp-server failed: %v output=%q", err, string(out))
	}
	time.Sleep(2 * time.Second)
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("gateway not healthy after mock-mcp-server recovery: %v", err)
	}

	resetCmd := exec.Command("go", "run", "./cli/precinct", "reset", "circuit-breaker", tool, "--confirm", "--format", "json")
	resetCmd.Dir = pocDir()
	var resetOut, resetErr bytes.Buffer
	resetCmd.Stdout = &resetOut
	resetCmd.Stderr = &resetErr
	if err := resetCmd.Run(); err != nil {
		t.Fatalf("precinct reset circuit-breaker failed: %v stdout=%q stderr=%q", err, resetOut.String(), resetErr.String())
	}

	var resetParsed struct {
		Reset []struct {
			Tool          string `json:"tool"`
			PreviousState string `json:"previous_state"`
			NewState      string `json:"new_state"`
		} `json:"reset"`
	}
	if err := json.Unmarshal(resetOut.Bytes(), &resetParsed); err != nil {
		t.Fatalf("invalid reset json: %v raw=%q", err, resetOut.String())
	}
	if len(resetParsed.Reset) != 1 {
		t.Fatalf("expected 1 reset entry, got %+v", resetParsed.Reset)
	}
	if resetParsed.Reset[0].Tool != tool {
		t.Fatalf("expected reset tool=%q, got %+v", tool, resetParsed.Reset[0])
	}
	if resetParsed.Reset[0].PreviousState != "open" || resetParsed.Reset[0].NewState != "closed" {
		t.Fatalf("expected open->closed transition, got %+v", resetParsed.Reset[0])
	}

	inspectClosed := exec.Command("go", "run", "./cli/precinct", "inspect", "circuit-breaker", tool, "--format", "json")
	inspectClosed.Dir = pocDir()
	var inspectClosedOut, inspectClosedErr bytes.Buffer
	inspectClosed.Stdout = &inspectClosedOut
	inspectClosed.Stderr = &inspectClosedErr
	if err := inspectClosed.Run(); err != nil {
		t.Fatalf("precinct inspect circuit-breaker (closed) failed: %v stdout=%q stderr=%q", err, inspectClosedOut.String(), inspectClosedErr.String())
	}

	var closedParsed struct {
		CircuitBreakers []struct {
			State string `json:"state"`
		} `json:"circuit_breakers"`
	}
	if err := json.Unmarshal(inspectClosedOut.Bytes(), &closedParsed); err != nil {
		t.Fatalf("invalid inspect closed json: %v raw=%q", err, inspectClosedOut.String())
	}
	if len(closedParsed.CircuitBreakers) != 1 || closedParsed.CircuitBreakers[0].State != "closed" {
		t.Fatalf("expected circuit breaker closed after reset, got %+v", closedParsed.CircuitBreakers)
	}
}

func postGatewayMethod(t *testing.T, spiffeID, method string, params map[string]any) int {
	t.Helper()
	return postGatewayMethodWithHeaders(t, spiffeID, method, params, nil)
}

func postGatewayMethodWithHeaders(t *testing.T, spiffeID, method string, params map[string]any, extraHeaders map[string]string) int {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, gatewayURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)
	for key, value := range extraHeaders {
		req.Header.Set(key, value)
	}

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("gateway request failed: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

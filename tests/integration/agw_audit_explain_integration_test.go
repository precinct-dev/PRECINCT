//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestAgwAuditExplainIntegration_DeniedRequest(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Skipf("Gateway not ready (requires running stack: make up): %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	body := `{"jsonrpc":"2.0","method":"tool_does_not_exist_for_explain","params":{},"id":77}`

	req, err := http.NewRequest(http.MethodPost, gatewayURL, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("denied request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 400 {
		t.Fatalf("expected denied response, got status=%d", resp.StatusCode)
	}

	var denied struct {
		Code           string `json:"code"`
		DecisionID     string `json:"decision_id"`
		MiddlewareStep int    `json:"middleware_step"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&denied); err != nil {
		t.Fatalf("decode denied response: %v", err)
	}
	if denied.DecisionID == "" {
		t.Fatalf("expected decision_id in denied response, got %+v", denied)
	}

	// Wait briefly for async audit write flush in the running gateway.
	time.Sleep(500 * time.Millisecond)

	cmd := exec.Command("go", "run", "./cli/agw", "audit", "explain", denied.DecisionID, "--format", "json")
	cmd.Dir = pocDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("agw audit explain failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var parsed struct {
		DecisionID string `json:"decision_id"`
		Result     string `json:"result"`
		ErrorCode  string `json:"error_code"`
		Layers     []struct {
			Step   int    `json:"step"`
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("expected valid explain json, got err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	if parsed.DecisionID != denied.DecisionID {
		t.Fatalf("expected decision_id=%q, got %+v", denied.DecisionID, parsed)
	}
	if !strings.Contains(parsed.Result, "denied") {
		t.Fatalf("expected denied result, got %+v", parsed)
	}

	failStep := 0
	for _, layer := range parsed.Layers {
		if layer.Status == "FAIL" {
			failStep = layer.Step
			if strings.TrimSpace(layer.Detail) == "" {
				t.Fatalf("expected non-empty fail detail, got %+v", layer)
			}
			break
		}
	}
	if failStep == 0 {
		t.Fatalf("expected a FAIL layer in explain output, got %+v", parsed.Layers)
	}

	// For this integration path, unknown tool requests deny at tool registry.
	if denied.MiddlewareStep > 0 && failStep != denied.MiddlewareStep {
		t.Fatalf("expected fail step=%d from gateway error, got %d (code=%s explain_code=%s)", denied.MiddlewareStep, failStep, denied.Code, parsed.ErrorCode)
	}
}

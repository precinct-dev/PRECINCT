//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestGatewayAdminCircuitBreakersResetIntegration_ResetsToolToClosed(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	listReq, err := http.NewRequest(http.MethodGet, gatewayURL+"/admin/circuit-breakers", nil)
	if err != nil {
		t.Fatalf("build list request: %v", err)
	}
	listReq.Header.Set("X-SPIFFE-ID", adminSPIFFEID)
	listResp, err := client.Do(listReq)
	if err != nil {
		t.Fatalf("GET /admin/circuit-breakers: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected list status=%d", listResp.StatusCode)
	}

	var listed struct {
		CircuitBreakers []struct {
			Tool  string `json:"tool"`
			State string `json:"state"`
		} `json:"circuit_breakers"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list json: %v", err)
	}
	if len(listed.CircuitBreakers) == 0 {
		t.Fatalf("expected non-empty circuit_breakers array, got %+v", listed)
	}

	targetTool := listed.CircuitBreakers[0].Tool
	if targetTool == "" {
		t.Fatal("expected non-empty tool name from list response")
	}

	resetBody, err := json.Marshal(map[string]string{"tool": targetTool})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	resetReq, err := http.NewRequest(http.MethodPost, gatewayURL+"/admin/circuit-breakers/reset", bytes.NewReader(resetBody))
	if err != nil {
		t.Fatalf("build reset request: %v", err)
	}
	resetReq.Header.Set("Content-Type", "application/json")
	resetReq.Header.Set("X-SPIFFE-ID", adminSPIFFEID)

	resetResp, err := client.Do(resetReq)
	if err != nil {
		t.Fatalf("POST /admin/circuit-breakers/reset: %v", err)
	}
	defer resetResp.Body.Close()
	if resetResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected reset status=%d", resetResp.StatusCode)
	}

	var resetParsed struct {
		Reset []struct {
			Tool          string `json:"tool"`
			PreviousState string `json:"previous_state"`
			NewState      string `json:"new_state"`
		} `json:"reset"`
	}
	if err := json.NewDecoder(resetResp.Body).Decode(&resetParsed); err != nil {
		t.Fatalf("decode reset json: %v", err)
	}
	if len(resetParsed.Reset) != 1 {
		t.Fatalf("expected 1 reset entry, got %d", len(resetParsed.Reset))
	}
	if resetParsed.Reset[0].Tool != targetTool {
		t.Fatalf("expected reset tool=%q, got %q", targetTool, resetParsed.Reset[0].Tool)
	}
	if resetParsed.Reset[0].PreviousState == "" {
		t.Fatalf("expected non-empty previous_state, got %+v", resetParsed.Reset[0])
	}
	if resetParsed.Reset[0].NewState != "closed" {
		t.Fatalf("expected new_state=closed, got %q", resetParsed.Reset[0].NewState)
	}

	getOneReq, err := http.NewRequest(http.MethodGet, gatewayURL+"/admin/circuit-breakers/"+targetTool, nil)
	if err != nil {
		t.Fatalf("build single-tool request: %v", err)
	}
	getOneReq.Header.Set("X-SPIFFE-ID", adminSPIFFEID)
	getOneResp, err := client.Do(getOneReq)
	if err != nil {
		t.Fatalf("GET /admin/circuit-breakers/%s: %v", targetTool, err)
	}
	defer getOneResp.Body.Close()
	if getOneResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected single-tool status=%d", getOneResp.StatusCode)
	}

	var oneParsed struct {
		CircuitBreakers []struct {
			Tool  string `json:"tool"`
			State string `json:"state"`
		} `json:"circuit_breakers"`
	}
	if err := json.NewDecoder(getOneResp.Body).Decode(&oneParsed); err != nil {
		t.Fatalf("decode single-tool json: %v", err)
	}
	if len(oneParsed.CircuitBreakers) != 1 {
		t.Fatalf("expected one circuit_breakers entry, got %d", len(oneParsed.CircuitBreakers))
	}
	if oneParsed.CircuitBreakers[0].Tool != targetTool {
		t.Fatalf("expected tool=%q, got %q", targetTool, oneParsed.CircuitBreakers[0].Tool)
	}
	if oneParsed.CircuitBreakers[0].State != "closed" {
		t.Fatalf("expected state=closed after reset, got %q", oneParsed.CircuitBreakers[0].State)
	}
}

//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"testing"
	"time"
)

func TestPrecinctInspectCircuitBreakerIntegration_JSON(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	cmd := exec.Command("go", "run", "./cli/precinct", "inspect", "circuit-breaker", "--format", "json")
	cmd.Dir = pocDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("precinct inspect circuit-breaker failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var parsed struct {
		CircuitBreakers []struct {
			Tool  string `json:"tool"`
			State string `json:"state"`
		} `json:"circuit_breakers"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("expected valid JSON, got err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if len(parsed.CircuitBreakers) == 0 {
		t.Fatalf("expected non-empty circuit_breakers, got %+v", parsed)
	}
}

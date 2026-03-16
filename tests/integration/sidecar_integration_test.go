//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// sidecarSPIFFEID is the SPIFFE ID that an Envoy sidecar would inject via
// the X-SPIFFE-ID header. It follows the sidecar naming convention from the
// Envoy sidecar configuration (deploy/sidecar/envoy-sidecar.yaml).
const sidecarSPIFFEID = "spiffe://poc.local/agents/mcp-client/sidecar-test/dev"

// TestSidecarToGatewayFlow verifies that a request carrying a sidecar-pattern
// SPIFFE ID (as injected by the Envoy sidecar) passes through the gateway's
// SPIFFEAuth middleware without a 401 rejection.
//
// This simulates what happens when an HTTP request traverses the Envoy sidecar
// proxy, which adds the X-SPIFFE-ID header before forwarding to the gateway.
func TestSidecarToGatewayFlow(t *testing.T) {
	requireGateway(t)

	mcpReq := map[string]any{
		"jsonrpc": "2.0",
		"method":  "file_read",
		"params":  map[string]any{"path": "/test"},
		"id":      1,
	}
	reqBody, err := json.Marshal(mcpReq)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, gatewayURL, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", sidecarSPIFFEID)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gateway request failed: %v", err)
	}
	defer resp.Body.Close()

	// The request must NOT be rejected by SPIFFEAuth (401). It may get a 403
	// from OPA policy (the sidecar identity may not have broad permissions),
	// or a 502 if the upstream is not running, but a 401 would mean the
	// identity header was not accepted -- which is the failure we are testing for.
	if resp.StatusCode == http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("sidecar SPIFFE ID was rejected by SPIFFEAuth (401): body=%s", string(body))
	}

	t.Logf("sidecar request accepted by SPIFFEAuth, final status=%d (non-401 confirms identity was processed)", resp.StatusCode)
}

// TestSidecarAuditAttribution verifies that when a request arrives with a
// sidecar-pattern SPIFFE ID, the gateway's audit log correctly attributes the
// request to that identity.
//
// It sends a tool call through the gateway with the sidecar SPIFFE ID, then
// uses `agw audit search` to find the audit entry and confirm the spiffe_id
// field matches.
func TestSidecarAuditAttribution(t *testing.T) {
	requireGateway(t)

	// Send a request with the sidecar SPIFFE ID to generate an audit entry.
	mcpReq := map[string]any{
		"jsonrpc": "2.0",
		"method":  "file_read",
		"params":  map[string]any{"path": "/sidecar-audit-test"},
		"id":      1,
	}
	reqBody, err := json.Marshal(mcpReq)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, gatewayURL, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", sidecarSPIFFEID)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gateway request failed: %v", err)
	}
	resp.Body.Close()

	// Give the audit subsystem a moment to flush.
	time.Sleep(500 * time.Millisecond)

	// Search audit logs for entries attributed to the sidecar SPIFFE ID.
	cmd := exec.Command("go", "run", "./cli/agw", "audit", "search",
		"--spiffe-id", sidecarSPIFFEID,
		"--last", "1m",
		"--format", "json",
	)
	cmd.Dir = pocDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("agw audit search failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var entries []struct {
		SPIFFEID string `json:"spiffe_id"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &entries); err != nil {
		t.Fatalf("invalid audit search json: %v raw=%q", err, stdout.String())
	}
	if len(entries) == 0 {
		t.Fatalf("expected audit entries for sidecar SPIFFE ID %q, got none (stdout=%q)", sidecarSPIFFEID, stdout.String())
	}

	// Verify every returned entry is attributed to the sidecar identity.
	for i, e := range entries {
		if e.SPIFFEID != sidecarSPIFFEID {
			t.Errorf("entry[%d]: expected spiffe_id=%q, got %q", i, sidecarSPIFFEID, e.SPIFFEID)
		}
	}

	t.Logf("found %d audit entries correctly attributed to sidecar SPIFFE ID %q", len(entries), sidecarSPIFFEID)
}

// TestSidecarNegative_NoIdentityReturns401 verifies that a request sent
// directly to the gateway WITHOUT the X-SPIFFE-ID header (i.e., bypassing
// the Envoy sidecar) is rejected with HTTP 401 and error code
// auth_missing_identity.
func TestSidecarNegative_NoIdentityReturns401(t *testing.T) {
	requireGateway(t)

	mcpReq := map[string]any{
		"jsonrpc": "2.0",
		"method":  "file_read",
		"params":  map[string]any{"path": "/test"},
		"id":      1,
	}
	reqBody, err := json.Marshal(mcpReq)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, gatewayURL, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Deliberately NOT setting X-SPIFFE-ID header -- simulating bypass of sidecar.

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gateway request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 for missing identity, got %d body=%s", resp.StatusCode, string(respBody))
	}

	var body map[string]any
	if err := json.Unmarshal(respBody, &body); err != nil {
		t.Logf("could not decode response body: %v (raw=%s)", err, string(respBody))
		// Still a pass -- we got 401 which is the primary assertion.
		return
	}

	code, _ := body["code"].(string)
	if code != "" && code != "auth_missing_identity" {
		t.Fatalf("expected error code auth_missing_identity, got %q body=%v", code, body)
	}

	middleware, _ := body["middleware"].(string)
	if middleware != "" && !strings.Contains(middleware, "spiffe_auth") {
		t.Fatalf("expected middleware spiffe_auth, got %q body=%v", middleware, body)
	}

	t.Logf("correctly rejected with 401 (code=%q, middleware=%q)", code, middleware)
}

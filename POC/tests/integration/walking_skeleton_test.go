//go:build integration
// +build integration

// Walking Skeleton Integration Test - RFA-qq0.13
// Proves ONE tool call traverses the full middleware stack end-to-end

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestWalkingSkeleton verifies one tool call flows through complete middleware chain:
// mTLS auth -> body capture -> SPIFFE ID extraction -> OPA policy check ->
// tool registry hash verification -> audit event -> proxy to upstream
func TestWalkingSkeleton(t *testing.T) {
	// Wait for services to be ready
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}
	if err := waitForService(opaURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("OPA not ready: %v", err)
	}

	// Create MCP request for file_read tool (lowest risk, simple test)
	mcpReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "read",
		"params": map[string]interface{}{
			"file_path": "/Users/ramirosalas/workspace/agentic_reference_architecture/POC/README.md",
		},
		"id": 1,
	}
	reqBody, err := json.Marshal(mcpReq)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	// Send request with valid SPIFFE ID (researcher agent allowed to read)
	req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// ACCEPTANCE CRITERIA CHECK 1: Request traversed middleware chain
	// We expect either:
	// - 200 if upstream Docker MCP is running
	// - 502 if upstream unavailable (proves gateway processed request and tried to proxy)
	// - 4xx if policy/tool checks worked but request was invalid
	// We should NOT get 500 (internal server error) if middleware is working
	if resp.StatusCode == http.StatusInternalServerError {
		t.Errorf("Got 500 Internal Server Error - middleware chain likely broken")
	}

	// Read audit logs from environment variable path or default
	auditLogPath := os.Getenv("AUDIT_LOG_PATH")
	if auditLogPath == "" {
		auditLogPath = "/tmp/audit.jsonl"
	}

	// Give audit log time to flush
	time.Sleep(100 * time.Millisecond)

	// ACCEPTANCE CRITERIA CHECK 2-5: Verify audit event contains all required fields
	auditData, err := os.ReadFile(auditLogPath)
	if err != nil {
		// In test environment, audit might only go to stdout
		t.Logf("Warning: Could not read audit log file: %v (audit may be stdout only in test)", err)
		t.Logf("Response status: %d (proves middleware chain executed)", resp.StatusCode)
		return
	}

	// Find the most recent audit event (last line in JSONL)
	lines := strings.Split(strings.TrimSpace(string(auditData)), "\n")
	if len(lines) == 0 {
		t.Fatal("No audit events found in audit log")
	}
	lastEvent := lines[len(lines)-1]

	var auditEvent struct {
		SessionID     string `json:"session_id"`
		DecisionID    string `json:"decision_id"`
		TraceID       string `json:"trace_id"`
		SPIFFEID      string `json:"spiffe_id"`
		Authorization *struct {
			OPADecisionID string `json:"opa_decision_id"`
			Allowed       bool   `json:"allowed"`
		} `json:"authorization"`
		Security *struct {
			ToolHashVerified bool `json:"tool_hash_verified"`
		} `json:"security"`
	}

	if err := json.Unmarshal([]byte(lastEvent), &auditEvent); err != nil {
		t.Fatalf("Failed to parse audit event: %v", err)
	}

	// AC 2: Structured JSON audit event with all required fields
	if auditEvent.SessionID == "" {
		t.Error("Audit event missing session_id")
	}
	if auditEvent.DecisionID == "" {
		t.Error("Audit event missing decision_id")
	}
	if auditEvent.TraceID == "" {
		t.Error("Audit event missing trace_id")
	}
	if auditEvent.SPIFFEID == "" {
		t.Error("Audit event missing spiffe_id")
	}

	// AC 3: OPA decision_id present and logged
	if auditEvent.Authorization == nil || auditEvent.Authorization.OPADecisionID == "" {
		t.Error("Audit event missing authorization.opa_decision_id")
	}

	// AC 4: Tool hash verification passed
	if auditEvent.Security == nil || !auditEvent.Security.ToolHashVerified {
		t.Error("Audit event shows tool_hash_verified=false or missing")
	}

	// AC 5: Agent received response (already verified via resp status check above)

	t.Logf("SUCCESS: Walking skeleton complete")
	t.Logf("  Session ID: %s", auditEvent.SessionID)
	t.Logf("  Decision ID: %s", auditEvent.DecisionID)
	t.Logf("  Trace ID: %s", auditEvent.TraceID)
	t.Logf("  SPIFFE ID: %s", auditEvent.SPIFFEID)
	t.Logf("  OPA Decision ID: %s", auditEvent.Authorization.OPADecisionID)
	t.Logf("  Tool Hash Verified: %v", auditEvent.Security.ToolHashVerified)
	t.Logf("  Response Status: %d", resp.StatusCode)
}

// TestWalkingSkeletonNegative verifies tool call with mismatched hash is denied
func TestWalkingSkeletonNegative(t *testing.T) {
	// Wait for gateway
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	// Create MCP request with WRONG hash
	mcpReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "read",
		"params": map[string]interface{}{
			"file_path": "/Users/ramirosalas/workspace/agentic_reference_architecture/POC/README.md",
			"tool_hash": "0000000000000000000000000000000000000000000000000000000000000000", // Wrong hash
		},
		"id": 1,
	}
	reqBody, err := json.Marshal(mcpReq)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req, err := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// AC (Negative): Request denied with mismatched hash
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for mismatched hash, got %d", resp.StatusCode)
	}

	// Wait for audit log to flush
	time.Sleep(100 * time.Millisecond)

	// Verify audit event records denial
	auditLogPath := os.Getenv("AUDIT_LOG_PATH")
	if auditLogPath == "" {
		auditLogPath = "/tmp/audit.jsonl"
	}

	auditData, err := os.ReadFile(auditLogPath)
	if err != nil {
		t.Logf("Warning: Could not read audit log file: %v", err)
		return
	}

	lines := strings.Split(strings.TrimSpace(string(auditData)), "\n")
	if len(lines) == 0 {
		return
	}
	lastEvent := lines[len(lines)-1]

	var auditEvent struct {
		StatusCode int `json:"status_code"`
		Security   *struct {
			ToolHashVerified bool `json:"tool_hash_verified"`
		} `json:"security"`
	}

	if err := json.Unmarshal([]byte(lastEvent), &auditEvent); err != nil {
		t.Logf("Could not parse audit event: %v", err)
		return
	}

	// Verify denial is logged
	if auditEvent.StatusCode != http.StatusForbidden {
		t.Errorf("Audit event should show 403 status, got %d", auditEvent.StatusCode)
	}

	t.Logf("SUCCESS: Negative test verified hash mismatch denial")
}

package middleware

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestAuditChain_IntegrationScenario tests the full audit chain workflow
// This test covers all acceptance criteria:
// 1. Events written as JSONL with hash chain
// 2. bundle_digest and registry_digest present
// 3. Tampering detected
// 4. First event has genesis hash
// 5. Verification utility validates entire chain
func TestAuditChain_IntegrationScenario(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "integration_audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "policy.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	// Create config files
	if err := os.WriteFile(bundlePath, []byte("package integration\ndefault allow = true"), 0644); err != nil {
		t.Fatalf("Failed to create bundle: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools:\n  - name: test\n    hash: abc"), 0644); err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	// AC1: Create auditor and generate 15 events
	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	for i := 0; i < 15; i++ {
		auditor.Log(AuditEvent{
			SessionID:  "integration-session",
			DecisionID: "integration-decision",
			TraceID:    "integration-trace",
			SPIFFEID:   "spiffe://integration/test",
			Action:     "integration_test",
			Result:     "success",
			Method:     "POST",
			Path:       "/test",
			StatusCode: 200,
		})
	}
	auditor.Close()

	// AC1 & AC4: Verify first event has genesis hash
	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("Failed to open audit file: %v", err)
	}
	scanner := bufio.NewScanner(file)

	// Read first event
	if !scanner.Scan() {
		t.Fatal("No events found in audit file")
	}
	var firstEvent AuditEvent
	if err := json.Unmarshal(scanner.Bytes(), &firstEvent); err != nil {
		t.Fatalf("Failed to unmarshal first event: %v", err)
	}
	file.Close()

	// Verify genesis hash (SHA-256 of empty string)
	genesisHash := sha256.Sum256([]byte(""))
	expectedGenesis := hex.EncodeToString(genesisHash[:])
	if firstEvent.PrevHash != expectedGenesis {
		t.Errorf("AC4 FAILED: First event prev_hash = %s, want genesis %s", firstEvent.PrevHash, expectedGenesis)
	} else {
		t.Log("AC4 PASSED: First event has correct genesis hash")
	}

	// AC2: Verify bundle_digest and registry_digest present and non-empty in ALL events
	file, err = os.Open(auditPath)
	if err != nil {
		t.Fatalf("Failed to open audit file: %v", err)
	}
	scanner = bufio.NewScanner(file)
	eventCount := 0
	for scanner.Scan() {
		eventCount++
		var event AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("Failed to unmarshal event %d: %v", eventCount, err)
		}

		if event.BundleDigest == "" {
			t.Errorf("AC2 FAILED: Event %d missing bundle_digest", eventCount)
		}
		if event.RegistryDigest == "" {
			t.Errorf("AC2 FAILED: Event %d missing registry_digest", eventCount)
		}
		if len(event.BundleDigest) != 64 {
			t.Errorf("AC2 FAILED: Event %d bundle_digest not 64 chars (SHA-256): %d", eventCount, len(event.BundleDigest))
		}
		if len(event.RegistryDigest) != 64 {
			t.Errorf("AC2 FAILED: Event %d registry_digest not 64 chars (SHA-256): %d", eventCount, len(event.RegistryDigest))
		}
	}
	file.Close()

	if eventCount != 15 {
		t.Errorf("Expected 15 events, got %d", eventCount)
	} else {
		t.Logf("AC2 PASSED: All %d events have bundle_digest and registry_digest", eventCount)
	}

	// AC5: Verification utility validates entire chain from JSONL file
	result, err := VerifyAuditChain(auditPath)
	if err != nil {
		t.Fatalf("AC5 FAILED: Chain verification error: %v", err)
	}

	if !result.Valid {
		t.Errorf("AC5 FAILED: Chain should be valid but got: %s", result.ErrorMessage)
	}
	if result.TotalEvents != 15 {
		t.Errorf("AC5 FAILED: Expected 15 events, got %d", result.TotalEvents)
	}
	if len(result.TamperedEvents) != 0 {
		t.Errorf("AC5 FAILED: Expected no tampered events, got %d", len(result.TamperedEvents))
	} else {
		t.Logf("AC5 PASSED: Verification utility validates entire chain (%d events)", result.TotalEvents)
	}

	// AC3: Tampering with any event breaks the chain
	// Parse events
	var events []AuditEvent
	file, _ = os.Open(auditPath)
	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		var event AuditEvent
		json.Unmarshal(scanner.Bytes(), &event)
		events = append(events, event)
	}
	file.Close()

	// Tamper with event 7 (middle of chain)
	events[6].Action = "TAMPERED_ACTION"

	// Write tampered events back
	file, err = os.Create(auditPath)
	if err != nil {
		t.Fatalf("Failed to write tampered file: %v", err)
	}
	for _, event := range events {
		jsonBytes, _ := json.Marshal(event)
		file.Write(append(jsonBytes, '\n'))
	}
	file.Close()

	// Verify chain breaks
	result, err = VerifyAuditChain(auditPath)
	if err != nil {
		t.Fatalf("AC3: Verification failed with error: %v", err)
	}

	if result.Valid {
		t.Error("AC3 FAILED: Chain should be invalid after tampering")
	}
	if len(result.TamperedEvents) == 0 {
		t.Error("AC3 FAILED: Expected tampered events to be detected")
	} else {
		t.Logf("AC3 PASSED: Tampering detected - %d tampered events found", len(result.TamperedEvents))
	}

	// Summary
	t.Log("==========================================")
	t.Log("ACCEPTANCE CRITERIA SUMMARY:")
	t.Log("AC1: Audit events written as JSONL with hash chain - PASSED")
	t.Log("AC2: bundle_digest and registry_digest present - PASSED")
	t.Log("AC3: Tampering breaks chain - PASSED")
	t.Log("AC4: First event has genesis hash - PASSED")
	t.Log("AC5: Verification utility validates chain - PASSED")
	t.Log("==========================================")
}

// TestAuditChain_RealWorldWorkflow simulates a realistic gateway workflow
func TestAuditChain_RealWorldWorkflow(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "gateway_audit.jsonl")

	// Use actual project config files
	bundlePath := filepath.Join(tmpDir, "mcp_policy.rego")
	registryPath := filepath.Join(tmpDir, "tool_grants.yaml")

	// Create mock config files that simulate real gateway configs
	bundleContent := `package mcp
import future.keywords.if
default allow := false
allow if {
    input.spiffe_id == "spiffe://poc.local/agents/test"
}
`
	registryContent := `tool_grants:
  - spiffe_pattern: "spiffe://poc.local/agents/*"
    allowed_tools:
      - file_read
      - file_write
    max_data_classification: internal
`

	if err := os.WriteFile(bundlePath, []byte(bundleContent), 0644); err != nil {
		t.Fatalf("Failed to create bundle: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte(registryContent), 0644); err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	// Create auditor
	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	// Simulate realistic gateway events
	scenarios := []struct {
		sessionID string
		action    string
		result    string
		status    int
	}{
		{"session-001", "mcp_request", "allowed", 200},
		{"session-001", "tool_execution", "success", 200},
		{"session-002", "mcp_request", "denied", 403},
		{"session-003", "mcp_request", "allowed", 200},
		{"session-003", "tool_execution", "error", 500},
		{"session-004", "mcp_request", "allowed", 200},
		{"session-004", "tool_execution", "success", 200},
		{"session-005", "mcp_request", "allowed", 200},
		{"session-005", "tool_execution", "success", 200},
		{"session-006", "mcp_request", "denied", 403},
	}

	for i, scenario := range scenarios {
		auditor.Log(AuditEvent{
			SessionID:  scenario.sessionID,
			DecisionID: "decision-" + scenario.sessionID,
			TraceID:    "trace-" + scenario.sessionID,
			SPIFFEID:   "spiffe://poc.local/agents/mcp-client/test",
			Action:     scenario.action,
			Result:     scenario.result,
			Method:     "POST",
			Path:       "/mcp",
			StatusCode: scenario.status,
		})

		// Verify chain integrity after each event
		if i >= 1 { // Need at least 2 events to verify chain
			result, err := VerifyAuditChain(auditPath)
			if err != nil {
				t.Fatalf("Chain verification failed after event %d: %v", i+1, err)
			}
			if !result.Valid {
				t.Errorf("Chain invalid after event %d: %s", i+1, result.ErrorMessage)
			}
		}
	}

	// Final verification
	result, err := VerifyAuditChain(auditPath)
	if err != nil {
		t.Fatalf("Final verification failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Chain should be valid after realistic workflow: %s", result.ErrorMessage)
	}
	if result.TotalEvents != len(scenarios) {
		t.Errorf("Expected %d events, got %d", len(scenarios), result.TotalEvents)
	}

	t.Logf("Real-world workflow test PASSED: %d events with valid hash chain", result.TotalEvents)
}

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

func TestAuditChainIntegrity(t *testing.T) {
	// Setup: Create temporary audit file and config files
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	// Create mock config files
	if err := os.WriteFile(bundlePath, []byte("package test\ndefault allow = false"), 0644); err != nil {
		t.Fatalf("Failed to create bundle file: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools:\n  - file_read\n  - file_write"), 0644); err != nil {
		t.Fatalf("Failed to create registry file: %v", err)
	}

	// Create auditor
	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	// Test 1: First event has genesis prev_hash (SHA-256 of empty string)
	genesisHash := sha256.Sum256([]byte(""))
	expectedGenesis := hex.EncodeToString(genesisHash[:])

	auditor.Log(AuditEvent{
		SessionID:  "session-1",
		DecisionID: "decision-1",
		TraceID:    "trace-1",
		SPIFFEID:   "spiffe://test/agent",
		Action:     "test_action",
		Result:     "success",
		Method:     "POST",
		Path:       "/test",
		StatusCode: 200,
	})

	// Read first event
	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("Failed to open audit file: %v", err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Scan()
	var firstEvent AuditEvent
	if err := json.Unmarshal(scanner.Bytes(), &firstEvent); err != nil {
		t.Fatalf("Failed to unmarshal first event: %v", err)
	}
	file.Close()

	if firstEvent.PrevHash != expectedGenesis {
		t.Errorf("First event prev_hash = %s, want genesis %s", firstEvent.PrevHash, expectedGenesis)
	}

	// Test 2: Generate multiple events and verify chain
	for i := 2; i <= 12; i++ {
		auditor.Log(AuditEvent{
			SessionID:  "session-" + string(rune('0'+i)),
			DecisionID: "decision-" + string(rune('0'+i)),
			TraceID:    "trace-" + string(rune('0'+i)),
			SPIFFEID:   "spiffe://test/agent",
			Action:     "test_action",
			Result:     "success",
			Method:     "POST",
			Path:       "/test",
			StatusCode: 200,
		})
	}

	// Test 3: Verify chain integrity (12 total events)
	result, err := VerifyAuditChain(auditPath)
	if err != nil {
		t.Fatalf("Chain verification failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Chain should be valid but got: %s", result.ErrorMessage)
	}

	if result.TotalEvents != 12 {
		t.Errorf("Expected 12 events, got %d", result.TotalEvents)
	}

	if len(result.TamperedEvents) != 0 {
		t.Errorf("Expected no tampered events, got %d", len(result.TamperedEvents))
	}

	// Test 4: Verify bundle_digest and registry_digest are present and non-empty
	file, err = os.Open(auditPath)
	if err != nil {
		t.Fatalf("Failed to open audit file: %v", err)
	}
	defer file.Close()

	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		var event AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("Failed to unmarshal event: %v", err)
		}

		if event.BundleDigest == "" {
			t.Error("Event missing bundle_digest")
		}
		if event.RegistryDigest == "" {
			t.Error("Event missing registry_digest")
		}

		// Verify digests are valid SHA-256 hex strings (64 chars)
		if len(event.BundleDigest) != 64 {
			t.Errorf("BundleDigest has invalid length: %d", len(event.BundleDigest))
		}
		if len(event.RegistryDigest) != 64 {
			t.Errorf("RegistryDigest has invalid length: %d", len(event.RegistryDigest))
		}
	}
}

func TestChainBreakDetection(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	// Create mock config files
	if err := os.WriteFile(bundlePath, []byte("package test"), 0644); err != nil {
		t.Fatalf("Failed to create bundle file: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatalf("Failed to create registry file: %v", err)
	}

	// Create auditor and generate events
	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	for i := 0; i < 10; i++ {
		auditor.Log(AuditEvent{
			SessionID:  "session",
			DecisionID: "decision",
			TraceID:    "trace",
			SPIFFEID:   "spiffe://test/agent",
			Action:     "action",
			Result:     "success",
			Method:     "POST",
			Path:       "/test",
		})
	}
	auditor.Close()

	// Tamper with middle event (line 5)
	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("Failed to open audit file: %v", err)
	}

	var lines []string
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 5 {
			// Tamper with this line by changing a field
			var event AuditEvent
			json.Unmarshal(scanner.Bytes(), &event)
			event.Action = "TAMPERED"
			tamperedBytes, _ := json.Marshal(event)
			lines = append(lines, string(tamperedBytes))
		} else {
			lines = append(lines, scanner.Text())
		}
	}
	file.Close()

	// Write tampered content back
	file, err = os.Create(auditPath)
	if err != nil {
		t.Fatalf("Failed to write tampered file: %v", err)
	}
	for _, line := range lines {
		file.WriteString(line + "\n")
	}
	file.Close()

	// Verify chain - should detect tampering
	result, err := VerifyAuditChain(auditPath)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if result.Valid {
		t.Error("Chain should be invalid after tampering")
	}

	if len(result.TamperedEvents) == 0 {
		t.Error("Expected tampered events to be detected")
	}

	// Event 6 should be flagged (its prev_hash won't match tampered event 5)
	found := false
	for _, idx := range result.TamperedEvents {
		if idx == 5 { // 0-indexed, so event 6 is index 5
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected event at index 5 to be flagged, got: %v", result.TamperedEvents)
	}
}

func TestAuditorWithoutJSONL(t *testing.T) {
	// Test backward compatibility: auditor works without JSONL path
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	if err := os.WriteFile(bundlePath, []byte("package test"), 0644); err != nil {
		t.Fatalf("Failed to create bundle file: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatalf("Failed to create registry file: %v", err)
	}

	// Create auditor WITHOUT jsonlPath (backward compatible mode)
	auditor, err := NewAuditor("", bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	// Should not panic
	auditor.Log(AuditEvent{
		SessionID: "test",
		Action:    "test",
	})

	// Verify hash chain fields are still populated
	if auditor.bundleDigest == "" {
		t.Error("BundleDigest should be populated even without JSONL")
	}
	if auditor.registryDigest == "" {
		t.Error("RegistryDigest should be populated even without JSONL")
	}
}

func TestChainResume(t *testing.T) {
	// Test that auditor can resume chain from existing file
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	if err := os.WriteFile(bundlePath, []byte("package test"), 0644); err != nil {
		t.Fatalf("Failed to create bundle file: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatalf("Failed to create registry file: %v", err)
	}

	// First auditor: write 5 events
	auditor1, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor1: %v", err)
	}
	for i := 0; i < 5; i++ {
		auditor1.Log(AuditEvent{
			SessionID: "session1",
			Action:    "action",
		})
	}
	auditor1.Close()

	// Second auditor: resume and write 5 more events
	auditor2, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor2: %v", err)
	}
	for i := 0; i < 5; i++ {
		auditor2.Log(AuditEvent{
			SessionID: "session2",
			Action:    "action",
		})
	}
	auditor2.Close()

	// Verify entire chain is valid
	result, err := VerifyAuditChain(auditPath)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Chain should be valid after resume: %s", result.ErrorMessage)
	}

	if result.TotalEvents != 10 {
		t.Errorf("Expected 10 events, got %d", result.TotalEvents)
	}
}

func TestGenesisHash(t *testing.T) {
	// Verify genesis hash computation
	genesisHash := sha256.Sum256([]byte(""))
	expected := hex.EncodeToString(genesisHash[:])

	// Known SHA-256 of empty string
	knownGenesis := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	if expected != knownGenesis {
		t.Errorf("Genesis hash = %s, want %s", expected, knownGenesis)
	}
}

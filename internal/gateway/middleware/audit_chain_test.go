// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

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
	defer func() {
		_ = auditor.Close()
	}()

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

	// RFA-lz1: Flush async writes before reading the file
	auditor.Flush()

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
	if err := file.Close(); err != nil {
		t.Fatalf("Failed to close audit file: %v", err)
	}

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

	// RFA-lz1: Flush async writes before verifying chain
	auditor.Flush()

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
	defer func() {
		_ = file.Close()
	}()

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
	if err := auditor.Close(); err != nil {
		t.Fatalf("Failed to close auditor: %v", err)
	}

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
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				t.Fatalf("Failed to parse event while tampering: %v", err)
			}
			event.Action = "TAMPERED"
			tamperedBytes, _ := json.Marshal(event)
			lines = append(lines, string(tamperedBytes))
		} else {
			lines = append(lines, scanner.Text())
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Failed to close file after read: %v", err)
	}

	// Write tampered content back
	file, err = os.Create(auditPath)
	if err != nil {
		t.Fatalf("Failed to write tampered file: %v", err)
	}
	for _, line := range lines {
		if _, err := file.WriteString(line + "\n"); err != nil {
			t.Fatalf("Failed to write tampered line: %v", err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Failed to close tampered file: %v", err)
	}

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
	defer func() {
		_ = auditor.Close()
	}()

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
	if err := auditor1.Close(); err != nil {
		t.Fatalf("Failed to close auditor1: %v", err)
	}

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
	if err := auditor2.Close(); err != nil {
		t.Fatalf("Failed to close auditor2: %v", err)
	}

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

// ---- RFA-lz1: Async Audit Logging Tests ----

// TestAsyncAuditFlush verifies that Flush() blocks until all queued events
// have been written to disk. This is the core correctness guarantee for
// async audit logging.
func TestAsyncAuditFlush(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	if err := os.WriteFile(bundlePath, []byte("package test"), 0644); err != nil {
		t.Fatalf("Failed to write bundle: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatalf("Failed to write registry: %v", err)
	}

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer func() {
		_ = auditor.Close()
	}()

	// Log 100 events rapidly
	for i := 0; i < 100; i++ {
		auditor.Log(AuditEvent{
			SessionID: "flush-test",
			Action:    "test_action",
		})
	}

	// After Flush(), all 100 events must be on disk
	auditor.Flush()

	result, err := VerifyAuditChain(auditPath)
	if err != nil {
		t.Fatalf("Chain verification failed: %v", err)
	}

	if result.TotalEvents != 100 {
		t.Errorf("Expected 100 events after Flush(), got %d", result.TotalEvents)
	}
	if !result.Valid {
		t.Errorf("Chain should be valid after Flush(): %s", result.ErrorMessage)
	}
}

// TestAsyncAuditChainIntegrity verifies that the hash chain is correct
// even with async writes -- the hash computation is synchronous so
// ordering is guaranteed regardless of I/O timing.
func TestAsyncAuditChainIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	if err := os.WriteFile(bundlePath, []byte("package test"), 0644); err != nil {
		t.Fatalf("Failed to write bundle: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatalf("Failed to write registry: %v", err)
	}

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	// Log 500 events to stress the async pipeline
	for i := 0; i < 500; i++ {
		auditor.Log(AuditEvent{
			SessionID:  "async-chain-test",
			DecisionID: "decision",
			TraceID:    "trace",
			SPIFFEID:   "spiffe://test/agent",
			Action:     "stress_test",
			Result:     "success",
			Method:     "POST",
			Path:       "/test",
			StatusCode: 200,
		})
	}

	// Close drains the channel, ensuring all writes complete
	if err := auditor.Close(); err != nil {
		t.Fatalf("Failed to close auditor: %v", err)
	}

	// Verify the entire chain is valid
	result, err := VerifyAuditChain(auditPath)
	if err != nil {
		t.Fatalf("Chain verification failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Chain should be valid with async writes: %s", result.ErrorMessage)
	}
	if result.TotalEvents != 500 {
		t.Errorf("Expected 500 events, got %d", result.TotalEvents)
	}
	if len(result.TamperedEvents) != 0 {
		t.Errorf("Expected no tampered events, got %d", len(result.TamperedEvents))
	}

	t.Logf("Async chain integrity PASSED: 500 events with valid hash chain")
}

// TestAsyncAuditCloseIdempotent verifies that calling Close() multiple
// times does not panic or cause errors.
func TestAsyncAuditCloseIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	if err := os.WriteFile(bundlePath, []byte("package test"), 0644); err != nil {
		t.Fatalf("Failed to write bundle: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatalf("Failed to write registry: %v", err)
	}

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	auditor.Log(AuditEvent{
		SessionID: "idempotent-test",
		Action:    "test",
	})

	// Close multiple times -- should not panic
	err1 := auditor.Close()
	err2 := auditor.Close()
	err3 := auditor.Close()

	if err1 != nil {
		t.Errorf("First Close() returned error: %v", err1)
	}
	if err2 != nil {
		t.Errorf("Second Close() returned error: %v", err2)
	}
	if err3 != nil {
		t.Errorf("Third Close() returned error: %v", err3)
	}
}

// TestAsyncAuditFlushMultiple verifies that Flush() can be called multiple
// times and each call correctly waits for pending events.
func TestAsyncAuditFlushMultiple(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	if err := os.WriteFile(bundlePath, []byte("package test"), 0644); err != nil {
		t.Fatalf("Failed to write bundle: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatalf("Failed to write registry: %v", err)
	}

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer func() {
		_ = auditor.Close()
	}()

	// First batch
	for i := 0; i < 10; i++ {
		auditor.Log(AuditEvent{
			SessionID: "batch-1",
			Action:    "test",
		})
	}
	auditor.Flush()

	result, _ := VerifyAuditChain(auditPath)
	if result.TotalEvents != 10 {
		t.Errorf("After first flush: expected 10, got %d", result.TotalEvents)
	}

	// Second batch
	for i := 0; i < 15; i++ {
		auditor.Log(AuditEvent{
			SessionID: "batch-2",
			Action:    "test",
		})
	}
	auditor.Flush()

	result, _ = VerifyAuditChain(auditPath)
	if result.TotalEvents != 25 {
		t.Errorf("After second flush: expected 25, got %d", result.TotalEvents)
	}

	if !result.Valid {
		t.Errorf("Chain should be valid after multiple flushes: %s", result.ErrorMessage)
	}
}

// TestAsyncAuditNoDataLoss verifies that no events are lost during async
// processing, even under rapid-fire logging.
func TestAsyncAuditNoDataLoss(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	if err := os.WriteFile(bundlePath, []byte("package test"), 0644); err != nil {
		t.Fatalf("Failed to write bundle: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatalf("Failed to write registry: %v", err)
	}

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	// Rapid fire 1000 events
	const eventCount = 1000
	for i := 0; i < eventCount; i++ {
		auditor.Log(AuditEvent{
			SessionID: "no-data-loss",
			Action:    "rapid_fire",
		})
	}

	// Close ensures all events are written
	if err := auditor.Close(); err != nil {
		t.Fatalf("Failed to close auditor: %v", err)
	}

	// Count events in file
	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("Failed to open audit file: %v", err)
	}
	defer func() {
		_ = file.Close()
	}()

	lineCount := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineCount++
	}

	if lineCount != eventCount {
		t.Errorf("Data loss detected: expected %d events, got %d", eventCount, lineCount)
	}
}

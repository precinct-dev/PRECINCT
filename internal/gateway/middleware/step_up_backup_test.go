// OC-lmzm: Unit and integration tests for X-Precinct-Backup-Recommended header.
//
// Tests verify:
//   - RequiresBackup=true + action allowed -> header present ("true")
//   - RequiresBackup=false + action allowed -> header absent
//   - RequiresBackup=true + action denied -> header absent
//   - Audit log records BackupRecommended when RequiresBackup=true and allowed
//   - Session context DestructiveActionsAuthorized incremented
//   - Integration: owner with partially reversible action -> header present
package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// --- Unit tests for X-Precinct-Backup-Recommended header ---

func TestBackupHeader_RequiresBackupTrue_ActionAllowed(t *testing.T) {
	// AC1: X-Precinct-Backup-Recommended: true set when RequiresBackup=true AND action allowed.
	// Use "modify_resource" tool (contains "modify" -> partially_reversible, Score=2, RequiresBackup=true).
	// Owner (Level=1) keeps risk low -> fast_path -> allowed.
	registry := testRegistry()
	registry.tools["modify_resource"] = ToolDefinition{
		Name:                "modify_resource",
		Description:         "Modify a resource",
		RiskLevel:           "low",
		AllowedDestinations: []string{},
	}
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	var receivedBackupHeader string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBackupHeader = r.Header.Get("X-Precinct-Backup-Recommended")
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	body := createTestMCPBody("tools/call", map[string]interface{}{
		"name":      "modify_resource",
		"arguments": map[string]interface{}{"id": "res-123"},
	})

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/owner/alice")
	ctx = WithSessionID(ctx, "test-session-backup-present")
	ctx = WithPrincipalLevel(ctx, 1) // owner
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if receivedBackupHeader != "true" {
		t.Errorf("expected X-Precinct-Backup-Recommended=true, got %q", receivedBackupHeader)
	}
}

func TestBackupHeader_RequiresBackupFalse_ActionAllowed(t *testing.T) {
	// AC2: Header absent when RequiresBackup=false (read tool -> reversible, Score=0).
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	var receivedBackupHeader string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBackupHeader = r.Header.Get("X-Precinct-Backup-Recommended")
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	body := createTestMCPBody("tools/call", map[string]interface{}{
		"name":      "read",
		"arguments": map[string]interface{}{},
	})

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test")
	ctx = WithSessionID(ctx, "test-session-backup-absent")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if receivedBackupHeader != "" {
		t.Errorf("expected X-Precinct-Backup-Recommended absent, got %q", receivedBackupHeader)
	}
}

func TestBackupHeader_RequiresBackupTrue_ActionDenied(t *testing.T) {
	// AC2: Header absent when action is denied (even if RequiresBackup=true).
	// Use "delete_resource" tool (contains "delete" -> irreversible, Score=3, RequiresBackup=true).
	// Agent (Level=3) + irreversible -> forces approval gate -> denied without token.
	registry := testRegistry()
	registry.tools["delete_resource"] = ToolDefinition{
		Name:                "delete_resource",
		Description:         "Delete a resource permanently",
		RiskLevel:           "medium",
		AllowedDestinations: []string{},
	}
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	body := createTestMCPBody("tools/call", map[string]interface{}{
		"name":      "delete_resource",
		"arguments": map[string]interface{}{"id": "res-123"},
	})

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/external/agent-x")
	ctx = WithSessionID(ctx, "test-session-backup-denied")
	ctx = WithPrincipalLevel(ctx, 3) // agent level -> forces approval for irreversible
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Action denied (403) -> header should NOT be set
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	if nextCalled {
		t.Error("next handler should not be called for denied action")
	}
	// Since the request was denied and next was never called, the header
	// was never visible to the downstream. Verify the request header was
	// not mutated (header only set on allowed path).
	if req.Header.Get("X-Precinct-Backup-Recommended") != "" {
		t.Error("X-Precinct-Backup-Recommended should not be set on denied action")
	}
}

func TestBackupHeader_AuditIncludesBackupRecommended(t *testing.T) {
	// AC3: Audit log records BackupRecommended=true when RequiresBackup=true and allowed.
	tmpDir := t.TempDir()
	auditPath := tmpDir + "/audit.jsonl"
	policyPath := tmpDir + "/policy.rego"
	registryPath := tmpDir + "/registry.yaml"

	if err := os.WriteFile(policyPath, []byte("package test"), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatalf("failed to write registry file: %v", err)
	}

	auditor, err := NewAuditor(auditPath, policyPath, registryPath)
	if err != nil {
		t.Fatalf("failed to create auditor: %v", err)
	}
	t.Cleanup(func() { _ = auditor.Close() })

	registry := testRegistry()
	registry.tools["modify_resource"] = ToolDefinition{
		Name:                "modify_resource",
		Description:         "Modify a resource",
		RiskLevel:           "low",
		AllowedDestinations: []string{},
	}
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, auditor)

	body := createTestMCPBody("tools/call", map[string]interface{}{
		"name":      "modify_resource",
		"arguments": map[string]interface{}{"id": "res-123"},
	})

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/owner/alice")
	ctx = WithSessionID(ctx, "test-session-audit-backup")
	ctx = WithPrincipalLevel(ctx, 1)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	auditor.Flush()

	auditData, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("failed to read audit file: %v", err)
	}
	if len(auditData) == 0 {
		t.Fatal("audit file should not be empty")
	}

	var found bool
	for _, line := range strings.Split(string(auditData), "\n") {
		if line == "" {
			continue
		}
		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if event.Action == "step_up_gating" {
			found = true
			if event.Security == nil {
				t.Fatal("expected security audit data in step_up_gating event")
			}
			if !event.Security.BackupRecommended {
				t.Error("expected BackupRecommended=true in audit event for modify_resource")
			}
			// "modify_resource" -> partially_reversible (Score=2)
			if event.Security.ReversibilityScore != 2 {
				t.Errorf("expected reversibility_score=2, got %d", event.Security.ReversibilityScore)
			}
			break
		}
	}
	if !found {
		t.Fatal("step_up_gating audit event not found in audit file")
	}
}

func TestBackupHeader_AuditBackupRecommendedFalse_WhenReversible(t *testing.T) {
	// Audit log records BackupRecommended=false for reversible actions.
	tmpDir := t.TempDir()
	auditPath := tmpDir + "/audit.jsonl"
	policyPath := tmpDir + "/policy.rego"
	registryPath := tmpDir + "/registry.yaml"

	if err := os.WriteFile(policyPath, []byte("package test"), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatalf("failed to write registry file: %v", err)
	}

	auditor, err := NewAuditor(auditPath, policyPath, registryPath)
	if err != nil {
		t.Fatalf("failed to create auditor: %v", err)
	}
	t.Cleanup(func() { _ = auditor.Close() })

	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, auditor)

	body := createTestMCPBody("tools/call", map[string]interface{}{
		"name":      "read",
		"arguments": map[string]interface{}{},
	})

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test")
	ctx = WithSessionID(ctx, "test-session-audit-no-backup")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	auditor.Flush()

	auditData, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("failed to read audit file: %v", err)
	}

	for _, line := range strings.Split(string(auditData), "\n") {
		if line == "" {
			continue
		}
		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if event.Action == "step_up_gating" {
			if event.Security != nil && event.Security.BackupRecommended {
				t.Error("expected BackupRecommended=false for reversible read action")
			}
			break
		}
	}
}

func TestBackupHeader_SessionDestructiveActionsIncremented(t *testing.T) {
	// AC4: Session context records authorized destructive action.
	registry := testRegistry()
	registry.tools["modify_resource"] = ToolDefinition{
		Name:                "modify_resource",
		Description:         "Modify a resource",
		RiskLevel:           "low",
		AllowedDestinations: []string{},
	}
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	session := &AgentSession{
		ID:                           "test-session-destructive",
		DestructiveActionsAuthorized: 0,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	body := createTestMCPBody("tools/call", map[string]interface{}{
		"name":      "modify_resource",
		"arguments": map[string]interface{}{"id": "res-123"},
	})

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/owner/alice")
	ctx = WithSessionID(ctx, "test-session-destructive")
	ctx = WithPrincipalLevel(ctx, 1)
	ctx = WithSessionContextData(ctx, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if session.DestructiveActionsAuthorized != 1 {
		t.Errorf("expected DestructiveActionsAuthorized=1, got %d", session.DestructiveActionsAuthorized)
	}
}

func TestBackupHeader_SessionNotIncrementedForReversible(t *testing.T) {
	// Session counter should NOT increment for reversible actions.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	session := &AgentSession{
		ID:                           "test-session-no-increment",
		DestructiveActionsAuthorized: 0,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	body := createTestMCPBody("tools/call", map[string]interface{}{
		"name":      "read",
		"arguments": map[string]interface{}{},
	})

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test")
	ctx = WithSessionID(ctx, "test-session-no-increment")
	ctx = WithSessionContextData(ctx, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if session.DestructiveActionsAuthorized != 0 {
		t.Errorf("expected DestructiveActionsAuthorized=0 for reversible action, got %d", session.DestructiveActionsAuthorized)
	}
}

// --- Integration test: owner with partially reversible action ---

func TestBackupHeader_Integration_OwnerPartiallyReversible(t *testing.T) {
	// AC7: Integration test -- owner (Level=1) with Score=2 action (partially reversible)
	// -> allowed through fast_path -> X-Precinct-Backup-Recommended: true present.
	registry := testRegistry()
	registry.tools["update_config"] = ToolDefinition{
		Name:                "update_config",
		Description:         "Update system configuration",
		RiskLevel:           "low",
		AllowedDestinations: []string{},
	}
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	tmpDir := t.TempDir()
	auditPath := tmpDir + "/audit.jsonl"
	policyPath := tmpDir + "/policy.rego"
	registryPath := tmpDir + "/registry.yaml"

	if err := os.WriteFile(policyPath, []byte("package test"), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatalf("failed to write registry file: %v", err)
	}

	auditor, err := NewAuditor(auditPath, policyPath, registryPath)
	if err != nil {
		t.Fatalf("failed to create auditor: %v", err)
	}
	t.Cleanup(func() { _ = auditor.Close() })

	session := &AgentSession{
		ID:                           "integration-session",
		DestructiveActionsAuthorized: 0,
	}

	var receivedBackupHeader string
	var receivedReversibilityHeader string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBackupHeader = r.Header.Get("X-Precinct-Backup-Recommended")
		receivedReversibilityHeader = r.Header.Get("X-Precinct-Reversibility")
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, auditor)

	body := createTestMCPBody("tools/call", map[string]interface{}{
		"name":      "update_config",
		"arguments": map[string]interface{}{"key": "max_retries", "value": "5"},
	})

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/owner/alice")
	ctx = WithSessionID(ctx, "integration-session")
	ctx = WithPrincipalLevel(ctx, 1) // owner
	ctx = WithSessionContextData(ctx, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Verify allowed (200)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Verify X-Precinct-Backup-Recommended header
	if receivedBackupHeader != "true" {
		t.Errorf("expected X-Precinct-Backup-Recommended=true, got %q", receivedBackupHeader)
	}

	// Verify X-Precinct-Reversibility header (update -> partially_reversible)
	if receivedReversibilityHeader != "partially_reversible" {
		t.Errorf("expected X-Precinct-Reversibility=partially_reversible, got %q", receivedReversibilityHeader)
	}

	// Verify session counter incremented
	if session.DestructiveActionsAuthorized != 1 {
		t.Errorf("expected DestructiveActionsAuthorized=1, got %d", session.DestructiveActionsAuthorized)
	}

	// Verify audit log
	auditor.Flush()

	auditData, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("failed to read audit file: %v", err)
	}

	var foundAudit bool
	for _, line := range strings.Split(string(auditData), "\n") {
		if line == "" {
			continue
		}
		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if event.Action == "step_up_gating" {
			foundAudit = true
			if event.Security == nil {
				t.Fatal("expected security audit data")
			}
			if !event.Security.BackupRecommended {
				t.Error("expected BackupRecommended=true in audit event")
			}
			if event.Security.ReversibilityScore != 2 {
				t.Errorf("expected reversibility_score=2, got %d", event.Security.ReversibilityScore)
			}
			if event.Security.ReversibilityCategory != "partially_reversible" {
				t.Errorf("expected reversibility_category=partially_reversible, got %q", event.Security.ReversibilityCategory)
			}
			break
		}
	}
	if !foundAudit {
		t.Fatal("step_up_gating audit event not found")
	}
}

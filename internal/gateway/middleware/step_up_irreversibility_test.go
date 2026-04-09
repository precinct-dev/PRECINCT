// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// OC-h4m7: Unit and integration tests for irreversibility-aware step-up gating.
//
// Tests verify:
//   - ClassifyReversibility is called within ComputeRiskScore via WithReversibility option
//   - ActionReversibility.Score >= 2 overrides RiskDimension.Reversibility
//   - Irreversible (Score=3) by non-owner (Level > 1) forces Approval gate (Total >= 7)
//   - Irreversible (Score=3) in escalated session forces Deny gate (Total >= 10)
//   - Partially reversible (Score=2) only overrides, no gate forcing
//   - Reversible action (read) produces no change from classifier
//   - X-Precinct-Reversibility header is injected
//   - Audit events include reversibility classification
//   - New error code irreversible_action_denied exists
package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// --- Unit tests for ComputeRiskScore with reversibility options ---

func TestComputeRiskScore_IrreversibleByOwner_NoForcing(t *testing.T) {
	// AC3: Owner (Level=1) with irreversible action should NOT force approval gate.
	// Level=1 is NOT > 1, so no gate forcing occurs.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")
	rev := ActionReversibility{Score: 3, Category: "irreversible"}

	score := ComputeRiskScore(&readDef, nil, "", false, registry, allowlist, config.UnknownToolDefaults,
		WithReversibility(rev),
		WithPrincipalLevelOption(1), // owner
	)

	// read tool is low risk (impact=0, rev=0, exp=0, nov=0)
	// With reversibility override: rev becomes 3 (since 3 >= 2 and 3 > 0)
	// But owner (Level=1) should NOT force total to >= 7
	if score.Reversibility != 3 {
		t.Errorf("reversibility should be overridden to 3, got %d", score.Reversibility)
	}
	gate := DetermineGate(score.Total(), config.Thresholds)
	if gate == "approval" || gate == "deny" {
		t.Errorf("owner (Level=1) with irreversible action should not be forced to approval/deny, got gate=%s total=%d", gate, score.Total())
	}
}

func TestComputeRiskScore_IrreversibleByAgent_ForcesApproval(t *testing.T) {
	// AC3: Agent (Level=3) with irreversible action forces Approval gate (Total >= 7).
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")
	rev := ActionReversibility{Score: 3, Category: "irreversible"}

	score := ComputeRiskScore(&readDef, nil, "", false, registry, allowlist, config.UnknownToolDefaults,
		WithReversibility(rev),
		WithPrincipalLevelOption(3), // agent
	)

	if score.Total() < 7 {
		t.Errorf("irreversible action by agent (Level=3) should force total >= 7, got %d", score.Total())
	}
	gate := DetermineGate(score.Total(), config.Thresholds)
	if gate != "approval" && gate != "deny" {
		t.Errorf("expected approval or deny gate for irreversible+agent, got %s", gate)
	}
}

func TestComputeRiskScore_IrreversibleEscalatedSession_ForcesDeny(t *testing.T) {
	// AC4: Irreversible (Score=3) in escalated session (EscalationScore > 15) forces Deny gate (Total >= 10).
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")
	rev := ActionReversibility{Score: 3, Category: "irreversible"}
	session := &AgentSession{
		EscalationScore: 20, // above EscalationWarningThreshold (15)
	}

	score := ComputeRiskScore(&readDef, session, "", false, registry, allowlist, config.UnknownToolDefaults,
		WithReversibility(rev),
		WithPrincipalLevelOption(3), // agent
	)

	if score.Total() < 10 {
		t.Errorf("irreversible action in escalated session should force total >= 10, got %d", score.Total())
	}
	gate := DetermineGate(score.Total(), config.Thresholds)
	if gate != "deny" {
		t.Errorf("expected deny gate for irreversible+escalated, got %s", gate)
	}
}

func TestComputeRiskScore_PartiallyReversible_OverrideOnly(t *testing.T) {
	// AC2: Score=2 overrides Reversibility dimension but does NOT force gate escalation.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")
	rev := ActionReversibility{Score: 2, Category: "partially_reversible"}

	score := ComputeRiskScore(&readDef, nil, "", false, registry, allowlist, config.UnknownToolDefaults,
		WithReversibility(rev),
		WithPrincipalLevelOption(3), // agent -- but Score=2 should not trigger forcing
	)

	// read tool base: impact=0, rev=0, exp=0, nov=0
	// With Score=2 override: rev becomes 2
	if score.Reversibility != 2 {
		t.Errorf("reversibility should be overridden to 2, got %d", score.Reversibility)
	}
	// Total = 0 + 2 + 0 + 0 = 2, which is fast_path
	gate := DetermineGate(score.Total(), config.Thresholds)
	if gate != "fast_path" {
		t.Errorf("partially reversible by agent should not force gate escalation, got gate=%s total=%d", gate, score.Total())
	}
}

func TestComputeRiskScore_ReversibleAction_NoChange(t *testing.T) {
	// Reversible action (Score=0) should not change anything.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")
	rev := ActionReversibility{Score: 0, Category: "reversible"}

	score := ComputeRiskScore(&readDef, nil, "", false, registry, allowlist, config.UnknownToolDefaults,
		WithReversibility(rev),
		WithPrincipalLevelOption(3),
	)

	// read tool base: impact=0, rev=0, exp=0, nov=0, total=0
	if score.Reversibility != 0 {
		t.Errorf("reversible action should not override, got reversibility=%d", score.Reversibility)
	}
	if score.Total() != 0 {
		t.Errorf("reversible action should have total=0, got %d", score.Total())
	}
}

func TestComputeRiskScore_NoReversibilityOption_BackwardCompatible(t *testing.T) {
	// Without WithReversibility option, ComputeRiskScore behaves exactly as before.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")

	scoreOld := ComputeRiskScore(&readDef, nil, "", false, registry, allowlist, config.UnknownToolDefaults)
	scoreNew := ComputeRiskScore(&readDef, nil, "", false, registry, allowlist, config.UnknownToolDefaults,
		WithPrincipalLevelOption(3),
	)

	if scoreOld != scoreNew {
		t.Errorf("without WithReversibility, scores should match: old=%+v new=%+v", scoreOld, scoreNew)
	}
}

func TestComputeRiskScore_UnknownTool_WithReversibility(t *testing.T) {
	// Unknown tool (nil toolDef) with reversibility override should still apply overrides.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	rev := ActionReversibility{Score: 3, Category: "irreversible"}
	session := &AgentSession{EscalationScore: 20}

	score := ComputeRiskScore(nil, session, "", false, registry, allowlist, config.UnknownToolDefaults,
		WithReversibility(rev),
		WithPrincipalLevelOption(3),
	)

	// Unknown defaults: impact=2, rev=2, exp=2, nov=3 = 9
	// With rev override: rev stays 3 (3 > 2), impact gets bumped for deny
	if score.Reversibility != 3 {
		t.Errorf("reversibility should be overridden to 3 for unknown tool, got %d", score.Reversibility)
	}
	if score.Total() < 10 {
		t.Errorf("irreversible+escalated unknown tool should force total >= 10, got %d", score.Total())
	}
}

// --- Tests for error code existence ---

func TestErrorCode_IrreversibleActionDenied_Exists(t *testing.T) {
	// AC6: New error code must exist.
	if ErrIrreversibleActionDenied != "irreversible_action_denied" {
		t.Errorf("expected error code 'irreversible_action_denied', got %q", ErrIrreversibleActionDenied)
	}
}

// --- Tests for escalation threshold constants ---

func TestEscalationThresholds(t *testing.T) {
	if EscalationWarningThreshold != 15 {
		t.Errorf("EscalationWarningThreshold should be 15, got %f", EscalationWarningThreshold)
	}
	if EscalationCriticalThreshold != 25 {
		t.Errorf("EscalationCriticalThreshold should be 25, got %f", EscalationCriticalThreshold)
	}
	if EscalationEmergencyThreshold != 40 {
		t.Errorf("EscalationEmergencyThreshold should be 40, got %f", EscalationEmergencyThreshold)
	}
}

// --- Tests for principal level context accessors ---

func TestPrincipalLevelContext(t *testing.T) {
	ctx := context.Background()

	// Default is 0
	if GetPrincipalLevel(ctx) != 0 {
		t.Errorf("default principal level should be 0, got %d", GetPrincipalLevel(ctx))
	}

	// Set and retrieve
	ctx = WithPrincipalLevel(ctx, 3)
	if GetPrincipalLevel(ctx) != 3 {
		t.Errorf("expected principal level 3, got %d", GetPrincipalLevel(ctx))
	}
}

// --- Integration tests: full middleware chain with reversibility ---

func TestStepUpGating_IrreversibleDeleteByAgent_ForcesApproval(t *testing.T) {
	// AC3 integration: External user (agent-level) attempts delete tool -> approval gate.
	registry := testRegistry()
	// Add a "delete_resource" tool with medium risk level
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
	ctx = WithSessionID(ctx, "test-session-delete")
	ctx = WithPrincipalLevel(ctx, 3) // agent level
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// With agent level (3) and irreversible action (delete), gate should be forced to approval.
	// Since no approval token is provided, the request should be denied (403).
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
	if nextCalled {
		t.Error("next handler should not be called for irreversible action without approval token")
	}

	// Verify error response contains approval requirement
	var errResp GatewayError
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Code != ErrStepUpApprovalRequired {
		t.Errorf("expected error code %q, got %q", ErrStepUpApprovalRequired, errResp.Code)
	}
}

func TestStepUpGating_IrreversibleDeleteInEscalatedSession_ForcesDeny(t *testing.T) {
	// AC4 integration: External user in escalated session (EscalationScore > 15) attempts delete -> deny gate.
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

	session := &AgentSession{
		EscalationScore: 20, // above EscalationWarningThreshold (15)
	}

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/external/agent-x")
	ctx = WithSessionID(ctx, "test-session-escalated")
	ctx = WithPrincipalLevel(ctx, 3) // agent level
	ctx = WithSessionContextData(ctx, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// With escalated session and irreversible action, gate should be deny (403).
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
	if nextCalled {
		t.Error("next handler should not be called for irreversible action in escalated session")
	}

	var errResp GatewayError
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Code != ErrStepUpDenied {
		t.Errorf("expected error code %q, got %q", ErrStepUpDenied, errResp.Code)
	}
}

func TestStepUpGating_ReversibilityHeader_Injected(t *testing.T) {
	// AC5: X-Precinct-Reversibility header injected into proxied requests.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	var receivedHeader string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Precinct-Reversibility")
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
	ctx = WithSessionID(ctx, "test-session-header")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	// "read" tool should classify as "reversible" (Score=0)
	if receivedHeader == "" {
		t.Error("X-Precinct-Reversibility header should be injected")
	}
	if receivedHeader != "reversible" {
		t.Errorf("expected X-Precinct-Reversibility=reversible for read tool, got %q", receivedHeader)
	}
}

func TestStepUpGating_DeleteTool_ReversibilityHeader(t *testing.T) {
	// Verify delete tool gets "irreversible" header value.
	registry := testRegistry()
	registry.tools["delete_resource"] = ToolDefinition{
		Name:                "delete_resource",
		Description:         "Delete a resource permanently",
		RiskLevel:           "low", // low risk level but irreversible name
		AllowedDestinations: []string{},
	}
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	var receivedHeader string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Precinct-Reversibility")
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
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test")
	ctx = WithSessionID(ctx, "test-session-delete-header")
	ctx = WithPrincipalLevel(ctx, 1) // owner -- will NOT force approval
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// "delete_resource" tool name contains "delete" -> irreversible category
	if receivedHeader != "irreversible" {
		t.Errorf("expected X-Precinct-Reversibility=irreversible for delete tool, got %q", receivedHeader)
	}
}

func TestStepUpGating_AuditIncludesReversibility(t *testing.T) {
	// AC7: Audit events include reversibility classification.
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
	ctx = WithSessionID(ctx, "test-session-audit")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// Flush auditor to ensure event is written
	auditor.Flush()

	// Read audit file and check for reversibility fields
	auditData, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("failed to read audit file: %v", err)
	}
	if len(auditData) == 0 {
		t.Fatal("audit file should not be empty")
	}

	// Find the step_up_gating event
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
			// "read" tool -> reversible (score=0)
			if event.Security.ReversibilityCategory != "reversible" {
				t.Errorf("expected reversibility_category=reversible, got %q", event.Security.ReversibilityCategory)
			}
			if event.Security.ReversibilityScore != 0 {
				t.Errorf("expected reversibility_score=0, got %d", event.Security.ReversibilityScore)
			}
			break
		}
	}
	if !found {
		t.Fatal("step_up_gating audit event not found in audit file")
	}
}

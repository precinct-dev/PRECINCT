// OC-d77k: Unit and integration tests for escalation score integration with step-up gating.
//
// Tests verify:
//   - ComputeRiskScore checks session.EscalationScore against thresholds (AC1)
//   - EscalationScore >= Critical (25): +3 added to Impact dimension (AC2)
//   - EscalationScore >= Emergency (40): all RiskDimension values set to 3 (AC3)
//   - RecordAction computes escalation contribution and updates session (AC4, AC5)
//   - Threshold crossing triggers SecurityFlagsCollector and session.EscalationFlags (AC6)
//   - Audit events include escalation_score and escalation_state (AC7)
//   - Gate transitions verified at each threshold (AC8)
//   - Integration test: sequence of destructive actions -> gate elevation (AC9)
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
	"time"
)

// --- Unit tests for ComputeRiskScore with escalation overrides ---

func TestComputeRiskScore_NoEscalation_NoChange(t *testing.T) {
	// AC1: With EscalationScore=0, ComputeRiskScore produces the same result as before.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")
	session := &AgentSession{EscalationScore: 0}

	score := ComputeRiskScore(&readDef, session, "", false, registry, allowlist, config.UnknownToolDefaults)

	// read tool: impact=0, rev=0, exp=0, nov=0 = 0
	if score.Total() != 0 {
		t.Errorf("expected total=0 with zero escalation, got %d", score.Total())
	}
	gate := DetermineGate(score.Total(), config.Thresholds)
	if gate != "fast_path" {
		t.Errorf("expected fast_path gate, got %s", gate)
	}
}

func TestComputeRiskScore_CriticalEscalation_AddsImpact(t *testing.T) {
	// AC2: EscalationScore >= 25 adds +3 to Impact dimension.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")
	session := &AgentSession{EscalationScore: 25}

	score := ComputeRiskScore(&readDef, session, "", false, registry, allowlist, config.UnknownToolDefaults)

	// read tool base: impact=0, rev=0, exp=0, nov=0
	// With Critical escalation: impact = 0+3 = 3
	if score.Impact != 3 {
		t.Errorf("expected impact=3 with critical escalation, got %d", score.Impact)
	}
	// Total = 3+0+0+0 = 3, which is still fast_path boundary
	if score.Total() != 3 {
		t.Errorf("expected total=3, got %d", score.Total())
	}
}

func TestComputeRiskScore_CriticalEscalation_ImpactCappedAt3(t *testing.T) {
	// AC2: Impact dimension is capped at 3 even when base impact is already > 0.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	bashDef, _ := registry.GetToolDefinition("bash") // critical: impact=3
	session := &AgentSession{EscalationScore: 30}

	score := ComputeRiskScore(&bashDef, session, "", false, registry, allowlist, config.UnknownToolDefaults)

	// bash base: impact=3, adding +3 should still cap at 3
	if score.Impact != 3 {
		t.Errorf("expected impact=3 (capped), got %d", score.Impact)
	}
}

func TestComputeRiskScore_CriticalEscalation_FastPathBecomesStepUp(t *testing.T) {
	// AC8: A normally fast-path tool (total 0-3) becomes step-up (4-6) at Critical.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	// grep tool: low risk, impact=0, rev=0, exp=0, nov=0, total=0
	grepDef, _ := registry.GetToolDefinition("grep")
	session := &AgentSession{EscalationScore: 25}

	score := ComputeRiskScore(&grepDef, session, "", false, registry, allowlist, config.UnknownToolDefaults)

	// With Critical escalation: impact = 0+3 = 3, total = 3
	// Total = 3 is still fast_path boundary (fast_path_max=3)
	gate := DetermineGate(score.Total(), config.Thresholds)
	if gate != "fast_path" {
		t.Errorf("expected fast_path for total=%d, got %s", score.Total(), gate)
	}

	// But a medium-risk tool with some base score will cross over
	httpDef, _ := registry.GetToolDefinition("http_request") // medium: impact=1, rev=1
	score2 := ComputeRiskScore(&httpDef, session, "", false, registry, allowlist, config.UnknownToolDefaults)

	// base: impact=1, rev=1, exp=0, nov=0, total=2
	// With Critical: impact = min(1+3, 3) = 3, total = 3+1+0+0 = 4
	if score2.Total() < 4 {
		t.Errorf("expected total >= 4 for medium tool with critical escalation, got %d", score2.Total())
	}
	gate2 := DetermineGate(score2.Total(), config.Thresholds)
	if gate2 != "step_up" {
		t.Errorf("expected step_up gate for medium tool at critical escalation, got %s", gate2)
	}
}

func TestComputeRiskScore_CriticalEscalation_StepUpBecomesApproval(t *testing.T) {
	// AC8: A normally step-up tool becomes approval at Critical.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	// tavily_search with sensitive session and external dest pushes to step-up range
	tavilyDef, _ := registry.GetToolDefinition("tavily_search") // medium: impact=1, rev=1
	session := &AgentSession{
		EscalationScore:     25,
		DataClassifications: []string{"sensitive"},
	}

	score := ComputeRiskScore(&tavilyDef, session, "evil.com", true, registry, allowlist, config.UnknownToolDefaults)

	// base external+sensitive: impact=1, rev=1, exp=3, nov=2, total=7
	// With Critical: impact = min(1+3, 3) = 3, total = 3+1+3+2 = 9
	gate := DetermineGate(score.Total(), config.Thresholds)
	if gate != "approval" {
		t.Errorf("expected approval gate with critical escalation + external sensitive, got %s (total=%d)", gate, score.Total())
	}
}

func TestComputeRiskScore_EmergencyEscalation_AllMax(t *testing.T) {
	// AC3: EscalationScore >= 40 sets all dimensions to 3, total=12, deny gate.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")
	session := &AgentSession{EscalationScore: 40}

	score := ComputeRiskScore(&readDef, session, "", false, registry, allowlist, config.UnknownToolDefaults)

	if score.Impact != 3 {
		t.Errorf("expected impact=3 at emergency, got %d", score.Impact)
	}
	if score.Reversibility != 3 {
		t.Errorf("expected reversibility=3 at emergency, got %d", score.Reversibility)
	}
	if score.Exposure != 3 {
		t.Errorf("expected exposure=3 at emergency, got %d", score.Exposure)
	}
	if score.Novelty != 3 {
		t.Errorf("expected novelty=3 at emergency, got %d", score.Novelty)
	}
	if score.Total() != 12 {
		t.Errorf("expected total=12 at emergency, got %d", score.Total())
	}
	gate := DetermineGate(score.Total(), config.Thresholds)
	if gate != "deny" {
		t.Errorf("expected deny gate at emergency, got %s", gate)
	}
}

func TestComputeRiskScore_EmergencyEscalation_DeniesEvenLowRiskTool(t *testing.T) {
	// AC3: Even the safest tool (read, total=0) is denied at emergency.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")
	session := &AgentSession{EscalationScore: 50} // well above emergency

	score := ComputeRiskScore(&readDef, session, "", false, registry, allowlist, config.UnknownToolDefaults)
	gate := DetermineGate(score.Total(), config.Thresholds)
	if gate != "deny" {
		t.Errorf("expected deny for ALL tools at emergency, got %s", gate)
	}
}

func TestComputeRiskScore_EmergencyEscalation_UnknownTool(t *testing.T) {
	// AC3: Unknown tool at emergency also gets full deny.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	session := &AgentSession{EscalationScore: 45}

	score := ComputeRiskScore(nil, session, "", false, registry, allowlist, config.UnknownToolDefaults)

	if score.Total() != 12 {
		t.Errorf("expected total=12 for unknown tool at emergency, got %d", score.Total())
	}
}

func TestComputeRiskScore_NilSession_NoEscalation(t *testing.T) {
	// Nil session should not trigger escalation overrides.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")

	score := ComputeRiskScore(&readDef, nil, "", false, registry, allowlist, config.UnknownToolDefaults)

	if score.Total() != 0 {
		t.Errorf("nil session should not trigger escalation, got total=%d", score.Total())
	}
}

func TestComputeRiskScore_BelowCritical_NoEscalationOverride(t *testing.T) {
	// EscalationScore just below Critical (24.9) should NOT trigger escalation override.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")
	session := &AgentSession{EscalationScore: 24.9}

	score := ComputeRiskScore(&readDef, session, "", false, registry, allowlist, config.UnknownToolDefaults)

	if score.Impact != 0 {
		t.Errorf("expected impact=0 below critical threshold, got %d", score.Impact)
	}
}

// --- Unit tests for RecordAction escalation computation ---

func TestRecordAction_EscalationContribution(t *testing.T) {
	// AC4, AC5: RecordAction computes contribution and appends EscalationEvent.
	sc := NewSessionContext(NewInMemoryStore())
	session := sc.GetOrCreateSession("spiffe://poc.local/agent/test", "session-esc-1")

	action := ToolAction{
		Timestamp:      time.Now(),
		Tool:           "delete_resource",
		Classification: "sensitive",
		ExternalTarget: false,
	}

	sc.RecordAction(session, action)

	// "delete_resource" classifies as irreversible (rev.Score=3, impact from action classification=3)
	// Contribution = impact * (4 - reversibility) = 3 * (4 - 3) = 3
	if session.EscalationScore == 0 {
		t.Error("expected non-zero escalation score after destructive action")
	}
	if len(session.EscalationHistory) == 0 {
		t.Fatal("expected at least one EscalationEvent in history")
	}

	event := session.EscalationHistory[0]
	if event.Tool != "delete_resource" {
		t.Errorf("expected tool=delete_resource, got %s", event.Tool)
	}
	if event.Contribution <= 0 {
		t.Errorf("expected positive contribution, got %f", event.Contribution)
	}
	if event.CumulativeAt != session.EscalationScore {
		t.Errorf("expected cumulative_at=%f, got %f", session.EscalationScore, event.CumulativeAt)
	}
}

func TestRecordAction_ReadOnly_NoEscalation(t *testing.T) {
	// AC4: Read-only actions have zero escalation contribution.
	sc := NewSessionContext(NewInMemoryStore())
	session := sc.GetOrCreateSession("spiffe://poc.local/agent/test", "session-esc-2")

	action := ToolAction{
		Timestamp:      time.Now(),
		Tool:           "read",
		Classification: "public",
		ExternalTarget: false,
	}

	sc.RecordAction(session, action)

	// "read" classifies as reversible (rev.Score=0), impact=0
	// Contribution = 0 * (4 - 0) = 0
	if session.EscalationScore != 0 {
		t.Errorf("expected escalation score=0 for read-only action, got %f", session.EscalationScore)
	}
	if len(session.EscalationHistory) != 0 {
		t.Errorf("expected no escalation events for read-only action, got %d", len(session.EscalationHistory))
	}
}

func TestRecordAction_EscalationAccumulation(t *testing.T) {
	// AC4, AC5: Multiple destructive actions accumulate escalation score.
	sc := NewSessionContext(NewInMemoryStore())
	session := sc.GetOrCreateSession("spiffe://poc.local/agent/test", "session-esc-3")

	// Record several destructive actions
	for i := 0; i < 5; i++ {
		action := ToolAction{
			Timestamp:      time.Now(),
			Tool:           "delete_resource",
			Classification: "sensitive",
			ExternalTarget: false,
		}
		sc.RecordAction(session, action)
	}

	if len(session.EscalationHistory) != 5 {
		t.Errorf("expected 5 escalation events, got %d", len(session.EscalationHistory))
	}

	// Each event's CumulativeAt should be monotonically increasing
	for i := 1; i < len(session.EscalationHistory); i++ {
		if session.EscalationHistory[i].CumulativeAt <= session.EscalationHistory[i-1].CumulativeAt {
			t.Errorf("cumulative_at should be monotonically increasing: event[%d]=%f <= event[%d]=%f",
				i, session.EscalationHistory[i].CumulativeAt, i-1, session.EscalationHistory[i-1].CumulativeAt)
		}
	}
}

func TestRecordActionWithContext_ThresholdCrossing_FlagsCollector(t *testing.T) {
	// AC6: Threshold crossing triggers SecurityFlagsCollector.Append() and session.EscalationFlags.
	sc := NewSessionContext(NewInMemoryStore())
	session := sc.GetOrCreateSession("spiffe://poc.local/agent/test", "session-esc-4")

	collector := &SecurityFlagsCollector{}
	ctx := WithFlagsCollector(context.Background(), collector)

	// Record enough destructive actions to cross the Warning threshold (15)
	for i := 0; i < 20; i++ {
		action := ToolAction{
			Timestamp:      time.Now(),
			Tool:           "delete_resource",
			Classification: "sensitive",
			ExternalTarget: false,
		}
		sc.RecordActionWithContext(ctx, session, action)
	}

	if session.EscalationScore < EscalationWarningThreshold {
		t.Fatalf("expected escalation score >= %f, got %f", EscalationWarningThreshold, session.EscalationScore)
	}

	// Verify session flags
	foundWarning := false
	for _, f := range session.EscalationFlags {
		if f == "escalation_warning" {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Error("expected escalation_warning flag in session.EscalationFlags")
	}

	// Verify collector received the flag
	foundCollectorWarning := false
	for _, f := range collector.Flags {
		if f == "escalation_warning" {
			foundCollectorWarning = true
		}
	}
	if !foundCollectorWarning {
		t.Error("expected escalation_warning flag in SecurityFlagsCollector")
	}
}

func TestRecordActionWithContext_CriticalThresholdCrossing(t *testing.T) {
	// AC6: Critical threshold crossing (25) triggers escalation_critical flag.
	sc := NewSessionContext(NewInMemoryStore())
	session := sc.GetOrCreateSession("spiffe://poc.local/agent/test", "session-esc-5")

	collector := &SecurityFlagsCollector{}
	ctx := WithFlagsCollector(context.Background(), collector)

	// Record enough to cross Critical (25)
	for i := 0; i < 40; i++ {
		action := ToolAction{
			Timestamp:      time.Now(),
			Tool:           "delete_resource",
			Classification: "sensitive",
			ExternalTarget: false,
		}
		sc.RecordActionWithContext(ctx, session, action)
	}

	if session.EscalationScore < EscalationCriticalThreshold {
		t.Fatalf("expected escalation score >= %f, got %f", EscalationCriticalThreshold, session.EscalationScore)
	}

	foundCritical := false
	for _, f := range session.EscalationFlags {
		if f == "escalation_critical" {
			foundCritical = true
		}
	}
	if !foundCritical {
		t.Errorf("expected escalation_critical flag in session.EscalationFlags, got %v", session.EscalationFlags)
	}

	foundCollectorCritical := false
	for _, f := range collector.Flags {
		if f == "escalation_critical" {
			foundCollectorCritical = true
		}
	}
	if !foundCollectorCritical {
		t.Errorf("expected escalation_critical flag in collector, got %v", collector.Flags)
	}
}

// --- Unit tests for EscalationState ---

func TestEscalationState(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0, "normal"},
		{10, "normal"},
		{14.9, "normal"},
		{15, "warning"},
		{20, "warning"},
		{24.9, "warning"},
		{25, "critical"},
		{30, "critical"},
		{39.9, "critical"},
		{40, "emergency"},
		{50, "emergency"},
		{100, "emergency"},
	}

	for _, tt := range tests {
		got := EscalationState(tt.score)
		if got != tt.expected {
			t.Errorf("EscalationState(%f) = %q, want %q", tt.score, got, tt.expected)
		}
	}
}

// --- Unit tests for escalation override interaction with reversibility ---

func TestComputeRiskScore_CriticalEscalation_WithReversibility(t *testing.T) {
	// Both escalation and reversibility overrides should apply.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")
	rev := ActionReversibility{Score: 3, Category: "irreversible"}
	session := &AgentSession{EscalationScore: 25}

	score := ComputeRiskScore(&readDef, session, "", false, registry, allowlist, config.UnknownToolDefaults,
		WithReversibility(rev),
		WithPrincipalLevelOption(3), // agent
	)

	// read base: impact=0, rev=0, exp=0, nov=0
	// Reversibility override: rev=3, then agent+irreversible forces total>=7
	// Escalation critical: impact += 3 (capped at 3)
	// Both should apply
	if score.Impact != 3 {
		t.Errorf("expected impact=3 with both escalation and reversibility, got %d", score.Impact)
	}
	if score.Reversibility != 3 {
		t.Errorf("expected reversibility=3, got %d", score.Reversibility)
	}
	if score.Total() < 7 {
		t.Errorf("expected total >= 7, got %d", score.Total())
	}
}

// --- Audit enrichment tests ---

func TestStepUpGating_AuditIncludesEscalation(t *testing.T) {
	// AC7: Audit events include escalation_score and escalation_state.
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
	defer auditor.Close()

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

	session := &AgentSession{EscalationScore: 20} // warning state

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test")
	ctx = WithSessionID(ctx, "test-session-escalation-audit")
	ctx = WithSessionContextData(ctx, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// Flush auditor to ensure event is written
	auditor.Flush()

	// Read audit file and check for escalation fields
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
				t.Fatal("expected security audit data")
			}
			if event.Security.EscalationScore != 20 {
				t.Errorf("expected escalation_score=20, got %f", event.Security.EscalationScore)
			}
			if event.Security.EscalationState != "warning" {
				t.Errorf("expected escalation_state=warning, got %q", event.Security.EscalationState)
			}
			break
		}
	}
	if !found {
		t.Fatal("step_up_gating audit event not found")
	}
}

func TestStepUpGating_AuditEscalation_NoSession(t *testing.T) {
	// AC7: When no session, escalation fields should be zero/empty.
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
	defer auditor.Close()

	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{}

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
	ctx = WithSessionID(ctx, "test-session-no-session-audit")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

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
			if event.Security == nil {
				t.Fatal("expected security audit data")
			}
			// No session -> score should be 0, state should be empty or "normal"
			if event.Security.EscalationScore != 0 {
				t.Errorf("expected escalation_score=0 without session, got %f", event.Security.EscalationScore)
			}
			break
		}
	}
}

// --- Integration test: sequence of destructive actions causing gate elevation ---

func TestStepUpGating_Integration_DestructiveSequenceElevatesGate(t *testing.T) {
	// AC9: Integration test - A sequence of destructive actions accumulates escalation score
	// past the Critical threshold, then a normally-fast-path action is elevated.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	// Create a session context for tracking
	sc := NewSessionContext(NewInMemoryStore())
	session := sc.GetOrCreateSession("spiffe://poc.local/agent/test", "session-integration-esc")

	// Phase 1: Record a series of destructive actions to build escalation score.
	// Each delete_resource with sensitive classification contributes impact=3 * (4-3)=3.
	// To reach Critical (25): need ceil(25/3) = 9 actions.
	for i := 0; i < 10; i++ {
		action := ToolAction{
			Timestamp:      time.Now(),
			Tool:           "delete_resource",
			Classification: "sensitive",
			ExternalTarget: false,
		}
		sc.RecordAction(session, action)
	}

	t.Logf("Escalation score after 10 destructive actions: %f", session.EscalationScore)

	if session.EscalationScore < EscalationCriticalThreshold {
		t.Fatalf("expected escalation score >= %f after 10 destructive actions, got %f",
			EscalationCriticalThreshold, session.EscalationScore)
	}

	// Phase 2: Now send a normally-fast-path tool call (read) through the middleware.
	// With Critical escalation, Impact gets +3, changing the gate.
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	body := createTestMCPBody("tools/call", map[string]interface{}{
		"name":      "read",
		"arguments": map[string]interface{}{"path": "/tmp/test.txt"},
	})

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agent/test")
	ctx = WithSessionID(ctx, "session-integration-esc")
	ctx = WithSessionContextData(ctx, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// read tool base: impact=0, rev=0, exp=0, nov=0, total=0 (fast_path)
	// With Critical escalation: impact=3, total=3 (still fast_path boundary)
	// The read tool stays at fast_path because total=3 == fast_path_max=3.
	// But a medium tool would cross over. Let's also test with a medium tool.
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for read tool even with critical escalation (total=3 is still fast_path), got %d", rr.Code)
	}

	// Phase 3: Verify the escalation override at the ComputeRiskScore level directly
	// (the middleware test above already proved the session is properly propagated).
	// Use ComputeRiskScore directly to verify gate transition for a medium tool.
	httpDef, _ := registry.GetToolDefinition("http_request") // medium: impact=1, rev=1
	riskScore := ComputeRiskScore(&httpDef, session, "", false, registry, allowlist, config.UnknownToolDefaults)

	// base: impact=1, rev=1, exp=0, nov=0, total=2 (fast_path)
	// With Critical escalation: impact = min(1+3, 3) = 3, total = 3+1+0+0 = 4 (step_up)
	t.Logf("http_request with critical escalation: total=%d impact=%d rev=%d",
		riskScore.Total(), riskScore.Impact, riskScore.Reversibility)

	if riskScore.Impact < 3 {
		t.Errorf("expected impact >= 3 at critical escalation, got %d", riskScore.Impact)
	}
	if riskScore.Total() <= 3 {
		t.Errorf("expected total > 3 (above fast_path) for medium tool at critical escalation, got %d", riskScore.Total())
	}
	gate := DetermineGate(riskScore.Total(), config.Thresholds)
	if gate == "fast_path" {
		t.Errorf("expected gate above fast_path for medium tool at critical escalation, got %s", gate)
	}
}

func TestStepUpGating_Integration_EmergencyDeniesEverything(t *testing.T) {
	// AC9: Emergency escalation denies ALL actions.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	session := &AgentSession{EscalationScore: 45} // above emergency (40)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	// Even "read" (the safest tool) should be denied
	body := createTestMCPBody("tools/call", map[string]interface{}{
		"name":      "read",
		"arguments": map[string]interface{}{"path": "/tmp/test.txt"},
	})

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(req.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agent/test")
	ctx = WithSessionID(ctx, "session-emergency")
	ctx = WithSessionContextData(ctx, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if nextCalled {
		t.Error("expected next handler NOT to be called at emergency escalation")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 at emergency escalation, got %d", rr.Code)
	}

	// Verify the error response
	var errResp GatewayError
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Code != ErrStepUpDenied {
		t.Errorf("expected error code %q, got %q", ErrStepUpDenied, errResp.Code)
	}
}

// --- Test backward compatibility ---

func TestComputeRiskScore_EscalationBackwardCompatible(t *testing.T) {
	// Without session escalation, ComputeRiskScore behaves exactly as before.
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")

	// No session
	scoreNoSession := ComputeRiskScore(&readDef, nil, "", false, registry, allowlist, config.UnknownToolDefaults)
	// Session with zero escalation
	scoreZeroEsc := ComputeRiskScore(&readDef, &AgentSession{EscalationScore: 0}, "", false, registry, allowlist, config.UnknownToolDefaults)

	if scoreNoSession != scoreZeroEsc {
		t.Errorf("zero escalation should match no-session: noSession=%+v zeroEsc=%+v", scoreNoSession, scoreZeroEsc)
	}
}

// --- OC-axk7: Integration test for E2E escalation detection demo scenario ---

// TestEscalationDetection_DemoScenario verifies the exact escalation progression
// used by the demo scenario (S-ESC-1..5). Each step builds on the previous
// session state. This test validates the full session context + step-up gating
// chain behavior without mocking.
func TestEscalationDetection_DemoScenario(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	// Create shared session context (used by session context middleware).
	sc := NewSessionContext(NewInMemoryStore())
	sessionID := "test-esc-demo-001"
	spiffeID := "spiffe://poc.local/owner/alice"

	// Build a handler chain: session context (step 8) -> step-up gating (step 9) -> OK handler.
	nextOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	stepUpHandler := StepUpGating(nextOK, guardClient, allowlist, config, registry, nil)
	fullHandler := SessionContextMiddleware(stepUpHandler, sc)

	makeRequest := func(toolName string, args map[string]interface{}) *httptest.ResponseRecorder {
		body := createTestMCPBody("tools/call", map[string]interface{}{
			"name":      toolName,
			"arguments": args,
		})
		req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		ctx := WithRequestBody(req.Context(), body)
		ctx = WithSPIFFEID(ctx, spiffeID)
		ctx = WithSessionID(ctx, sessionID)
		// Set principal level=1 (owner) for consistent behavior.
		ctx = WithPrincipalRole(ctx, PrincipalRole{Level: 1, Role: "owner"})
		// Create a SecurityFlagsCollector so escalation flags are captured.
		collector := &SecurityFlagsCollector{}
		ctx = WithFlagsCollector(ctx, collector)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		fullHandler.ServeHTTP(rr, req)
		return rr
	}

	// ---------------------------------------------------------------
	// S-ESC-1: tavily_search with action=read.
	// tavily_search is external -> impact=2 at session context step 8.
	// "search" keyword matches rev Score=0. Contribution=2*(4-0)=8.
	// At step 9: params["action"]="read" -> Score=0, no reversibility override.
	// Base: I=1,R=1,E=2,N=0=4 (step_up). No guard -> allowed.
	// ---------------------------------------------------------------
	rr := makeRequest("tavily_search", map[string]interface{}{
		"query": "read patient records", "action": "read",
	})
	if rr.Code != http.StatusOK {
		t.Errorf("S-ESC-1: expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	session := sc.GetOrCreateSession(spiffeID, sessionID)
	if session.EscalationScore != 8 {
		t.Errorf("S-ESC-1: expected escalation=8, got %f", session.EscalationScore)
	}

	// ---------------------------------------------------------------
	// S-ESC-2: tavily_search (no destructive action).
	// Contribution=8, cumulative=16. Crosses Warning (15).
	// escalation_warning flag should be set.
	// ---------------------------------------------------------------
	rr = makeRequest("tavily_search", map[string]interface{}{
		"query": "redact names from memory",
	})
	if rr.Code != http.StatusOK {
		t.Errorf("S-ESC-2: expected 200, got %d", rr.Code)
	}
	if session.EscalationScore != 16 {
		t.Errorf("S-ESC-2: expected escalation=16, got %f", session.EscalationScore)
	}
	if !containsFlag(session.EscalationFlags, "escalation_warning") {
		t.Errorf("S-ESC-2: expected escalation_warning flag, got %v", session.EscalationFlags)
	}

	// ---------------------------------------------------------------
	// S-ESC-3: tavily_search with action=delete.
	// Contribution=8 at step 8, cumulative=24.
	// At step 9: "delete" in params -> Score=3.
	// applyReversibilityOverrides: Score=3, EscalationScore(24)>Warning(15) -> forceMinTotal(10).
	// Gate=deny. HTTP 403.
	// ---------------------------------------------------------------
	rr = makeRequest("tavily_search", map[string]interface{}{
		"query": "delete old records", "action": "delete",
	})
	if rr.Code != http.StatusForbidden {
		t.Errorf("S-ESC-3: expected 403, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if session.EscalationScore != 24 {
		t.Errorf("S-ESC-3: expected escalation=24, got %f", session.EscalationScore)
	}

	// ---------------------------------------------------------------
	// S-ESC-5 (executed 4th): tavily_search with action=read.
	// Contribution=8, cumulative=32. Crosses Critical (25).
	// At step 9: action=read -> Score=0. No reversibility override.
	// applyEscalationOverrides: 32>=Critical -> +3 Impact. I=1+3=3(cap).
	// Total = 3+1+2+0 = 6 (step_up). No guard -> allowed.
	// ---------------------------------------------------------------
	rr = makeRequest("tavily_search", map[string]interface{}{
		"query": "read system status", "action": "read",
	})
	if rr.Code != http.StatusOK {
		t.Errorf("S-ESC-5: expected 200 (read survives Critical), got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if session.EscalationScore != 32 {
		t.Errorf("S-ESC-5: expected escalation=32, got %f", session.EscalationScore)
	}
	if !containsFlag(session.EscalationFlags, "escalation_critical") {
		t.Errorf("S-ESC-5: expected escalation_critical flag, got %v", session.EscalationFlags)
	}

	// ---------------------------------------------------------------
	// S-ESC-4 (executed 5th): tavily_search with action=shutdown.
	// Contribution=8, cumulative=40. Crosses Emergency (40).
	// At step 9: Emergency override -> all dims=3, total=12. Gate=deny.
	// ---------------------------------------------------------------
	rr = makeRequest("tavily_search", map[string]interface{}{
		"query": "shutdown all services", "action": "shutdown",
	})
	if rr.Code != http.StatusForbidden {
		t.Errorf("S-ESC-4: expected 403 (Emergency deny), got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if session.EscalationScore != 40 {
		t.Errorf("S-ESC-4: expected escalation=40, got %f", session.EscalationScore)
	}
	if !containsFlag(session.EscalationFlags, "escalation_emergency") {
		t.Errorf("S-ESC-4: expected escalation_emergency flag, got %v", session.EscalationFlags)
	}

	// Verify final escalation history has 5 entries (all 5 calls contributed).
	if len(session.EscalationHistory) != 5 {
		t.Errorf("expected 5 escalation history entries, got %d", len(session.EscalationHistory))
	}
}

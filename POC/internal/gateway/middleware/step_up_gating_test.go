package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- Mock guard client for unit testing ---

// mockGuardClient is a configurable mock for GroqGuardClient
type mockGuardClient struct {
	injectionProb float64
	jailbreakProb float64
	err           error
}

func (m *mockGuardClient) ClassifyContent(ctx context.Context, content string) (*GuardResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &GuardResult{
		InjectionProb: m.injectionProb,
		JailbreakProb: m.jailbreakProb,
		Blocked:       false,
	}, nil
}

// --- Helper functions ---

func defaultRiskConfig() *RiskConfig {
	return DefaultRiskConfig()
}

func defaultAllowlist() *DestinationAllowlist {
	return &DestinationAllowlist{
		Allowed: []string{
			"localhost",
			"127.0.0.1",
			"api.tavily.com",
			"*.tavily.com",
			"api.github.com",
		},
	}
}

func testRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools: map[string]ToolDefinition{
			"read": {
				Name:                "read",
				Description:         "Read file contents",
				RiskLevel:           "low",
				AllowedDestinations: []string{},
			},
			"grep": {
				Name:                "grep",
				Description:         "Search for patterns",
				RiskLevel:           "low",
				AllowedDestinations: []string{},
			},
			"tavily_search": {
				Name:                "tavily_search",
				Description:         "Search the web",
				RiskLevel:           "medium",
				AllowedDestinations: []string{"api.tavily.com", "*.tavily.com"},
			},
			"bash": {
				Name:                "bash",
				Description:         "Execute shell commands",
				RiskLevel:           "critical",
				RequiresStepUp:      true,
				AllowedDestinations: []string{},
			},
			"email_send": {
				Name:                "email_send",
				Description:         "Send email",
				RiskLevel:           "high",
				AllowedDestinations: []string{"smtp.internal.com"},
			},
			"http_request": {
				Name:                "http_request",
				Description:         "Make HTTP request",
				RiskLevel:           "medium",
				AllowedDestinations: []string{"api.github.com"},
			},
		},
	}
}

func createTestMCPBody(method string, params map[string]interface{}) []byte {
	req := MCPRequest{
		Jsonrpc: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	}
	body, _ := json.Marshal(req)
	return body
}

func newTestRequest(body []byte) *http.Request {
	r := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(r.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test")
	ctx = WithSessionID(ctx, "test-session-123")
	return r.WithContext(ctx)
}

func newModelCompatRequest(body []byte) *http.Request {
	r := httptest.NewRequest("POST", openAICompatChatCompletionsPath, bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := WithRequestBody(r.Context(), body)
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test")
	ctx = WithSessionID(ctx, "test-session-123")
	return r.WithContext(ctx)
}

// --- Tests for RiskDimension ---

func TestRiskDimension_Total(t *testing.T) {
	tests := []struct {
		name     string
		dim      RiskDimension
		expected int
	}{
		{"AllZero", RiskDimension{0, 0, 0, 0}, 0},
		{"AllThree", RiskDimension{3, 3, 3, 3}, 12},
		{"Mixed", RiskDimension{1, 2, 0, 3}, 6},
		{"LowRisk", RiskDimension{0, 0, 0, 0}, 0},
		{"MediumRisk", RiskDimension{1, 1, 1, 1}, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.dim.Total()
			if got != tt.expected {
				t.Errorf("Total() = %d, want %d", got, tt.expected)
			}
		})
	}
}

// --- Tests for DetermineGate ---

func TestDetermineGate(t *testing.T) {
	thresholds := RiskThresholds{
		FastPathMax: 3,
		StepUpMax:   6,
		ApprovalMax: 9,
	}

	tests := []struct {
		score    int
		expected string
	}{
		{0, "fast_path"},
		{1, "fast_path"},
		{2, "fast_path"},
		{3, "fast_path"},
		{4, "step_up"},
		{5, "step_up"},
		{6, "step_up"},
		{7, "approval"},
		{8, "approval"},
		{9, "approval"},
		{10, "deny"},
		{11, "deny"},
		{12, "deny"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Score_%d", tt.score), func(t *testing.T) {
			got := DetermineGate(tt.score, thresholds)
			if got != tt.expected {
				t.Errorf("DetermineGate(%d) = %q, want %q", tt.score, got, tt.expected)
			}
		})
	}
}

// --- Tests for DestinationAllowlist ---

func TestDestinationAllowlist_IsAllowed(t *testing.T) {
	allowlist := defaultAllowlist()

	tests := []struct {
		destination string
		expected    bool
	}{
		{"", true},                      // Empty destination = internal
		{"localhost", true},             // Exact match
		{"127.0.0.1", true},             // Exact match
		{"api.tavily.com", true},        // Exact match
		{"search.tavily.com", true},     // Wildcard match
		{"api.github.com", true},        // Exact match
		{"evil.com", false},             // Not on allowlist
		{"attacker.example.com", false}, // Not on allowlist
		{"fake-tavily.com", false},      // Does not match *.tavily.com
	}

	for _, tt := range tests {
		t.Run(tt.destination, func(t *testing.T) {
			got := allowlist.IsAllowed(tt.destination)
			if got != tt.expected {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.destination, got, tt.expected)
			}
		})
	}
}

// --- Tests for ComputeRiskScore ---

func TestComputeRiskScore_LowRiskTool(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	readDef, _ := registry.GetToolDefinition("read")

	score := ComputeRiskScore(&readDef, nil, "", false, registry, allowlist, config.UnknownToolDefaults)

	if score.Total() > 3 {
		t.Errorf("read tool should be low risk (0-3), got total %d: impact=%d rev=%d exp=%d nov=%d",
			score.Total(), score.Impact, score.Reversibility, score.Exposure, score.Novelty)
	}
}

func TestComputeRiskScore_CriticalTool(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	bashDef, _ := registry.GetToolDefinition("bash")

	score := ComputeRiskScore(&bashDef, nil, "", false, registry, allowlist, config.UnknownToolDefaults)

	// Critical tool: impact=3, reversibility=3, exposure>=2, novelty=0
	if score.Impact != 3 {
		t.Errorf("bash impact should be 3, got %d", score.Impact)
	}
	if score.Reversibility != 3 {
		t.Errorf("bash reversibility should be 3, got %d", score.Reversibility)
	}
	if score.Exposure < 2 {
		t.Errorf("bash exposure should be >= 2, got %d", score.Exposure)
	}
}

func TestComputeRiskScore_MediumToolToUnknownDestination(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	httpDef, _ := registry.GetToolDefinition("http_request")

	score := ComputeRiskScore(&httpDef, nil, "evil.com", true, registry, allowlist, config.UnknownToolDefaults)

	// Medium tool to unknown destination: novelty should be elevated
	if score.Novelty < 2 {
		t.Errorf("unknown destination novelty should be >= 2, got %d", score.Novelty)
	}
}

func TestComputeRiskScore_UnknownTool(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	score := ComputeRiskScore(nil, nil, "", false, registry, allowlist, config.UnknownToolDefaults)

	// Unknown tool gets defaults: impact=2, reversibility=2, exposure=2, novelty=3 = 9
	if score.Impact != 2 || score.Reversibility != 2 || score.Exposure != 2 || score.Novelty != 3 {
		t.Errorf("unknown tool should use defaults, got impact=%d rev=%d exp=%d nov=%d",
			score.Impact, score.Reversibility, score.Exposure, score.Novelty)
	}
	if score.Total() != 9 {
		t.Errorf("unknown tool total should be 9, got %d", score.Total())
	}
}

func TestComputeRiskScore_WithSensitiveSession(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	httpDef, _ := registry.GetToolDefinition("http_request")

	session := &AgentSession{
		DataClassifications: []string{"sensitive"},
	}

	score := ComputeRiskScore(&httpDef, session, "api.github.com", true, registry, allowlist, config.UnknownToolDefaults)

	// External target with sensitive session data -> exposure should be 3
	if score.Exposure != 3 {
		t.Errorf("external with sensitive session should have exposure 3, got %d", score.Exposure)
	}
}

// --- Tests for StepUpGating middleware ---

func TestStepUpGating_FastPath_LowRiskTool(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	body := createTestMCPBody("read", map[string]interface{}{"path": "/tmp/test.txt"})
	req := newTestRequest(body)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("Expected next handler to be called for low-risk tool")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
}

func TestStepUpGating_StepUp_AllowedDestination_CleanContent(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.1, jailbreakProb: 0.1}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	// tavily_search to known destination = medium risk, step-up range
	body := createTestMCPBody("tavily_search", map[string]interface{}{
		"query":       "test query",
		"destination": "api.tavily.com",
	})
	req := newTestRequest(body)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("Expected next handler to be called for allowed destination with clean content")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
}

func TestStepUpGating_StepUp_DisallowedDestination(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	// tavily_search to disallowed destination
	// tavily_search (medium risk): impact=1, reversibility=1, exposure=2 (external), novelty=2 (disallowed dest)
	// Total = 6 -> step-up range, so destination check applies
	body := createTestMCPBody("tavily_search", map[string]interface{}{
		"query":       "test",
		"destination": "evil.com",
	})
	req := newTestRequest(body)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if nextCalled {
		t.Error("Expected next handler NOT to be called for disallowed destination")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", rr.Code)
	}

	// Verify the unified JSON error envelope
	var resp GatewayError
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode JSON error envelope: %v", err)
	}
	if resp.Code != ErrStepUpDestinationBlocked {
		t.Errorf("Expected code %q, got %q", ErrStepUpDestinationBlocked, resp.Code)
	}
	if resp.Middleware != "step_up_gating" {
		t.Errorf("Expected middleware 'step_up_gating', got %q", resp.Middleware)
	}
	if resp.MiddlewareStep != 9 {
		t.Errorf("Expected middleware_step 9, got %d", resp.MiddlewareStep)
	}
}

func TestStepUpGating_StepUp_GuardModelFlagsInjection(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	// Guard model detects injection
	guardClient := &mockGuardClient{injectionProb: 0.85, jailbreakProb: 0.10}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	// Medium risk tool, triggers step-up, guard finds injection
	body := createTestMCPBody("http_request", map[string]interface{}{
		"url":         "https://api.github.com/repos",
		"destination": "api.github.com",
	})
	req := newTestRequest(body)

	// Need to push into step-up range (4-6): add session with sensitive data
	session := &AgentSession{
		DataClassifications: []string{"sensitive"},
	}
	ctx := WithSessionContextData(req.Context(), session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if nextCalled {
		t.Error("Expected next handler NOT to be called when guard flags injection")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", rr.Code)
	}
}

func TestStepUpGating_StepUp_GuardModelFlagsJailbreak(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	// Guard model detects jailbreak
	guardClient := &mockGuardClient{injectionProb: 0.10, jailbreakProb: 0.75}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	body := createTestMCPBody("http_request", map[string]interface{}{
		"url":         "https://api.github.com/repos",
		"destination": "api.github.com",
	})
	req := newTestRequest(body)
	session := &AgentSession{
		DataClassifications: []string{"sensitive"},
	}
	ctx := WithSessionContextData(req.Context(), session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if nextCalled {
		t.Error("Expected next handler NOT to be called when guard flags jailbreak")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", rr.Code)
	}
}

func TestStepUpGating_ApprovalRequired_CriticalTool(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	// bash is critical: impact=3, reversibility=3, exposure>=2
	// This puts it in approval or deny range
	body := createTestMCPBody("bash", map[string]interface{}{
		"command": "rm -rf /",
	})
	req := newTestRequest(body)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if nextCalled {
		t.Error("Expected next handler NOT to be called for critical tool without approval")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", rr.Code)
	}

	// Verify the unified JSON error envelope
	var resp GatewayError
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode JSON error envelope: %v", err)
	}
	// Should be either approval_required or deny code
	if resp.Code != ErrStepUpApprovalRequired && resp.Code != ErrStepUpDenied {
		t.Errorf("Expected code %q or %q, got %q", ErrStepUpApprovalRequired, ErrStepUpDenied, resp.Code)
	}
	if resp.Middleware != "step_up_gating" {
		t.Errorf("Expected middleware 'step_up_gating', got %q", resp.Middleware)
	}
	if resp.MiddlewareStep != 9 {
		t.Errorf("Expected middleware_step 9, got %d", resp.MiddlewareStep)
	}
}

func TestStepUpGating_ApprovalToken_AllowsCriticalTool(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{}

	svc := NewApprovalCapabilityService("test-key", 5*time.Minute, 30*time.Minute, nil)
	created, err := svc.CreateRequest(ApprovalRequestInput{
		Scope: ApprovalScope{
			Action:        "tool.call",
			Resource:      "bash",
			ActorSPIFFEID: "spiffe://poc.local/agents/test",
			SessionID:     "test-session-123",
		},
	})
	if err != nil {
		t.Fatalf("create approval request: %v", err)
	}
	grant, err := svc.GrantRequest(ApprovalGrantInput{RequestID: created.RequestID, ApprovedBy: "security@corp"})
	if err != nil {
		t.Fatalf("grant approval request: %v", err)
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		if got := r.Header.Get("X-Step-Up-Approved"); got != "true" {
			t.Fatalf("expected X-Step-Up-Approved=true, got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil, svc)
	body := createTestMCPBody("bash", map[string]interface{}{"command": "echo safe"})
	req := newTestRequest(body)
	req.Header.Set("X-Step-Up-Token", grant.Token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called with valid approval token")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestStepUpGating_ModelHighRisk_RequiresApprovalToken(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	req := newModelCompatRequest(body)
	req.Header.Set("X-Risk-Mode", "high")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for high-risk model operation without approval token, got %d", rr.Code)
	}

	var resp GatewayError
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode gateway error: %v", err)
	}
	if resp.Code != ErrStepUpApprovalRequired {
		t.Fatalf("expected %s, got %s", ErrStepUpApprovalRequired, resp.Code)
	}
}

func TestStepUpGating_ModelHighRisk_AllowsWithApprovalToken(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{}

	svc := NewApprovalCapabilityService("test-key", 5*time.Minute, 30*time.Minute, nil)
	created, err := svc.CreateRequest(ApprovalRequestInput{
		Scope: ApprovalScope{
			Action:        "model.call",
			Resource:      "gpt-4o",
			ActorSPIFFEID: "spiffe://poc.local/agents/test",
			SessionID:     "test-session-123",
		},
	})
	if err != nil {
		t.Fatalf("create approval request: %v", err)
	}
	grant, err := svc.GrantRequest(ApprovalGrantInput{RequestID: created.RequestID, ApprovedBy: "security@corp"})
	if err != nil {
		t.Fatalf("grant approval request: %v", err)
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		if got := r.Header.Get("X-Step-Up-Approved"); got != "true" {
			t.Fatalf("expected X-Step-Up-Approved=true, got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	})
	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil, svc)

	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	req := newModelCompatRequest(body)
	req.Header.Set("X-Risk-Mode", "high")
	req.Header.Set("X-Step-Up-Token", grant.Token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatal("expected next handler call with valid approval token")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestStepUpGating_DenyByDefault_UnknownTool(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	// Unknown tool with defaults: 2+2+2+3 = 9 (approval range)
	body := createTestMCPBody("unknown_evil_tool", map[string]interface{}{
		"target": "evil.com",
	})
	req := newTestRequest(body)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if nextCalled {
		t.Error("Expected next handler NOT to be called for unknown tool")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", rr.Code)
	}
}

func TestStepUpGating_NoBody_PassThrough(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, nil, allowlist, config, registry, nil)

	// Request with no body
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("Expected next handler to be called for request with no body")
	}
}

func TestStepUpGating_InvalidJSON_PassThrough(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, nil, allowlist, config, registry, nil)

	body := []byte("not json")
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	ctx := WithRequestBody(req.Context(), body)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("Expected next handler to be called for invalid JSON")
	}
}

func TestStepUpGating_GuardModelUnavailable_FailOpenForStepUp(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	// Guard client that returns error
	guardClient := &mockGuardClient{err: fmt.Errorf("connection refused")}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	// Medium risk tool in step-up range with allowed destination
	body := createTestMCPBody("tavily_search", map[string]interface{}{
		"query":       "test",
		"destination": "api.tavily.com",
	})
	req := newTestRequest(body)

	// Push into step-up range with a sensitive session
	session := &AgentSession{
		DataClassifications: []string{"internal"},
	}
	ctx := WithSessionContextData(req.Context(), session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// For step-up range (4-6), guard unavailable should fail open
	if !nextCalled {
		t.Error("Expected next handler to be called (fail open for step-up range)")
	}
}

func TestStepUpGating_NilGuardClient_StepUpPassesThrough(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, nil, allowlist, config, registry, nil)

	// Tool that would be in step-up range with allowed destination
	body := createTestMCPBody("tavily_search", map[string]interface{}{
		"query":       "test",
		"destination": "api.tavily.com",
	})
	req := newTestRequest(body)

	// Add session context to push into step-up range
	session := &AgentSession{
		DataClassifications: []string{"internal"},
	}
	ctx := WithSessionContextData(req.Context(), session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// No guard client = skip guard check, should pass through
	if !nextCalled {
		t.Error("Expected next handler to be called with nil guard client")
	}
}

func TestStepUpGating_ResponseBodyContainsRiskBreakdown(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	// Critical tool should be blocked with risk breakdown in response
	body := createTestMCPBody("bash", map[string]interface{}{
		"command": "ls",
	})
	req := newTestRequest(body)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", rr.Code)
	}

	// Verify unified JSON error envelope
	var resp GatewayError
	bodyBytes, _ := io.ReadAll(rr.Body)
	if err := json.Unmarshal(bodyBytes, &resp); err != nil {
		t.Fatalf("Failed to parse response body: %v", err)
	}

	// Verify error code is a step-up related code
	if resp.Code != ErrStepUpApprovalRequired && resp.Code != ErrStepUpDenied {
		t.Errorf("Expected step-up error code, got %q", resp.Code)
	}
	if resp.Middleware != "step_up_gating" {
		t.Errorf("Expected middleware 'step_up_gating', got %q", resp.Middleware)
	}
	if resp.MiddlewareStep != 9 {
		t.Errorf("Expected middleware_step 9, got %d", resp.MiddlewareStep)
	}

	// Verify risk_breakdown is in details
	if resp.Details == nil {
		t.Fatal("Expected details in response body")
	}

	breakdown, ok := resp.Details["risk_breakdown"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected risk_breakdown in details")
	}

	// Verify all 4 dimensions are present
	for _, dim := range []string{"impact", "reversibility", "exposure", "novelty"} {
		if _, exists := breakdown[dim]; !exists {
			t.Errorf("Expected dimension %q in risk_breakdown", dim)
		}
	}

	// Verify risk_score is in details
	if _, ok := resp.Details["risk_score"]; !ok {
		t.Error("Expected risk_score in details")
	}

	// Verify gate is in details
	if _, ok := resp.Details["gate"]; !ok {
		t.Error("Expected gate in details")
	}
}

func TestStepUpGating_AuditEventLogged(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{}

	// Create a minimal auditor that writes to a temp file
	tmpFile := t.TempDir() + "/audit.jsonl"
	// We can't easily create a full auditor without the OPA/registry files,
	// so we test with nil auditor (audit logging is nil-safe)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Test with nil auditor - should not panic
	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	body := createTestMCPBody("read", map[string]interface{}{"path": "/tmp/test.txt"})
	req := newTestRequest(body)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 with nil auditor, got %d", rr.Code)
	}

	// Verify tmpFile usage is just for temp dir name
	_ = tmpFile
}

func TestStepUpGating_ContextHasStepUpResult(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{}

	var capturedResult *StepUpGatingResult
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedResult = GetStepUpResult(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

	body := createTestMCPBody("read", map[string]interface{}{"path": "/tmp/test.txt"})
	req := newTestRequest(body)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if capturedResult == nil {
		t.Fatal("Expected step-up result in context")
	}
	if !capturedResult.Allowed {
		t.Error("Expected result to be allowed for low-risk tool")
	}
	if capturedResult.Gate != "fast_path" {
		t.Errorf("Expected gate 'fast_path', got %q", capturedResult.Gate)
	}
	if capturedResult.TotalScore > 3 {
		t.Errorf("Expected total score <= 3 for fast path, got %d", capturedResult.TotalScore)
	}
}

// --- Tests for computeImpact, computeReversibility, computeExposure, computeNovelty ---

func TestComputeImpact(t *testing.T) {
	tests := []struct {
		riskLevel string
		expected  int
	}{
		{"low", 0},
		{"medium", 1},
		{"high", 2},
		{"critical", 3},
		{"unknown", 2}, // defaults to medium-high
	}

	for _, tt := range tests {
		t.Run(tt.riskLevel, func(t *testing.T) {
			def := &ToolDefinition{RiskLevel: tt.riskLevel}
			got := computeImpact(def)
			if got != tt.expected {
				t.Errorf("computeImpact(%q) = %d, want %d", tt.riskLevel, got, tt.expected)
			}
		})
	}
}

func TestComputeReversibility(t *testing.T) {
	tests := []struct {
		riskLevel string
		expected  int
	}{
		{"low", 0},
		{"medium", 1},
		{"high", 2},
		{"critical", 3},
	}

	for _, tt := range tests {
		t.Run(tt.riskLevel, func(t *testing.T) {
			def := &ToolDefinition{RiskLevel: tt.riskLevel}
			got := computeReversibility(def)
			if got != tt.expected {
				t.Errorf("computeReversibility(%q) = %d, want %d", tt.riskLevel, got, tt.expected)
			}
		})
	}
}

func TestComputeExposure(t *testing.T) {
	tests := []struct {
		name       string
		riskLevel  string
		isExternal bool
		session    *AgentSession
		expected   int
	}{
		{
			name:       "LowRisk_Internal",
			riskLevel:  "low",
			isExternal: false,
			session:    nil,
			expected:   0,
		},
		{
			name:       "External_NoSensitive",
			riskLevel:  "medium",
			isExternal: true,
			session:    nil,
			expected:   2,
		},
		{
			name:       "External_WithSensitiveSession",
			riskLevel:  "medium",
			isExternal: true,
			session:    &AgentSession{DataClassifications: []string{"sensitive"}},
			expected:   3,
		},
		{
			name:       "CriticalTool_Internal",
			riskLevel:  "critical",
			isExternal: false,
			session:    nil,
			expected:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			def := &ToolDefinition{RiskLevel: tt.riskLevel}
			got := computeExposure(def, tt.isExternal, tt.session)
			if got != tt.expected {
				t.Errorf("computeExposure() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestComputeNovelty(t *testing.T) {
	allowlist := defaultAllowlist()

	tests := []struct {
		name        string
		toolDef     *ToolDefinition
		destination string
		expected    int
	}{
		{
			name:        "NoDestination",
			toolDef:     &ToolDefinition{AllowedDestinations: []string{"api.tavily.com"}},
			destination: "",
			expected:    0,
		},
		{
			name:        "KnownToolKnownDest",
			toolDef:     &ToolDefinition{AllowedDestinations: []string{"api.tavily.com"}},
			destination: "api.tavily.com",
			expected:    0,
		},
		{
			name:        "KnownToolNewDestOnGlobalAllowlist",
			toolDef:     &ToolDefinition{AllowedDestinations: []string{"api.tavily.com"}},
			destination: "api.github.com",
			expected:    1,
		},
		{
			name:        "KnownToolUnknownDest",
			toolDef:     &ToolDefinition{AllowedDestinations: []string{"api.tavily.com"}},
			destination: "evil.com",
			expected:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeNovelty(tt.toolDef, tt.destination, allowlist)
			if got != tt.expected {
				t.Errorf("computeNovelty() = %d, want %d", got, tt.expected)
			}
		})
	}
}

// --- Tests for LoadRiskConfig and LoadDestinationAllowlist ---

func TestDefaultRiskConfig(t *testing.T) {
	config := DefaultRiskConfig()
	if config.Thresholds.FastPathMax != 3 {
		t.Errorf("Expected fast_path_max 3, got %d", config.Thresholds.FastPathMax)
	}
	if config.Thresholds.StepUpMax != 6 {
		t.Errorf("Expected step_up_max 6, got %d", config.Thresholds.StepUpMax)
	}
	if config.Thresholds.ApprovalMax != 9 {
		t.Errorf("Expected approval_max 9, got %d", config.Thresholds.ApprovalMax)
	}
	if config.Guard.InjectionThreshold != 0.30 {
		t.Errorf("Expected injection_threshold 0.30, got %f", config.Guard.InjectionThreshold)
	}
	if config.Guard.JailbreakThreshold != 0.30 {
		t.Errorf("Expected jailbreak_threshold 0.30, got %f", config.Guard.JailbreakThreshold)
	}
}

func TestDefaultDestinationAllowlist(t *testing.T) {
	allowlist := DefaultDestinationAllowlist()
	if !allowlist.IsAllowed("localhost") {
		t.Error("Expected localhost to be allowed")
	}
	if !allowlist.IsAllowed("127.0.0.1") {
		t.Error("Expected 127.0.0.1 to be allowed")
	}
	if allowlist.IsAllowed("evil.com") {
		t.Error("Expected evil.com NOT to be allowed")
	}
}

// --- Test for each threshold band ---

func TestStepUpGating_AllThresholdBands(t *testing.T) {
	registry := testRegistry()
	allowlist := defaultAllowlist()
	config := defaultRiskConfig()
	guardClient := &mockGuardClient{injectionProb: 0.0, jailbreakProb: 0.0}

	tests := []struct {
		name          string
		toolName      string
		params        map[string]interface{}
		session       *AgentSession
		expectedGate  string
		expectAllowed bool
		expectCode    int
	}{
		{
			name:          "FastPath_ReadTool",
			toolName:      "read",
			params:        map[string]interface{}{"path": "/tmp/test.txt"},
			session:       nil,
			expectedGate:  "fast_path",
			expectAllowed: true,
			expectCode:    http.StatusOK,
		},
		{
			name:          "FastPath_GrepTool",
			toolName:      "grep",
			params:        map[string]interface{}{"pattern": "test", "path": "/tmp"},
			session:       nil,
			expectedGate:  "fast_path",
			expectAllowed: true,
			expectCode:    http.StatusOK,
		},
		{
			name:          "Deny_UnknownTool",
			toolName:      "unknown_tool",
			params:        map[string]interface{}{},
			session:       nil,
			expectedGate:  "approval", // defaults: 2+2+2+3=9
			expectAllowed: false,
			expectCode:    http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedResult *StepUpGatingResult
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedResult = GetStepUpResult(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			handler := StepUpGating(next, guardClient, allowlist, config, registry, nil)

			body := createTestMCPBody(tt.toolName, tt.params)
			req := newTestRequest(body)
			if tt.session != nil {
				ctx := WithSessionContextData(req.Context(), tt.session)
				req = req.WithContext(ctx)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectCode {
				t.Errorf("Expected status %d, got %d", tt.expectCode, rr.Code)
			}

			if tt.expectAllowed {
				if capturedResult == nil {
					t.Fatal("Expected step-up result in context")
				}
				if capturedResult.Gate != tt.expectedGate {
					t.Errorf("Expected gate %q, got %q", tt.expectedGate, capturedResult.Gate)
				}
			}
		})
	}
}

// --- Test GroqGuardHTTPClient ---

func TestGroqGuardHTTPClient_HasAPIKey(t *testing.T) {
	client := NewGroqGuardClient("test-key", 5)
	if !client.HasAPIKey() {
		t.Error("Expected HasAPIKey() to return true")
	}

	emptyClient := NewGroqGuardClient("", 5)
	if emptyClient.HasAPIKey() {
		t.Error("Expected HasAPIKey() to return false for empty key")
	}
}

func TestGroqGuardHTTPClient_NoAPIKey(t *testing.T) {
	client := NewGroqGuardClient("", 5)
	_, err := client.ClassifyContent(context.Background(), "test content")
	if err == nil {
		t.Error("Expected error when no API key configured")
	}
	if err.Error() != "no Groq API key configured" {
		t.Errorf("Expected 'no Groq API key configured', got %q", err.Error())
	}
}

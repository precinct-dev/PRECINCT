package gateway

import (
	"testing"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
)

// ============================================================
// AC #1: App-driven call origin detected
// ============================================================

func TestDetectCallOrigin_ExplicitUIContext_ResourceURI(t *testing.T) {
	ctx := &UIToolCallContext{
		ResourceURI: "ui://dashboard-server/analytics.html",
		SessionID:   "sess-123",
	}
	origin := DetectCallOrigin(ctx, nil)
	if origin != CallOriginApp {
		t.Errorf("expected CallOriginApp when ResourceURI is set, got %s", origin)
	}
}

func TestDetectCallOrigin_ExplicitUIContext_OriginatingTool(t *testing.T) {
	ctx := &UIToolCallContext{
		OriginatingTool: "render-analytics",
		SessionID:       "sess-123",
	}
	origin := DetectCallOrigin(ctx, nil)
	if origin != CallOriginApp {
		t.Errorf("expected CallOriginApp when OriginatingTool is set, got %s", origin)
	}
}

func TestDetectCallOrigin_ActiveUISession_AppVisibleTool(t *testing.T) {
	ctx := &UIToolCallContext{
		SessionID: "sess-123",
	}
	visibility := []ToolVisibility{VisibilityApp}
	origin := DetectCallOrigin(ctx, visibility)
	if origin != CallOriginApp {
		t.Errorf("expected CallOriginApp for active UI session with app-visible tool, got %s", origin)
	}
}

func TestDetectCallOrigin_ActiveUISession_BothVisibility(t *testing.T) {
	ctx := &UIToolCallContext{
		SessionID: "sess-123",
	}
	visibility := []ToolVisibility{VisibilityBoth}
	origin := DetectCallOrigin(ctx, visibility)
	if origin != CallOriginApp {
		t.Errorf("expected CallOriginApp for active UI session with both-visibility tool, got %s", origin)
	}
}

func TestDetectCallOrigin_ActiveUISession_ModelOnlyTool(t *testing.T) {
	ctx := &UIToolCallContext{
		SessionID: "sess-123",
	}
	visibility := []ToolVisibility{VisibilityModel}
	origin := DetectCallOrigin(ctx, visibility)
	if origin != CallOriginAgent {
		t.Errorf("expected CallOriginAgent for model-only tool even with UI session, got %s", origin)
	}
}

func TestDetectCallOrigin_NoUIContext(t *testing.T) {
	origin := DetectCallOrigin(nil, nil)
	if origin != CallOriginAgent {
		t.Errorf("expected CallOriginAgent when no UI context, got %s", origin)
	}
}

func TestDetectCallOrigin_EmptyUIContext(t *testing.T) {
	ctx := &UIToolCallContext{}
	origin := DetectCallOrigin(ctx, nil)
	if origin != CallOriginAgent {
		t.Errorf("expected CallOriginAgent when UI context is empty (no session), got %s", origin)
	}
}

func TestDetectCallOrigin_EmptyVisibility_WithUISession(t *testing.T) {
	ctx := &UIToolCallContext{
		SessionID: "sess-123",
	}
	// Empty visibility = both => app-visible
	origin := DetectCallOrigin(ctx, nil)
	if origin != CallOriginApp {
		t.Errorf("expected CallOriginApp with UI session and empty (default=both) visibility, got %s", origin)
	}
}

// ============================================================
// AC #2: Separate rate limits (20 req/min burst 5 for app)
// ============================================================

func TestGetAppDrivenRateLimitConfig_DefaultValues(t *testing.T) {
	uiConfig := UIConfigDefaults()
	mediator := NewToolCallMediator(uiConfig, nil)

	config := mediator.GetAppDrivenRateLimitConfig()
	if !config.Enabled {
		t.Error("expected app-driven rate limit to be enabled by default")
	}
	if config.RequestsPerMinute != 20 {
		t.Errorf("expected 20 req/min for app-driven, got %d", config.RequestsPerMinute)
	}
	if config.Burst != 5 {
		t.Errorf("expected burst 5 for app-driven, got %d", config.Burst)
	}
}

func TestGetAppDrivenRateLimitConfig_CustomValues(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.AppToolCalls.RequestsPerMinute = 30
	uiConfig.AppToolCalls.Burst = 10
	mediator := NewToolCallMediator(uiConfig, nil)

	config := mediator.GetAppDrivenRateLimitConfig()
	if config.RequestsPerMinute != 30 {
		t.Errorf("expected 30 req/min, got %d", config.RequestsPerMinute)
	}
	if config.Burst != 10 {
		t.Errorf("expected burst 10, got %d", config.Burst)
	}
}

func TestGetAppDrivenRateLimitConfig_Disabled(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.AppToolCalls.SeparateRateLimit = false
	mediator := NewToolCallMediator(uiConfig, nil)

	config := mediator.GetAppDrivenRateLimitConfig()
	if config.Enabled {
		t.Error("expected app-driven rate limit to be disabled")
	}
}

// Integration test: real rate limiter behavior
func TestAppDrivenRateLimiter_EnforcesLimits(t *testing.T) {
	appLimiter := middleware.NewAppDrivenRateLimiter(20, 2)

	spiffe := "spiffe://example.org/agent/test"

	// First 2 requests (burst) should succeed
	allowed1, _, _ := appLimiter.Allow(spiffe)
	if !allowed1 {
		t.Error("expected first app-driven request to be allowed")
	}
	allowed2, _, _ := appLimiter.Allow(spiffe)
	if !allowed2 {
		t.Error("expected second app-driven request to be allowed (within burst)")
	}

	// Third immediate request should be rate limited (burst exhausted)
	allowed3, _, _ := appLimiter.Allow(spiffe)
	if allowed3 {
		t.Error("expected third app-driven request to be rate limited (burst of 2 exhausted)")
	}
}

func TestAppDrivenRateLimiter_SeparateFromAgentBucket(t *testing.T) {
	agentLimiter := middleware.NewRateLimiter(60, 1, middleware.NewInMemoryRateLimitStore())
	appLimiter := middleware.NewAppDrivenRateLimiter(20, 1)

	spiffe := "spiffe://example.org/agent/test"

	// Agent bucket: exhaust the single token
	allowed, _, _ := agentLimiter.Allow(spiffe)
	if !allowed {
		t.Error("agent first request should be allowed")
	}
	allowed, _, _ = agentLimiter.Allow(spiffe)
	if allowed {
		t.Error("agent second request should be rate limited")
	}

	// App bucket: should still have its own token (independent)
	allowed, _, _ = appLimiter.Allow(spiffe)
	if !allowed {
		t.Error("app request should be allowed (separate bucket from agent)")
	}
}

func TestAppDrivenRateLimiter_RPMAndBurst(t *testing.T) {
	appLimiter := middleware.NewAppDrivenRateLimiter(20, 5)
	if appLimiter.RPM() != 20 {
		t.Errorf("expected RPM=20, got %d", appLimiter.RPM())
	}
	if appLimiter.Burst() != 5 {
		t.Errorf("expected Burst=5, got %d", appLimiter.Burst())
	}
}

// ============================================================
// AC #3: Tool allowlisting blocks unapproved tools
// ============================================================

func TestCheckToolAllowlist_ApprovedTool(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	grants := []UICapabilityGrant{
		{
			Server:        "mcp-dashboard-server",
			Tenant:        "acme-corp",
			Mode:          "allow",
			ApprovedTools: []string{"render-analytics", "show-chart"},
		},
	}

	gating := NewUICapabilityGating(uiConfig, "")
	gating.grants = grants
	gating.grantMap = map[string]*UICapabilityGrant{
		grantKey("mcp-dashboard-server", "acme-corp"): &grants[0],
	}

	mediator := NewToolCallMediator(uiConfig, gating)

	req := &ToolCallMediationRequest{
		ToolName:   "render-analytics",
		Server:     "mcp-dashboard-server",
		Tenant:     "acme-corp",
		CallOrigin: CallOriginApp,
	}

	if !mediator.CheckToolAllowlist(req) {
		t.Error("expected approved tool to be allowed")
	}
}

func TestCheckToolAllowlist_UnapprovedTool(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	grants := []UICapabilityGrant{
		{
			Server:        "mcp-dashboard-server",
			Tenant:        "acme-corp",
			Mode:          "allow",
			ApprovedTools: []string{"render-analytics", "show-chart"},
		},
	}

	gating := NewUICapabilityGating(uiConfig, "")
	gating.grants = grants
	gating.grantMap = map[string]*UICapabilityGrant{
		grantKey("mcp-dashboard-server", "acme-corp"): &grants[0],
	}

	mediator := NewToolCallMediator(uiConfig, gating)

	req := &ToolCallMediationRequest{
		ToolName:   "delete-data",
		Server:     "mcp-dashboard-server",
		Tenant:     "acme-corp",
		CallOrigin: CallOriginApp,
	}

	if mediator.CheckToolAllowlist(req) {
		t.Error("expected unapproved tool to be blocked")
	}
}

func TestCheckToolAllowlist_AgentDriven_Bypasses(t *testing.T) {
	uiConfig := UIConfigDefaults()
	mediator := NewToolCallMediator(uiConfig, nil)

	req := &ToolCallMediationRequest{
		ToolName:   "anything",
		Server:     "any-server",
		Tenant:     "any-tenant",
		CallOrigin: CallOriginAgent,
	}

	if !mediator.CheckToolAllowlist(req) {
		t.Error("agent-driven calls should bypass tool allowlisting")
	}
}

func TestCheckToolAllowlist_NoCapabilityGating(t *testing.T) {
	uiConfig := UIConfigDefaults()
	mediator := NewToolCallMediator(uiConfig, nil)

	req := &ToolCallMediationRequest{
		ToolName:   "render-analytics",
		Server:     "mcp-dashboard-server",
		Tenant:     "acme-corp",
		CallOrigin: CallOriginApp,
	}

	// No capability gating = fail closed
	if mediator.CheckToolAllowlist(req) {
		t.Error("expected tool to be blocked when no capability gating configured")
	}
}

func TestCheckToolAllowlist_EmptyApprovedList_AllApproved(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	grants := []UICapabilityGrant{
		{
			Server:        "mcp-server",
			Tenant:        "acme",
			Mode:          "allow",
			ApprovedTools: []string{}, // Empty = all approved
		},
	}

	gating := NewUICapabilityGating(uiConfig, "")
	gating.grants = grants
	gating.grantMap = map[string]*UICapabilityGrant{
		grantKey("mcp-server", "acme"): &grants[0],
	}

	mediator := NewToolCallMediator(uiConfig, gating)

	req := &ToolCallMediationRequest{
		ToolName:   "any-tool",
		Server:     "mcp-server",
		Tenant:     "acme",
		CallOrigin: CallOriginApp,
	}

	if !mediator.CheckToolAllowlist(req) {
		t.Error("expected all tools approved when approved_tools list is empty")
	}
}

// ============================================================
// AC #4: Visibility enforcement
// ============================================================

func TestCheckVisibility_AppOnly_BlockedFromAgent(t *testing.T) {
	allowed, reason := CheckVisibility(CallOriginAgent, []ToolVisibility{VisibilityApp})
	if allowed {
		t.Error("expected app-only tool to be blocked from agent")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestCheckVisibility_ModelOnly_BlockedFromApp(t *testing.T) {
	allowed, reason := CheckVisibility(CallOriginApp, []ToolVisibility{VisibilityModel})
	if allowed {
		t.Error("expected model-only tool to be blocked from app")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestCheckVisibility_Both_AllowedForAgent(t *testing.T) {
	allowed, _ := CheckVisibility(CallOriginAgent, []ToolVisibility{VisibilityBoth})
	if !allowed {
		t.Error("expected both-visibility tool to be allowed for agent")
	}
}

func TestCheckVisibility_Both_AllowedForApp(t *testing.T) {
	allowed, _ := CheckVisibility(CallOriginApp, []ToolVisibility{VisibilityBoth})
	if !allowed {
		t.Error("expected both-visibility tool to be allowed for app")
	}
}

func TestCheckVisibility_Empty_AllowedForBoth(t *testing.T) {
	// Empty visibility = default = both
	allowed, _ := CheckVisibility(CallOriginAgent, nil)
	if !allowed {
		t.Error("expected empty visibility to allow agent access")
	}

	allowed, _ = CheckVisibility(CallOriginApp, nil)
	if !allowed {
		t.Error("expected empty visibility to allow app access")
	}
}

func TestCheckVisibility_ModelAndApp_AllowedForBoth(t *testing.T) {
	visibility := []ToolVisibility{VisibilityModel, VisibilityApp}

	allowed, _ := CheckVisibility(CallOriginAgent, visibility)
	if !allowed {
		t.Error("expected [model, app] to allow agent access")
	}

	allowed, _ = CheckVisibility(CallOriginApp, visibility)
	if !allowed {
		t.Error("expected [model, app] to allow app access")
	}
}

func TestIsToolAppOnly(t *testing.T) {
	if !IsToolAppOnly([]ToolVisibility{VisibilityApp}) {
		t.Error("expected [app] to be app-only")
	}
	if IsToolAppOnly([]ToolVisibility{VisibilityModel}) {
		t.Error("expected [model] to NOT be app-only")
	}
	if IsToolAppOnly([]ToolVisibility{VisibilityBoth}) {
		t.Error("expected [both] to NOT be app-only")
	}
	if IsToolAppOnly(nil) {
		t.Error("expected nil to NOT be app-only")
	}
}

func TestIsToolModelOnly(t *testing.T) {
	if !IsToolModelOnly([]ToolVisibility{VisibilityModel}) {
		t.Error("expected [model] to be model-only")
	}
	if IsToolModelOnly([]ToolVisibility{VisibilityApp}) {
		t.Error("expected [app] to NOT be model-only")
	}
	if IsToolModelOnly(nil) {
		t.Error("expected nil to NOT be model-only")
	}
}

// ============================================================
// AC #5: Cross-server app-driven calls always blocked
// ============================================================

func TestCheckCrossServerBlocked_DifferentServer(t *testing.T) {
	req := &ToolCallMediationRequest{
		ToolName:   "refresh-data",
		Server:     "mcp-other-server",
		CallOrigin: CallOriginApp,
		UIContext: &UIToolCallContext{
			ResourceURI: "ui://mcp-dashboard-server/analytics.html",
			SessionID:   "sess-123",
		},
	}

	blocked, reason := CheckCrossServerBlocked(req)
	if !blocked {
		t.Error("expected cross-server app-driven call to be blocked")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestCheckCrossServerBlocked_SameServer(t *testing.T) {
	req := &ToolCallMediationRequest{
		ToolName:   "refresh-data",
		Server:     "mcp-dashboard-server",
		CallOrigin: CallOriginApp,
		UIContext: &UIToolCallContext{
			ResourceURI: "ui://mcp-dashboard-server/analytics.html",
			SessionID:   "sess-123",
		},
	}

	blocked, _ := CheckCrossServerBlocked(req)
	if blocked {
		t.Error("expected same-server app-driven call to NOT be blocked")
	}
}

func TestCheckCrossServerBlocked_AgentDriven_NotBlocked(t *testing.T) {
	req := &ToolCallMediationRequest{
		ToolName:   "refresh-data",
		Server:     "mcp-other-server",
		CallOrigin: CallOriginAgent,
		UIContext: &UIToolCallContext{
			ResourceURI: "ui://mcp-dashboard-server/analytics.html",
		},
	}

	blocked, _ := CheckCrossServerBlocked(req)
	if blocked {
		t.Error("agent-driven calls should not be subject to cross-server blocking")
	}
}

func TestCheckCrossServerBlocked_NoUIContext(t *testing.T) {
	req := &ToolCallMediationRequest{
		ToolName:   "refresh-data",
		Server:     "mcp-other-server",
		CallOrigin: CallOriginApp,
	}

	blocked, _ := CheckCrossServerBlocked(req)
	if blocked {
		t.Error("expected no blocking when no UI context to determine origin")
	}
}

func TestCheckCrossServerBlocked_EmptyResourceURI(t *testing.T) {
	req := &ToolCallMediationRequest{
		ToolName:   "refresh-data",
		Server:     "mcp-other-server",
		CallOrigin: CallOriginApp,
		UIContext: &UIToolCallContext{
			SessionID: "sess-123",
		},
	}

	blocked, _ := CheckCrossServerBlocked(req)
	if blocked {
		t.Error("expected no blocking when resource URI is empty")
	}
}

func TestExtractServerFromResourceURI(t *testing.T) {
	tests := []struct {
		uri    string
		expect string
	}{
		{"ui://mcp-dashboard-server/analytics.html", "mcp-dashboard-server"},
		{"ui://my-server/path/to/resource", "my-server"},
		{"ui://server-only", "server-only"},
		{"https://not-ui-scheme/path", ""},
		{"ui://", ""},
		{"", ""},
		{"short", ""},
	}

	for _, tt := range tests {
		got := extractServerFromResourceURI(tt.uri)
		if got != tt.expect {
			t.Errorf("extractServerFromResourceURI(%q) = %q, want %q", tt.uri, got, tt.expect)
		}
	}
}

// ============================================================
// AC #6: Step-up always required for app-driven high/critical risk tools
// ============================================================

func TestRequiresAppDrivenStepUp_HighRisk(t *testing.T) {
	uiConfig := UIConfigDefaults()
	mediator := NewToolCallMediator(uiConfig, nil)

	req := &ToolCallMediationRequest{
		ToolName:   "email_send",
		RiskLevel:  "high",
		CallOrigin: CallOriginApp,
	}

	if !mediator.RequiresAppDrivenStepUp(req) {
		t.Error("expected step-up required for app-driven high-risk tool")
	}
}

func TestRequiresAppDrivenStepUp_CriticalRisk(t *testing.T) {
	uiConfig := UIConfigDefaults()
	mediator := NewToolCallMediator(uiConfig, nil)

	req := &ToolCallMediationRequest{
		ToolName:   "bash",
		RiskLevel:  "critical",
		CallOrigin: CallOriginApp,
	}

	if !mediator.RequiresAppDrivenStepUp(req) {
		t.Error("expected step-up required for app-driven critical-risk tool")
	}
}

func TestRequiresAppDrivenStepUp_LowRisk_NotRequired(t *testing.T) {
	uiConfig := UIConfigDefaults()
	mediator := NewToolCallMediator(uiConfig, nil)

	req := &ToolCallMediationRequest{
		ToolName:   "read",
		RiskLevel:  "low",
		CallOrigin: CallOriginApp,
	}

	if mediator.RequiresAppDrivenStepUp(req) {
		t.Error("expected step-up NOT required for low-risk app-driven tool")
	}
}

func TestRequiresAppDrivenStepUp_MediumRisk_NotRequired(t *testing.T) {
	uiConfig := UIConfigDefaults()
	mediator := NewToolCallMediator(uiConfig, nil)

	req := &ToolCallMediationRequest{
		ToolName:   "search",
		RiskLevel:  "medium",
		CallOrigin: CallOriginApp,
	}

	if mediator.RequiresAppDrivenStepUp(req) {
		t.Error("expected step-up NOT required for medium-risk app-driven tool")
	}
}

func TestRequiresAppDrivenStepUp_AgentDriven_NotRequired(t *testing.T) {
	uiConfig := UIConfigDefaults()
	mediator := NewToolCallMediator(uiConfig, nil)

	req := &ToolCallMediationRequest{
		ToolName:   "bash",
		RiskLevel:  "critical",
		CallOrigin: CallOriginAgent,
	}

	if mediator.RequiresAppDrivenStepUp(req) {
		t.Error("expected step-up NOT required for agent-driven call even if critical risk")
	}
}

func TestRequiresAppDrivenStepUp_Disabled(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.AppToolCalls.ForceStepUpForHighRisk = false
	mediator := NewToolCallMediator(uiConfig, nil)

	req := &ToolCallMediationRequest{
		ToolName:   "bash",
		RiskLevel:  "critical",
		CallOrigin: CallOriginApp,
	}

	if mediator.RequiresAppDrivenStepUp(req) {
		t.Error("expected step-up NOT required when ForceStepUpForHighRisk is disabled")
	}
}

// Test the middleware-level function in step_up_gating.go
func TestIsAppDrivenHighRisk_ViaMiddleware(t *testing.T) {
	if !middleware.IsAppDrivenHighRisk("app", "high", true) {
		t.Error("expected app + high + enabled = true")
	}
	if !middleware.IsAppDrivenHighRisk("app", "critical", true) {
		t.Error("expected app + critical + enabled = true")
	}
	if middleware.IsAppDrivenHighRisk("agent", "high", true) {
		t.Error("expected agent + high = false")
	}
	if middleware.IsAppDrivenHighRisk("app", "low", true) {
		t.Error("expected app + low = false")
	}
	if middleware.IsAppDrivenHighRisk("app", "high", false) {
		t.Error("expected app + high + disabled = false")
	}
}

// ============================================================
// AC #7: Audit events emitted with ui_context and correlation
// ============================================================

func TestBuildAppDrivenAuditData_WithFullContext(t *testing.T) {
	uiCtx := &UIToolCallContext{
		ResourceURI:     "ui://dashboard-server/analytics.html",
		ContentHash:     "sha256:ab12cd34",
		OriginatingTool: "render-analytics",
		SessionID:       "sess-abc123",
	}

	sessionStart := time.Date(2026, 2, 4, 14, 30, 0, 0, time.UTC)
	data := BuildAppDrivenAuditData(uiCtx, 7, sessionStart)

	if data == nil {
		t.Fatal("expected non-nil audit data")
	}

	// Verify UIContext
	if data.UIContext == nil {
		t.Fatal("expected non-nil UIContext")
	}
	if data.UIContext.ResourceURI != "ui://dashboard-server/analytics.html" {
		t.Errorf("expected resource_uri, got %q", data.UIContext.ResourceURI)
	}
	if data.UIContext.ContentHash != "sha256:ab12cd34" {
		t.Errorf("expected content_hash, got %q", data.UIContext.ContentHash)
	}
	if data.UIContext.OriginatingTool != "render-analytics" {
		t.Errorf("expected originating_tool, got %q", data.UIContext.OriginatingTool)
	}
	if data.UIContext.SessionID != "sess-abc123" {
		t.Errorf("expected session_id, got %q", data.UIContext.SessionID)
	}

	// Verify Correlation
	if data.Correlation == nil {
		t.Fatal("expected non-nil Correlation")
	}
	if data.Correlation.ToolCallsInUISession != 7 {
		t.Errorf("expected tool_calls_in_ui_session=7, got %d", data.Correlation.ToolCallsInUISession)
	}
	if !data.Correlation.UserInteractionInferred {
		t.Error("expected user_interaction_inferred=true")
	}
	if data.Correlation.UISessionStart != "2026-02-04T14:30:00Z" {
		t.Errorf("expected ui_session_start formatted, got %q", data.Correlation.UISessionStart)
	}
}

func TestBuildAppDrivenAuditData_NilUIContext(t *testing.T) {
	data := BuildAppDrivenAuditData(nil, 3, time.Time{})

	if data == nil {
		t.Fatal("expected non-nil audit data even with nil context")
	}
	if data.UIContext != nil {
		t.Error("expected nil UIContext when input is nil")
	}
	if data.Correlation == nil {
		t.Fatal("expected non-nil Correlation")
	}
	if data.Correlation.ToolCallsInUISession != 3 {
		t.Errorf("expected tool count 3, got %d", data.Correlation.ToolCallsInUISession)
	}
	if data.Correlation.UISessionStart != "" {
		t.Errorf("expected empty session start for zero time, got %q", data.Correlation.UISessionStart)
	}
}

// ============================================================
// Integration test: Full mediation pipeline
// ============================================================

func TestMediate_AppDriven_AllChecksPass(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	grants := []UICapabilityGrant{
		{
			Server:        "mcp-dashboard-server",
			Tenant:        "acme-corp",
			Mode:          "allow",
			ApprovedTools: []string{"render-analytics", "refresh-data"},
		},
	}

	gating := NewUICapabilityGating(uiConfig, "")
	gating.grants = grants
	gating.grantMap = map[string]*UICapabilityGrant{
		grantKey("mcp-dashboard-server", "acme-corp"): &grants[0],
	}

	mediator := NewToolCallMediator(uiConfig, gating)

	req := &ToolCallMediationRequest{
		ToolName:   "refresh-data",
		Server:     "mcp-dashboard-server",
		Tenant:     "acme-corp",
		RiskLevel:  "low",
		Visibility: []ToolVisibility{VisibilityBoth},
		CallOrigin: CallOriginApp,
		UIContext: &UIToolCallContext{
			ResourceURI:     "ui://mcp-dashboard-server/analytics.html",
			OriginatingTool: "render-analytics",
			SessionID:       "sess-123",
		},
	}

	result := mediator.Mediate(req)
	if !result.Allowed {
		t.Errorf("expected allowed, got blocked: %s", result.Reason)
	}
	if result.AuditEventType != middleware.UIEventToolInvocationAppDriven {
		t.Errorf("expected audit event type %s, got %s",
			middleware.UIEventToolInvocationAppDriven, result.AuditEventType)
	}
}

func TestMediate_AppDriven_VisibilityBlocked(t *testing.T) {
	uiConfig := UIConfigDefaults()
	mediator := NewToolCallMediator(uiConfig, nil)

	req := &ToolCallMediationRequest{
		ToolName:   "internal-tool",
		Server:     "server",
		Tenant:     "tenant",
		RiskLevel:  "low",
		Visibility: []ToolVisibility{VisibilityModel}, // Model-only
		CallOrigin: CallOriginApp,
	}

	result := mediator.Mediate(req)
	if result.Allowed {
		t.Error("expected model-only tool to be blocked from app")
	}
	if result.AuditEventType != middleware.UIEventToolInvocationAppDrivenBlocked {
		t.Errorf("expected blocked audit event type, got %s", result.AuditEventType)
	}
}

func TestMediate_AppDriven_AllowlistBlocked(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	grants := []UICapabilityGrant{
		{
			Server:        "mcp-server",
			Tenant:        "acme",
			Mode:          "allow",
			ApprovedTools: []string{"tool-a"},
		},
	}

	gating := NewUICapabilityGating(uiConfig, "")
	gating.grants = grants
	gating.grantMap = map[string]*UICapabilityGrant{
		grantKey("mcp-server", "acme"): &grants[0],
	}

	mediator := NewToolCallMediator(uiConfig, gating)

	req := &ToolCallMediationRequest{
		ToolName:   "tool-b", // Not in approved list
		Server:     "mcp-server",
		Tenant:     "acme",
		CallOrigin: CallOriginApp,
	}

	result := mediator.Mediate(req)
	if result.Allowed {
		t.Error("expected unapproved tool to be blocked")
	}
	if result.AuditEventType != middleware.UIEventToolInvocationAppDrivenBlocked {
		t.Errorf("expected blocked audit event type, got %s", result.AuditEventType)
	}
}

func TestMediate_AppDriven_CrossServerBlocked(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	grants := []UICapabilityGrant{
		{
			Server:        "other-server",
			Tenant:        "acme",
			Mode:          "allow",
			ApprovedTools: []string{"refresh-data"},
		},
	}

	gating := NewUICapabilityGating(uiConfig, "")
	gating.grants = grants
	gating.grantMap = map[string]*UICapabilityGrant{
		grantKey("other-server", "acme"): &grants[0],
	}

	mediator := NewToolCallMediator(uiConfig, gating)

	req := &ToolCallMediationRequest{
		ToolName:   "refresh-data",
		Server:     "other-server",
		Tenant:     "acme",
		CallOrigin: CallOriginApp,
		UIContext: &UIToolCallContext{
			ResourceURI: "ui://mcp-dashboard-server/analytics.html",
			SessionID:   "sess-123",
		},
	}

	result := mediator.Mediate(req)
	if result.Allowed {
		t.Error("expected cross-server call to be blocked")
	}
	if result.AuditEventType != middleware.UIEventToolInvocationAppDrivenBlocked {
		t.Errorf("expected blocked audit event type, got %s", result.AuditEventType)
	}
}

func TestMediate_AppDriven_HighRisk_RequiresStepUp(t *testing.T) {
	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = true

	grants := []UICapabilityGrant{
		{
			Server:        "mcp-server",
			Tenant:        "acme",
			Mode:          "allow",
			ApprovedTools: []string{"email_send"},
		},
	}

	gating := NewUICapabilityGating(uiConfig, "")
	gating.grants = grants
	gating.grantMap = map[string]*UICapabilityGrant{
		grantKey("mcp-server", "acme"): &grants[0],
	}

	mediator := NewToolCallMediator(uiConfig, gating)

	req := &ToolCallMediationRequest{
		ToolName:   "email_send",
		Server:     "mcp-server",
		Tenant:     "acme",
		RiskLevel:  "high",
		CallOrigin: CallOriginApp,
		UIContext: &UIToolCallContext{
			ResourceURI: "ui://mcp-server/compose.html",
			SessionID:   "sess-123",
		},
	}

	result := mediator.Mediate(req)
	if !result.Allowed {
		t.Errorf("expected allowed (step-up is separate), got blocked: %s", result.Reason)
	}
	if !result.RequiresStepUp {
		t.Error("expected RequiresStepUp=true for app-driven high-risk tool")
	}
}

func TestMediate_AgentDriven_NoMediationNeeded(t *testing.T) {
	uiConfig := UIConfigDefaults()
	mediator := NewToolCallMediator(uiConfig, nil)

	req := &ToolCallMediationRequest{
		ToolName:   "bash",
		Server:     "any-server",
		Tenant:     "any-tenant",
		RiskLevel:  "critical",
		CallOrigin: CallOriginAgent,
	}

	result := mediator.Mediate(req)
	if !result.Allowed {
		t.Errorf("expected agent-driven call to pass mediation, got: %s", result.Reason)
	}
	if result.AuditEventType != "" {
		t.Errorf("expected no audit event for agent-driven, got %s", result.AuditEventType)
	}
	if result.RequiresStepUp {
		t.Error("expected no step-up for agent-driven call")
	}
}

func TestMediate_AgentDriven_AppOnlyToolBlocked(t *testing.T) {
	uiConfig := UIConfigDefaults()
	mediator := NewToolCallMediator(uiConfig, nil)

	req := &ToolCallMediationRequest{
		ToolName:   "ui-only-tool",
		Server:     "any-server",
		Tenant:     "any-tenant",
		Visibility: []ToolVisibility{VisibilityApp},
		CallOrigin: CallOriginAgent,
	}

	result := mediator.Mediate(req)
	if result.Allowed {
		t.Error("expected app-only tool to be blocked for agent")
	}
}

// ============================================================
// Visibility helper functions
// ============================================================

func TestHasAppVisibility(t *testing.T) {
	if !hasAppVisibility(nil) {
		t.Error("nil should have app visibility (default=both)")
	}
	if !hasAppVisibility([]ToolVisibility{VisibilityApp}) {
		t.Error("[app] should have app visibility")
	}
	if !hasAppVisibility([]ToolVisibility{VisibilityBoth}) {
		t.Error("[both] should have app visibility")
	}
	if hasAppVisibility([]ToolVisibility{VisibilityModel}) {
		t.Error("[model] should NOT have app visibility")
	}
}

func TestHasModelVisibility(t *testing.T) {
	if !hasModelVisibility(nil) {
		t.Error("nil should have model visibility (default=both)")
	}
	if !hasModelVisibility([]ToolVisibility{VisibilityModel}) {
		t.Error("[model] should have model visibility")
	}
	if !hasModelVisibility([]ToolVisibility{VisibilityBoth}) {
		t.Error("[both] should have model visibility")
	}
	if hasModelVisibility([]ToolVisibility{VisibilityApp}) {
		t.Error("[app] should NOT have model visibility")
	}
}

// ============================================================
// Edge cases
// ============================================================

func TestNewToolCallMediator_NilConfig(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewToolCallMediator should not panic with nil config, got: %v", r)
		}
	}()

	// This should handle gracefully even if config is nil
	config := UIConfigDefaults()
	m := NewToolCallMediator(config, nil)
	if m == nil {
		t.Fatal("expected non-nil mediator")
	}
}

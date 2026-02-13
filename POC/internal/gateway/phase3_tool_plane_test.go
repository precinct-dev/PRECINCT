package gateway

import (
	"net/http"
	"testing"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

func TestToolPlaneEvaluatorEnforcesCapabilityAdapterAndAction(t *testing.T) {
	engine := newToolPlanePolicyEngine("")

	baseReq := func() PlaneRequestV2 {
		return PlaneRequestV2{
			Envelope: RunEnvelope{
				RunID:         "phase3-unit-tool",
				SessionID:     "phase3-unit-tool-session",
				Tenant:        "tenant-a",
				ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Plane:         PlaneTool,
			},
			Policy: PolicyInputV2{
				Envelope: RunEnvelope{
					RunID:         "phase3-unit-tool",
					SessionID:     "phase3-unit-tool-session",
					Tenant:        "tenant-a",
					ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
					Plane:         PlaneTool,
				},
				Action:   "tool.execute",
				Resource: "tool/read",
				Attributes: map[string]any{
					"capability_id": "tool.default.mcp",
					"tool_name":     "read",
					"protocol":      "mcp",
				},
			},
		}
	}

	t.Run("allow path", func(t *testing.T) {
		res := engine.evaluate(baseReq())
		if res.Decision != DecisionAllow || res.Reason != ReasonToolAllow || res.HTTPStatus != http.StatusOK {
			t.Fatalf("expected allow/TOOL_ALLOW/200, got decision=%s reason=%s status=%d metadata=%v", res.Decision, res.Reason, res.HTTPStatus, res.Metadata)
		}
	})

	t.Run("capability denied", func(t *testing.T) {
		req := baseReq()
		req.Policy.Attributes["capability_id"] = "tool.unknown.mcp"
		res := engine.evaluate(req)
		if res.Reason != ReasonToolCapabilityDenied || res.HTTPStatus != http.StatusForbidden {
			t.Fatalf("expected TOOL_CAPABILITY_DENIED/403, got reason=%s status=%d", res.Reason, res.HTTPStatus)
		}
	})

	t.Run("adapter unsupported", func(t *testing.T) {
		req := baseReq()
		req.Policy.Attributes["protocol"] = "cli"
		res := engine.evaluate(req)
		if res.Reason != ReasonToolAdapterUnsupported || res.HTTPStatus != http.StatusForbidden {
			t.Fatalf("expected TOOL_ADAPTER_UNSUPPORTED/403, got reason=%s status=%d", res.Reason, res.HTTPStatus)
		}
	})

	t.Run("action denied", func(t *testing.T) {
		req := baseReq()
		req.Policy.Resource = "tool/write"
		res := engine.evaluate(req)
		if res.Reason != ReasonToolActionDenied || res.HTTPStatus != http.StatusForbidden {
			t.Fatalf("expected TOOL_ACTION_DENIED/403, got reason=%s status=%d", res.Reason, res.HTTPStatus)
		}
	})
}

func TestToolPlaneStepUpRequirementAndApprovalToken(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	sessionID := "phase3-tool-stepup-session"
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	basePayload := map[string]any{
		"envelope": map[string]any{
			"run_id":          "phase3-tool-stepup-run",
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "tool",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "phase3-tool-stepup-run",
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "tool",
			},
			"action":   "tool.execute",
			"resource": "tool/write",
			"attributes": map[string]any{
				"capability_id": "tool.highrisk.cli",
				"tool_name":     "bash",
				"adapter":       "cli",
			},
		},
	}

	code, body := postGatewayJSON(t, h, http.MethodPost, "/v1/tool/execute", basePayload)
	if code != http.StatusPreconditionRequired {
		t.Fatalf("expected 428 without step-up token, got %d body=%v", code, body)
	}
	if got, _ := body["reason_code"].(string); got != string(ReasonToolStepUpRequired) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonToolStepUpRequired, body["reason_code"])
	}

	record, err := gw.approvalCapabilities.CreateRequest(middleware.ApprovalRequestInput{
		Scope: middleware.ApprovalScope{
			Action:        "tool.execute",
			Resource:      "tool/write",
			ActorSPIFFEID: spiffeID,
			SessionID:     sessionID,
		},
		RequestedBy: spiffeID,
		Reason:      "phase3 tool step-up unit test",
		TTLSeconds:  120,
	})
	if err != nil {
		t.Fatalf("create approval request: %v", err)
	}
	grant, err := gw.approvalCapabilities.GrantRequest(middleware.ApprovalGrantInput{
		RequestID:  record.RequestID,
		ApprovedBy: "security@corp",
		Reason:     "approved test path",
	})
	if err != nil {
		t.Fatalf("grant approval request: %v", err)
	}

	stepUpPayload := map[string]any{
		"envelope": map[string]any{
			"run_id":          "phase3-tool-stepup-run-approved",
			"session_id":      sessionID,
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffeID,
			"plane":           "tool",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "phase3-tool-stepup-run-approved",
				"session_id":      sessionID,
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffeID,
				"plane":           "tool",
			},
			"action":   "tool.execute",
			"resource": "tool/write",
			"attributes": map[string]any{
				"capability_id":             "tool.highrisk.cli",
				"tool_name":                 "bash",
				"adapter":                   "cli",
				"approval_capability_token": grant.Token,
			},
		},
	}
	code, body = postGatewayJSON(t, h, http.MethodPost, "/v1/tool/execute", stepUpPayload)
	if code != http.StatusOK {
		t.Fatalf("expected 200 with valid approval token, got %d body=%v", code, body)
	}
	if got, _ := body["reason_code"].(string); got != string(ReasonToolAllow) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonToolAllow, body["reason_code"])
	}
}

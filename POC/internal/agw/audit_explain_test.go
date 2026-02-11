package agw

import (
	"strings"
	"testing"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

func TestErrorCodeToStep_All25CodesMapped(t *testing.T) {
	codes := []string{
		middleware.ErrAuthMissingIdentity,
		middleware.ErrAuthInvalidIdentity,
		middleware.ErrAuthzPolicyDenied,
		middleware.ErrAuthzNoMatchingGrant,
		middleware.ErrAuthzToolNotFound,
		middleware.ErrRegistryHashMismatch,
		middleware.ErrRegistryToolUnknown,
		middleware.ErrDLPCredentialsDetected,
		middleware.ErrDLPInjectionBlocked,
		middleware.ErrDLPPIIBlocked,
		middleware.ErrStepUpDenied,
		middleware.ErrStepUpApprovalRequired,
		middleware.ErrStepUpGuardBlocked,
		middleware.ErrStepUpDestinationBlocked,
		middleware.ErrDeepScanBlocked,
		middleware.ErrDeepScanUnavailableFailClosed,
		middleware.ErrRateLimitExceeded,
		middleware.ErrCircuitOpen,
		middleware.ErrRequestTooLarge,
		middleware.ErrExfiltrationDetected,
		middleware.ErrUICapabilityDenied,
		middleware.ErrUIResourceBlocked,
		middleware.ErrMCPTransportFailed,
		middleware.ErrMCPRequestFailed,
		middleware.ErrMCPInvalidResponse,
		middleware.ErrMCPInvalidRequest,
	}

	for _, code := range codes {
		step, ok := ErrorCodeToStep(code)
		if !ok {
			t.Fatalf("expected mapping for code %q", code)
		}
		if step < 1 || step > 13 {
			t.Fatalf("expected step 1..13 for code %q, got %d", code, step)
		}
	}
}

func TestBuildAuditExplain_DeniedFromErrorCode(t *testing.T) {
	entries := []map[string]any{
		{
			"timestamp":       "2026-02-11T10:00:00Z",
			"decision_id":     "dec-1",
			"spiffe_id":       "spiffe://poc.local/agents/test/dev",
			"tool":            "unknown-tool",
			"status_code":     403,
			"action":          "mcp_request",
			"code":            middleware.ErrRegistryToolUnknown,
			"middleware_step": 5,
		},
	}

	out, err := BuildAuditExplain(entries, "dec-1")
	if err != nil {
		t.Fatalf("BuildAuditExplain: %v", err)
	}

	if out.Result != "denied (HTTP 403)" {
		t.Fatalf("unexpected result: %q", out.Result)
	}
	if out.ErrorCode != middleware.ErrRegistryToolUnknown {
		t.Fatalf("expected error code %q, got %q", middleware.ErrRegistryToolUnknown, out.ErrorCode)
	}

	if len(out.Layers) != 13 {
		t.Fatalf("expected 13 layers, got %d", len(out.Layers))
	}
	if out.Layers[4].Status != "FAIL" { // step 5 is index 4
		t.Fatalf("expected step 5 FAIL, got %+v", out.Layers[4])
	}
	if !strings.Contains(out.Layers[4].Detail, middleware.ErrRegistryToolUnknown) {
		t.Fatalf("expected fail detail to contain error code, got %+v", out.Layers[4])
	}
	if out.Layers[5].Status != "SKIPPED" { // step 6 is index 5
		t.Fatalf("expected step 6 SKIPPED after failure, got %+v", out.Layers[5])
	}
}

func TestBuildAuditExplain_AllowedAllPass(t *testing.T) {
	entries := []map[string]any{
		{
			"timestamp":   "2026-02-11T10:00:00Z",
			"decision_id": "dec-allow",
			"spiffe_id":   "spiffe://poc.local/agents/test/dev",
			"tool":        "tavily_search",
			"status_code": 200,
			"action":      "mcp_request",
		},
	}

	out, err := BuildAuditExplain(entries, "dec-allow")
	if err != nil {
		t.Fatalf("BuildAuditExplain: %v", err)
	}
	if out.Result != "allowed" {
		t.Fatalf("expected allowed, got %q", out.Result)
	}
	for _, layer := range out.Layers {
		if layer.Status != "PASS" {
			t.Fatalf("expected all PASS for allowed request, got %+v", out.Layers)
		}
	}
}

func TestBuildAuditExplain_DeniedInferredFromStepUpAudit(t *testing.T) {
	entries := []map[string]any{
		{
			"timestamp":   "2026-02-11T10:00:00Z",
			"decision_id": "dec-step-up",
			"spiffe_id":   "spiffe://poc.local/agents/test/dev",
			"tool":        "bash",
			"status_code": 403,
			"action":      "mcp_request",
		},
		{
			"timestamp":   "2026-02-11T10:00:00Z",
			"decision_id": "dec-step-up",
			"action":      "step_up_gating",
			"result":      "gate=approval allowed=false total_score=5 reason=approval required",
		},
	}

	out, err := BuildAuditExplain(entries, "dec-step-up")
	if err != nil {
		t.Fatalf("BuildAuditExplain: %v", err)
	}
	if out.Layers[8].Status != "FAIL" { // step 9
		t.Fatalf("expected step 9 FAIL, got %+v", out.Layers[8])
	}
	if out.ErrorCode != middleware.ErrStepUpDenied {
		t.Fatalf("expected inferred step-up code, got %q", out.ErrorCode)
	}
}

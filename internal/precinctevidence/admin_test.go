package precinctevidence

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

func TestLogLoopAdminDecision(t *testing.T) {
	t.Parallel()

	logger := &mockAuditLogger{}
	req := httptest.NewRequest(http.MethodPost, "/admin/loop/runs/run-1/halt", nil)
	ctx := middleware.WithSPIFFEID(req.Context(), "spiffe://poc.local/admin")
	ctx = middleware.WithSessionID(ctx, "sess-1")
	req = req.WithContext(ctx)

	LogLoopAdminDecision(logger, req, "admin.loop.halt", map[string]any{
		"run_id":      "run-1",
		"state":       "running",
		"halt_reason": "operator",
	}, "dec-1", "trace-1", http.StatusOK)

	if len(logger.events) != 1 {
		t.Fatalf("expected one event, got %d", len(logger.events))
	}
	ev := logger.events[0]
	if ev.Action != "admin.loop.halt" {
		t.Fatalf("expected action admin.loop.halt, got %q", ev.Action)
	}
	if ev.DecisionID != "dec-1" || ev.TraceID != "trace-1" {
		t.Fatalf("expected correlation ids dec-1/trace-1, got %q/%q", ev.DecisionID, ev.TraceID)
	}
	if ev.Result == "" {
		t.Fatal("expected non-empty result")
	}
}

func TestLogRuleOpsDecision(t *testing.T) {
	t.Parallel()

	logger := &mockAuditLogger{}
	req := httptest.NewRequest(http.MethodPost, "/admin/dlp/rulesets/create", nil)
	ctx := middleware.WithSPIFFEID(req.Context(), "spiffe://poc.local/admin")
	ctx = middleware.WithSessionID(ctx, "sess-2")
	req = req.WithContext(ctx)

	LogRuleOpsDecision(logger, req, "ruleset-1", "create", "allow", "ok", "dec-2", "trace-2", http.StatusOK)

	if len(logger.events) != 1 {
		t.Fatalf("expected one event, got %d", len(logger.events))
	}
	ev := logger.events[0]
	if ev.Action != "ruleops.create" {
		t.Fatalf("expected action ruleops.create, got %q", ev.Action)
	}
	if ev.Path != "/admin/dlp/rulesets/create" {
		t.Fatalf("expected path %q, got %q", "/admin/dlp/rulesets/create", ev.Path)
	}
}

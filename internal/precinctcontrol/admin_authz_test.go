package precinctcontrol

import "testing"

func TestResolveAdminMiddlewareForPath(t *testing.T) {
	t.Run("ruleops admin path", func(t *testing.T) {
		mw := ResolveAdminMiddlewareForPath("/admin/dlp/rulesets/active", AdminMiddlewareNames{})
		if mw != "v24_ruleops_admin" {
			t.Fatalf("expected ruleops middleware, got %q", mw)
		}
	})

	t.Run("admin default path", func(t *testing.T) {
		mw := ResolveAdminMiddlewareForPath("/admin/unknown", AdminMiddlewareNames{})
		if mw != "v24_admin_authz" {
			t.Fatalf("expected default middleware, got %q", mw)
		}
	})

	t.Run("custom names", func(t *testing.T) {
		mw := ResolveAdminMiddlewareForPath("/admin/loop/runs/1", AdminMiddlewareNames{LoopRuns: "loop.custom", Default: "admin.default"})
		if mw != "loop.custom" {
			t.Fatalf("expected custom loop middleware, got %q", mw)
		}
	})
}

func TestDefaultAdminMiddlewareNames(t *testing.T) {
	t.Parallel()

	names := DefaultAdminMiddlewareNames()
	if names.ConnectorAuth != "v24_connector_authority" {
		t.Fatalf("expected default connector auth middleware v24_connector_authority, got %q", names.ConnectorAuth)
	}
	if names.RuleOps != "v24_ruleops_admin" {
		t.Fatalf("expected default ruleops middleware v24_ruleops_admin, got %q", names.RuleOps)
	}
	if names.Approval != "v24_approval_admin" {
		t.Fatalf("expected default approval middleware v24_approval_admin, got %q", names.Approval)
	}
	if names.BreakGlass != "v24_break_glass_admin" {
		t.Fatalf("expected default break-glass middleware v24_break_glass_admin, got %q", names.BreakGlass)
	}
	if names.Profile != "v24_profile_admin" {
		t.Fatalf("expected default profile middleware v24_profile_admin, got %q", names.Profile)
	}
	if names.LoopRuns != "v24_loop_admin" {
		t.Fatalf("expected default loop runs middleware v24_loop_admin, got %q", names.LoopRuns)
	}
	if names.Circuit != "v24_circuit_breaker_admin" {
		t.Fatalf("expected default circuit-breaker middleware v24_circuit_breaker_admin, got %q", names.Circuit)
	}
	if names.PolicyReload != "v24_policy_reload_admin" {
		t.Fatalf("expected default policy reload middleware v24_policy_reload_admin, got %q", names.PolicyReload)
	}
	if names.Default != "" {
		t.Fatalf("expected default middleware unset by default factory, got %q", names.Default)
	}
}

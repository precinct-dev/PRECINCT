package gateway

import (
	"errors"
	"testing"
	"time"
)

func TestBreakGlassLifecycleDualAuthAndRevert(t *testing.T) {
	base := time.Date(2026, 2, 13, 10, 0, 0, 0, time.UTC)
	mgr := newBreakGlassManager(nil)
	mgr.now = func() time.Time { return base }

	record, err := mgr.request(breakGlassRequestInput{
		IncidentID: "INC-42",
		Scope: breakGlassScope{
			Action:        "model.call",
			Resource:      "gpt-4o",
			ActorSPIFFEID: "spiffe://poc.local/agents/a/dev",
		},
		RequestedBy: "security@corp",
		TTLSeconds:  120,
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if record.Status != breakGlassStatusPending {
		t.Fatalf("expected pending status, got %s", record.Status)
	}

	// Activation before dual approval is forbidden.
	if _, err := mgr.activate(breakGlassActivateInput{RequestID: record.RequestID, ActivatedBy: "ops@corp"}); !errors.Is(err, errBreakGlassDualAuthNeeded) {
		t.Fatalf("expected dual-auth error, got %v", err)
	}

	if _, err := mgr.approve(breakGlassApprovalInput{RequestID: record.RequestID, ApprovedBy: "security-1@corp"}); err != nil {
		t.Fatalf("approve #1: %v", err)
	}
	approved, err := mgr.approve(breakGlassApprovalInput{RequestID: record.RequestID, ApprovedBy: "security-2@corp"})
	if err != nil {
		t.Fatalf("approve #2: %v", err)
	}
	if approved.Status != breakGlassStatusApproved {
		t.Fatalf("expected approved status after two approvals, got %s", approved.Status)
	}

	active, err := mgr.activate(breakGlassActivateInput{RequestID: record.RequestID, ActivatedBy: "ops@corp"})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if active.Status != breakGlassStatusActive {
		t.Fatalf("expected active status, got %s", active.Status)
	}
	if active.ExpiresAt == nil {
		t.Fatal("expected expires_at on active record")
	}

	if _, ok := mgr.activeOverride(breakGlassScope{
		Action:        "model.call",
		Resource:      "gpt-4o",
		ActorSPIFFEID: "spiffe://poc.local/agents/a/dev",
	}); !ok {
		t.Fatal("expected active override to match configured scope")
	}
	if _, ok := mgr.activeOverride(breakGlassScope{
		Action:        "model.call",
		Resource:      "gpt-4o-mini",
		ActorSPIFFEID: "spiffe://poc.local/agents/a/dev",
	}); ok {
		t.Fatal("expected non-matching resource to be denied")
	}

	reverted, err := mgr.revert(breakGlassRevertInput{RequestID: record.RequestID, RevertedBy: "ops@corp"})
	if err != nil {
		t.Fatalf("revert: %v", err)
	}
	if reverted.Status != breakGlassStatusReverted {
		t.Fatalf("expected reverted status, got %s", reverted.Status)
	}
	if _, ok := mgr.activeOverride(breakGlassScope{
		Action:        "model.call",
		Resource:      "gpt-4o",
		ActorSPIFFEID: "spiffe://poc.local/agents/a/dev",
	}); ok {
		t.Fatal("expected reverted override to be inactive")
	}
}

func TestBreakGlassAutoExpiry(t *testing.T) {
	base := time.Date(2026, 2, 13, 11, 0, 0, 0, time.UTC)
	mgr := newBreakGlassManager(nil)
	mgr.now = func() time.Time { return base }

	record, err := mgr.request(breakGlassRequestInput{
		IncidentID: "INC-EXP",
		Scope: breakGlassScope{
			Action:        "model.call",
			Resource:      "gpt-4o",
			ActorSPIFFEID: "spiffe://poc.local/agents/a/dev",
		},
		RequestedBy: "security@corp",
		TTLSeconds:  1,
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := mgr.approve(breakGlassApprovalInput{RequestID: record.RequestID, ApprovedBy: "security-1@corp"}); err != nil {
		t.Fatalf("approve #1: %v", err)
	}
	if _, err := mgr.approve(breakGlassApprovalInput{RequestID: record.RequestID, ApprovedBy: "security-2@corp"}); err != nil {
		t.Fatalf("approve #2: %v", err)
	}
	if _, err := mgr.activate(breakGlassActivateInput{RequestID: record.RequestID, ActivatedBy: "ops@corp"}); err != nil {
		t.Fatalf("activate: %v", err)
	}

	// Move past expiry and verify automatic revert-to-expired behavior.
	mgr.now = func() time.Time { return base.Add(2 * time.Second) }
	if _, ok := mgr.activeOverride(breakGlassScope{
		Action:        "model.call",
		Resource:      "gpt-4o",
		ActorSPIFFEID: "spiffe://poc.local/agents/a/dev",
	}); ok {
		t.Fatal("expected expired override to be inactive")
	}

	got, ok := mgr.get(record.RequestID)
	if !ok {
		t.Fatalf("expected record %s to exist", record.RequestID)
	}
	if got.Status != breakGlassStatusExpired {
		t.Fatalf("expected expired status, got %s", got.Status)
	}
}

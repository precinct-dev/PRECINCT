// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestApprovalCapabilityLifecycle(t *testing.T) {
	base := time.Date(2026, 2, 13, 8, 0, 0, 0, time.UTC)
	svc := mustNewApprovalCapabilityService(t, "test-key", 5*time.Minute, 30*time.Minute, nil, "dev")
	svc.now = func() time.Time { return base }

	created, err := svc.CreateRequest(ApprovalRequestInput{
		Scope: ApprovalScope{
			Action:        "tool.call",
			Resource:      "bash",
			ActorSPIFFEID: "spiffe://poc.local/agents/a/dev",
			SessionID:     "sess-123",
		},
		RequestedBy: "agent-owner@corp",
		TTLSeconds:  120,
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if created.Status != ApprovalStatusPending {
		t.Fatalf("expected pending status, got %s", created.Status)
	}

	grant, err := svc.GrantRequest(ApprovalGrantInput{
		RequestID:  created.RequestID,
		ApprovedBy: "security@corp",
		Reason:     "ticket-1001",
	})
	if err != nil {
		t.Fatalf("grant request: %v", err)
	}
	if grant.Token == "" {
		t.Fatal("expected non-empty capability token")
	}
	if grant.Claims.Action != "tool.call" || grant.Claims.Resource != "bash" {
		t.Fatalf("unexpected claims: %+v", grant.Claims)
	}

	claims, err := svc.ValidateAndConsume(grant.Token, ApprovalScope{
		Action:        "tool.call",
		Resource:      "bash",
		ActorSPIFFEID: "spiffe://poc.local/agents/a/dev",
		SessionID:     "sess-123",
	})
	if err != nil {
		t.Fatalf("validate and consume: %v", err)
	}
	if claims.RequestID != created.RequestID {
		t.Fatalf("expected request id %s, got %s", created.RequestID, claims.RequestID)
	}

	_, err = svc.ValidateAndConsume(grant.Token, ApprovalScope{
		Action:        "tool.call",
		Resource:      "bash",
		ActorSPIFFEID: "spiffe://poc.local/agents/a/dev",
		SessionID:     "sess-123",
	})
	if !errors.Is(err, ErrApprovalTokenConsumed) {
		t.Fatalf("expected ErrApprovalTokenConsumed, got %v", err)
	}

	record, ok := svc.GetRequest(created.RequestID)
	if !ok {
		t.Fatalf("expected request %s to exist", created.RequestID)
	}
	if record.Status != ApprovalStatusConsumed {
		t.Fatalf("expected consumed status, got %s", record.Status)
	}
}

func TestApprovalCapabilityRejectsScopeMismatchAndExpiry(t *testing.T) {
	base := time.Date(2026, 2, 13, 9, 0, 0, 0, time.UTC)
	svc := mustNewApprovalCapabilityService(t, "test-key", 60*time.Second, 10*time.Minute, nil, "dev")
	svc.now = func() time.Time { return base }

	created, err := svc.CreateRequest(ApprovalRequestInput{
		Scope: ApprovalScope{
			Action:        "model.call",
			Resource:      "gpt-4o",
			ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dev",
			SessionID:     "sess-model",
		},
		TTLSeconds: 30,
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	grant, err := svc.GrantRequest(ApprovalGrantInput{RequestID: created.RequestID, ApprovedBy: "security@corp"})
	if err != nil {
		t.Fatalf("grant request: %v", err)
	}

	_, err = svc.ValidateAndConsume(grant.Token, ApprovalScope{
		Action:        "model.call",
		Resource:      "gpt-4o-mini",
		ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dev",
		SessionID:     "sess-model",
	})
	if !errors.Is(err, ErrApprovalScopeMismatch) {
		t.Fatalf("expected ErrApprovalScopeMismatch, got %v", err)
	}

	// Advance time beyond expiry and verify expiry handling.
	svc.now = func() time.Time { return base.Add(31 * time.Second) }
	_, err = svc.ValidateAndConsume(grant.Token, ApprovalScope{
		Action:        "model.call",
		Resource:      "gpt-4o",
		ActorSPIFFEID: "spiffe://poc.local/agents/mcp-client/dev",
		SessionID:     "sess-model",
	})
	if !errors.Is(err, ErrApprovalTokenExpired) {
		t.Fatalf("expected ErrApprovalTokenExpired, got %v", err)
	}

	record, ok := svc.GetRequest(created.RequestID)
	if !ok {
		t.Fatalf("expected request %s to exist", created.RequestID)
	}
	if record.Status != ApprovalStatusExpired {
		t.Fatalf("expected expired status, got %s", record.Status)
	}
}

func TestApprovalCapabilityDenyPath(t *testing.T) {
	svc := mustNewApprovalCapabilityService(t, "test-key", 5*time.Minute, 30*time.Minute, nil, "dev")
	created, err := svc.CreateRequest(ApprovalRequestInput{
		Scope: ApprovalScope{
			Action:        "tool.call",
			Resource:      "bash",
			ActorSPIFFEID: "spiffe://poc.local/agents/a/dev",
			SessionID:     "sess-deny",
		},
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	denied, err := svc.DenyRequest(ApprovalDenyInput{
		RequestID: created.RequestID,
		DeniedBy:  "security@corp",
		Reason:    "high blast radius",
	})
	if err != nil {
		t.Fatalf("deny request: %v", err)
	}
	if denied.Status != ApprovalStatusDenied {
		t.Fatalf("expected denied status, got %s", denied.Status)
	}

	_, err = svc.GrantRequest(ApprovalGrantInput{RequestID: created.RequestID, ApprovedBy: "security@corp"})
	if !errors.Is(err, ErrApprovalInvalidState) {
		t.Fatalf("expected ErrApprovalInvalidState after deny, got %v", err)
	}
}

func TestApprovalCapabilityService_GeneratesEphemeralKeyWhenMissing(t *testing.T) {
	svcA := mustNewApprovalCapabilityService(t, "", 5*time.Minute, 30*time.Minute, nil, "dev")
	svcB := mustNewApprovalCapabilityService(t, "", 5*time.Minute, 30*time.Minute, nil, "dev")

	if len(strings.TrimSpace(string(svcA.signingKey))) < MinApprovalSigningKeyLength {
		t.Fatalf("expected generated key length >= %d", MinApprovalSigningKeyLength)
	}
	if len(strings.TrimSpace(string(svcB.signingKey))) < MinApprovalSigningKeyLength {
		t.Fatalf("expected generated key length >= %d", MinApprovalSigningKeyLength)
	}
	if string(svcA.signingKey) == string(svcB.signingKey) {
		t.Fatal("expected generated ephemeral signing keys to differ between service instances")
	}
}

// mustNewApprovalCapabilityService is a test helper that calls
// NewApprovalCapabilityService and fails the test on error.
func mustNewApprovalCapabilityService(t *testing.T, signingKey string, defaultTTL, maxTTL time.Duration, auditor *Auditor, profile string) *ApprovalCapabilityService {
	t.Helper()
	svc, err := NewApprovalCapabilityService(signingKey, defaultTTL, maxTTL, auditor, profile)
	if err != nil {
		t.Fatalf("NewApprovalCapabilityService: %v", err)
	}
	return svc
}

func TestApprovalCapability_ProdProfile_RejectsEmptySigningKey(t *testing.T) {
	for _, profile := range []string{"prod", "prod_standard", "prod_regulated_hipaa"} {
		t.Run(profile, func(t *testing.T) {
			svc, err := NewApprovalCapabilityService("", 5*time.Minute, 30*time.Minute, nil, profile)
			if err == nil {
				t.Fatalf("expected error for empty signing key in profile %q, got nil (svc=%v)", profile, svc)
			}
			if !errors.Is(err, ErrApprovalSigningKeyRequired) {
				t.Fatalf("expected ErrApprovalSigningKeyRequired, got %v", err)
			}
			if !strings.Contains(err.Error(), profile) {
				t.Fatalf("error message should contain profile name %q, got: %v", profile, err)
			}
		})
	}
}

func TestApprovalCapability_DevProfile_AllowsEphemeralKey(t *testing.T) {
	for _, profile := range []string{"dev", "", "custom-dev"} {
		t.Run("profile="+profile, func(t *testing.T) {
			svc, err := NewApprovalCapabilityService("", 5*time.Minute, 30*time.Minute, nil, profile)
			if err != nil {
				t.Fatalf("dev profile %q should allow empty signing key, got error: %v", profile, err)
			}
			if svc == nil {
				t.Fatal("expected non-nil service")
			}
			if len(svc.signingKey) < MinApprovalSigningKeyLength {
				t.Fatalf("expected generated key length >= %d, got %d", MinApprovalSigningKeyLength, len(svc.signingKey))
			}
		})
	}
}

func TestApprovalCapability_ProdProfile_AcceptsConfiguredKey(t *testing.T) {
	validKey := "prod-approval-signing-key-material-at-least-32"
	for _, profile := range []string{"prod", "prod_standard", "prod_regulated_hipaa"} {
		t.Run(profile, func(t *testing.T) {
			svc, err := NewApprovalCapabilityService(validKey, 5*time.Minute, 30*time.Minute, nil, profile)
			if err != nil {
				t.Fatalf("prod profile with valid key should succeed, got error: %v", err)
			}
			if svc == nil {
				t.Fatal("expected non-nil service")
			}
			if string(svc.signingKey) != validKey {
				t.Fatalf("expected signing key %q, got %q", validKey, string(svc.signingKey))
			}
		})
	}
}

func TestApprovalCapability_DevProfile_AcceptsConfiguredKey(t *testing.T) {
	validKey := "my-dev-key-at-least-thirty-two-chars-long"
	svc, err := NewApprovalCapabilityService(validKey, 5*time.Minute, 30*time.Minute, nil, "dev")
	if err != nil {
		t.Fatalf("dev profile with configured key should succeed, got error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
		return
	}
	if string(svc.signingKey) != validKey {
		t.Fatalf("expected signing key %q, got %q", validKey, string(svc.signingKey))
	}
}

func TestIsApprovalSigningKeyStrong(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{name: "missing", key: "", want: false},
		{name: "too-short", key: "short-key", want: false},
		{name: "known-weak-default", key: "poc-approval-signing-key-change-me", want: false},
		{name: "strong", key: "prod-approval-signing-key-material-at-least-32", want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsApprovalSigningKeyStrong(tc.key); got != tc.want {
				t.Fatalf("IsApprovalSigningKeyStrong(%q)=%t want %t", tc.key, got, tc.want)
			}
		})
	}
}

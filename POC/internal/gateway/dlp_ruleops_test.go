package gateway

import (
	"testing"
	"time"
)

func TestDLPRuleOpsLifecycleAndDigestPinning(t *testing.T) {
	mgr, scanner, err := newDLPRuleOpsManager()
	if err != nil {
		t.Fatalf("newDLPRuleOpsManager: %v", err)
	}

	now := time.Now().UTC()
	rsV2, created, err := mgr.upsertDraft(dlpRulesetUpsertRequest{
		Version:            "v2",
		SuspiciousPatterns: []string{`(?i)exfiltrate now`},
	}, now)
	if err != nil {
		t.Fatalf("upsert v2: %v", err)
	}
	if !created {
		t.Fatal("expected v2 to be created")
	}
	if rsV2.Digest == "" {
		t.Fatal("expected digest for v2 ruleset")
	}

	if _, err := mgr.promote("v2", now); err == nil {
		t.Fatal("expected promote to fail for unapproved/unsigned ruleset")
	}

	if _, err := mgr.approve("v2", "security@example.com", "sig-v2", now); err != nil {
		t.Fatalf("approve v2: %v", err)
	}
	activeV2, err := mgr.promote("v2", now)
	if err != nil {
		t.Fatalf("promote v2: %v", err)
	}
	if activeV2.State != dlpRulesetStateActive {
		t.Fatalf("expected active state, got %s", activeV2.State)
	}

	metaProvider, ok := scanner.(*managedDLPScanner)
	if !ok {
		t.Fatal("expected managedDLPScanner")
	}
	version, digest := metaProvider.ActiveRulesetMetadata()
	if version != "v2" || digest != activeV2.Digest {
		t.Fatalf("expected active metadata pinned to v2 digest=%s, got version=%s digest=%s", activeV2.Digest, version, digest)
	}

	if _, _, err := mgr.upsertDraft(dlpRulesetUpsertRequest{
		Version:            "v3",
		CredentialPatterns: []string{`(?i)supersecret`},
	}, now); err != nil {
		t.Fatalf("upsert v3: %v", err)
	}
	if _, err := mgr.approve("v3", "security@example.com", "sig-v3", now); err != nil {
		t.Fatalf("approve v3: %v", err)
	}
	if _, err := mgr.promote("v3", now); err != nil {
		t.Fatalf("promote v3: %v", err)
	}

	rolledBack, err := mgr.rollback("", now)
	if err != nil {
		t.Fatalf("rollback previous: %v", err)
	}
	if rolledBack.Version != "v2" {
		t.Fatalf("expected rollback to v2, got %s", rolledBack.Version)
	}
}

func TestDLPRulesetDigestDeterministic(t *testing.T) {
	a := dlpRuleset{
		Version:            "vX",
		CredentialPatterns: []string{`a`, `b`},
		PIIPatterns:        []string{`c`},
		SuspiciousPatterns: []string{`d`},
	}
	b := dlpRuleset{
		Version:            "vX",
		CredentialPatterns: []string{`a`, `b`},
		PIIPatterns:        []string{`c`},
		SuspiciousPatterns: []string{`d`},
	}
	d1, err := computeDLPRulesetDigest(a)
	if err != nil {
		t.Fatalf("compute digest a: %v", err)
	}
	d2, err := computeDLPRulesetDigest(b)
	if err != nil {
		t.Fatalf("compute digest b: %v", err)
	}
	if d1 != d2 {
		t.Fatalf("expected deterministic digest, got %s vs %s", d1, d2)
	}
}

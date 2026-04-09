// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/precinctcli/compliance"
)

func TestPrecinctComplianceCollect_SignSuccess(t *testing.T) {
	origCollect := complianceCollectEvidencePackage
	origSign := complianceSignEvidencePackage
	t.Cleanup(func() {
		complianceCollectEvidencePackage = origCollect
		complianceSignEvidencePackage = origSign
	})

	complianceCollectEvidencePackage = func(p compliance.CollectParams) (*compliance.CollectResult, error) {
		if p.Framework != "soc2" {
			t.Fatalf("expected framework soc2, got %+v", p)
		}
		return &compliance.CollectResult{EvidenceDir: "/tmp/evidence-soc2"}, nil
	}

	signCalled := false
	complianceSignEvidencePackage = func(p compliance.SignParams) (compliance.SignResult, error) {
		signCalled = true
		if p.EvidenceDir != "/tmp/evidence-soc2" {
			t.Fatalf("expected evidence dir passed to signer, got %+v", p)
		}
		return compliance.SignResult{
			ArchivePath:   "/tmp/evidence-soc2/evidence-package.tar.gz",
			SignaturePath: "/tmp/evidence-soc2/evidence-package.tar.gz.sig",
		}, nil
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"compliance", "collect", "--framework", "soc2", "--sign"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !signCalled {
		t.Fatalf("expected sign path to be called")
	}
	if strings.TrimSpace(stdout.String()) != "/tmp/evidence-soc2" {
		t.Fatalf("expected evidence dir on stdout, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Signed evidence package: /tmp/evidence-soc2/evidence-package.tar.gz.sig") {
		t.Fatalf("expected signed message on stderr, got %q", stderr.String())
	}
}

func TestPrecinctComplianceCollect_SignSkippedWarns(t *testing.T) {
	origCollect := complianceCollectEvidencePackage
	origSign := complianceSignEvidencePackage
	t.Cleanup(func() {
		complianceCollectEvidencePackage = origCollect
		complianceSignEvidencePackage = origSign
	})

	complianceCollectEvidencePackage = func(p compliance.CollectParams) (*compliance.CollectResult, error) {
		return &compliance.CollectResult{EvidenceDir: "/tmp/evidence-soc2"}, nil
	}
	complianceSignEvidencePackage = func(p compliance.SignParams) (compliance.SignResult, error) {
		return compliance.SignResult{
			Skipped:    true,
			SkipReason: "cosign not installed; skipping signing",
		}, nil
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"compliance", "collect", "--framework", "soc2", "--sign"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "WARNING: cosign not installed; skipping signing") {
		t.Fatalf("expected warning on stderr, got %q", stderr.String())
	}
}

func TestPrecinctComplianceCollect_FrameworkRequired(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"compliance", "collect"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--framework is required") {
		t.Fatalf("expected framework required error, got %q", stderr.String())
	}
}

func TestPrecinctComplianceCollect_OpenSearchRequiresSecretMaterial(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"compliance", "collect", "--framework", "soc2", "--audit-source", "opensearch"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "PRECINCT_OPENSEARCH_PASSWORD") {
		t.Fatalf("expected opensearch password env error, got %q", stderr.String())
	}
}

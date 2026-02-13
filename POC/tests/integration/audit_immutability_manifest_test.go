package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func pocRootForManifestTests(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../")
	if err != nil {
		t.Fatalf("resolve POC root: %v", err)
	}
	return root
}

func TestKustomizeBuildIncludesImmutableAuditSinkConfig(t *testing.T) {
	if _, err := exec.LookPath("kustomize"); err != nil {
		t.Skip("kustomize not installed")
	}

	root := pocRootForManifestTests(t)
	cmd := exec.Command("kustomize", "build", filepath.Join(root, "infra/eks/observability"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kustomize build failed: %v\nOutput:\n%s", err, string(out))
	}
	manifest := string(out)

	requiredSnippets := []string{
		"name: audit-s3-config",
		"mode: \"COMPLIANCE\"",
		"retention_days: 90",
		"enabled: true",
		"eks.amazonaws.com/role-arn:",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(manifest, snippet) {
			t.Fatalf("expected manifest to include %q", snippet)
		}
	}
}

func TestImmutableAuditSinkProofArtifactContainsVerificationFields(t *testing.T) {
	root := pocRootForManifestTests(t)
	scriptPath := filepath.Join(root, "tests/e2e/validate_immutable_audit_sink.sh")
	proofPath := filepath.Join(t.TempDir(), "immutable-audit-sink-proof.json")

	cmd := exec.Command("bash", scriptPath, "--output", proofPath)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("immutable audit sink validation script failed: %v\nOutput:\n%s", err, string(out))
	}

	b, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatalf("read proof artifact: %v", err)
	}

	var proof struct {
		SchemaVersion string `json:"schema_version"`
		Status        string `json:"status"`
		ImmutableSink struct {
			ConfigMapPresent               bool   `json:"configmap_present"`
			ObjectLockMode                 string `json:"object_lock_mode"`
			RetentionDays                  int    `json:"retention_days"`
			HashChainEnabled               bool   `json:"hash_chain_enabled"`
			IRSAAnnotationPresent          bool   `json:"irsa_annotation_present"`
			RequiredCorrelationFieldsReady bool   `json:"required_correlation_fields_present"`
		} `json:"immutable_sink_verification"`
	}
	if err := json.Unmarshal(b, &proof); err != nil {
		t.Fatalf("unmarshal proof artifact: %v", err)
	}

	if proof.SchemaVersion != "audit.immutable_sink.v1" {
		t.Fatalf("unexpected schema_version: %q", proof.SchemaVersion)
	}
	if proof.Status != "pass" {
		t.Fatalf("expected pass status, got %q", proof.Status)
	}
	if !proof.ImmutableSink.ConfigMapPresent {
		t.Fatalf("expected configmap_present=true")
	}
	if proof.ImmutableSink.ObjectLockMode != "COMPLIANCE" {
		t.Fatalf("expected COMPLIANCE mode, got %q", proof.ImmutableSink.ObjectLockMode)
	}
	if proof.ImmutableSink.RetentionDays < 90 {
		t.Fatalf("expected retention_days >= 90, got %d", proof.ImmutableSink.RetentionDays)
	}
	if !proof.ImmutableSink.HashChainEnabled {
		t.Fatalf("expected hash_chain_enabled=true")
	}
	if !proof.ImmutableSink.IRSAAnnotationPresent {
		t.Fatalf("expected irsa_annotation_present=true")
	}
	if !proof.ImmutableSink.RequiredCorrelationFieldsReady {
		t.Fatalf("expected required_correlation_fields_present=true")
	}
}

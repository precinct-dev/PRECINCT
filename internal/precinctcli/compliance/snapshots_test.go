package compliance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotConfig_CopiesExpectedFiles(t *testing.T) {
	root := t.TempDir()
	dst := filepath.Join(root, "out")

	mustWrite := func(rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	mustWrite("config/tool-registry.yaml")
	mustWrite("config/opa/tool_grants.yaml")
	mustWrite("config/risk_thresholds.yaml")
	mustWrite("config/spiffe-ids.yaml")
	mustWrite("config/opa/mcp_policy.rego")

	items, err := snapshotConfig(root, dst)
	if err != nil {
		t.Fatalf("snapshotConfig: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected snapshots, got none")
	}

	// Spot check renamed outputs exist.
	for _, name := range []string{"tool-registry.yaml", "tool_grants.yaml", "risk_thresholds.yaml", "spiffe-ids.yaml", "mcp_policy.rego"} {
		if _, err := os.Stat(filepath.Join(dst, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}
}

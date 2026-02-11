package unit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func upgradeScriptPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(pocRoot(t), "scripts", "upgrade.sh")
}

func runUpgradeScript(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{upgradeScriptPath(t)}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("upgrade.sh failed: %v\noutput:\n%s", err, string(out))
	}
}

func TestUpgrade_UpdateVersionsYaml(t *testing.T) {
	tmp := t.TempDir()
	versions := filepath.Join(tmp, "versions.yaml")
	if err := os.WriteFile(versions, []byte(`components:
  keydb:
    image: eqalpha/keydb
    version: "1.0.0"
    pinned: false
`), 0o644); err != nil {
		t.Fatalf("write versions.yaml: %v", err)
	}

	runUpgradeScript(t, "--_test_update_versions", versions, "keydb", "1.2.3")

	b, err := os.ReadFile(versions)
	if err != nil {
		t.Fatalf("read versions.yaml: %v", err)
	}
	if !strings.Contains(string(b), `version: "1.2.3"`) {
		t.Fatalf("expected updated version in versions.yaml; got:\n%s", string(b))
	}
}

func TestUpgrade_SnapshotRoundtrip(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "file.txt")
	if err := os.WriteFile(f, []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	runUpgradeScript(t, "--_test_snapshot_roundtrip", f)
}


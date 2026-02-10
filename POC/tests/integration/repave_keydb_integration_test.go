//go:build integration
// +build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRepaveKeyDB(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not installed: %v", err)
	}
	if _, err := exec.LookPath("make"); err != nil {
		t.Skipf("make not installed: %v", err)
	}

	dir := pocDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	run := func(name string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("command failed: %s %s\nerror: %v\noutput:\n%s", name, strings.Join(args, " "), err, string(out))
		}
		return string(out)
	}

	// Ensure KeyDB is running (this test is self-contained; it does not require the full stack).
	run("docker", "compose", "up", "-d", "--wait", "--wait-timeout", "180", "keydb")

	key := fmt.Sprintf("repave_test_key_%d", time.Now().UnixNano())
	want := "repave_test_value"

	run("docker", "compose", "exec", "-T", "keydb", "keydb-cli", "set", key, want)
	gotBefore := strings.TrimSpace(run("docker", "compose", "exec", "-T", "keydb", "keydb-cli", "get", key))
	if gotBefore != want {
		t.Fatalf("expected keydb get before repave to return %q, got %q", want, gotBefore)
	}

	// AC8: run the Makefile entry point that exercises scripts/repave.sh.
	out := run("make", "repave", "COMPONENT=keydb")
	if !strings.Contains(out, "[repave] current_image_hash=") {
		t.Fatalf("repave output missing pre-repave image hash marker; output:\n%s", out)
	}
	if !strings.Contains(out, "[repave] pulling fresh image") {
		t.Fatalf("repave output missing pull marker; output:\n%s", out)
	}

	pong := strings.TrimSpace(run("docker", "compose", "exec", "-T", "keydb", "keydb-cli", "ping"))
	if pong != "PONG" {
		t.Fatalf("expected PONG after repave, got %q", pong)
	}

	gotAfter := strings.TrimSpace(run("docker", "compose", "exec", "-T", "keydb", "keydb-cli", "get", key))
	if gotAfter != want {
		t.Fatalf("expected keydb get after repave to return %q, got %q", want, gotAfter)
	}

	// Cleanup test key so the persisted volume doesn't accumulate test data.
	run("docker", "compose", "exec", "-T", "keydb", "keydb-cli", "del", key)

	// AC6: repave state file updated.
	statePath := filepath.Join(dir, ".repave-state.json")
	b, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("expected repave state file at %s: %v", statePath, err)
	}

	var state struct {
		LastRepave map[string]struct {
			Timestamp string `json:"timestamp"`
			ImageHash string `json:"image_hash"`
			Health    string `json:"health"`
		} `json:"last_repave"`
	}
	if err := json.Unmarshal(b, &state); err != nil {
		t.Fatalf("failed to parse %s: %v", statePath, err)
	}

	keydbState, ok := state.LastRepave["keydb"]
	if !ok {
		t.Fatalf("expected last_repave.keydb to exist in %s", statePath)
	}
	if keydbState.Timestamp == "" || keydbState.ImageHash == "" || keydbState.Health == "" {
		t.Fatalf("expected last_repave.keydb fields to be populated, got: %+v", keydbState)
	}
	if keydbState.Health != "healthy" {
		t.Fatalf("expected last_repave.keydb.health=healthy, got %q", keydbState.Health)
	}
}


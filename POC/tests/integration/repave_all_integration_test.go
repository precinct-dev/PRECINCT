//go:build integration
// +build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRepaveAll_GeneratesReport_UpdatesState_AndPreservesKeyDBData(t *testing.T) {
	for _, bin := range []string{"docker", "make", "jq", "curl"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed: %v", bin, err)
		}
	}

	dir := pocDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	run := func(env []string, name string, args ...string) (string, int) {
		t.Helper()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return string(out), 0
		}
		if ee := (*exec.ExitError)(nil); errors.As(err, &ee) {
			return string(out), ee.ExitCode()
		}
		t.Fatalf("command failed unexpectedly: %s %s: %v\noutput:\n%s", name, strings.Join(args, " "), err, string(out))
		return "", 1
	}

	// Ensure Phoenix network exists and Phoenix stack is up (required by main stack).
	if out, code := run(nil, "make", "phoenix-up"); code != 0 {
		t.Fatalf("make phoenix-up failed:\n%s", out)
	}

	// The full POC stack can be expensive to (re)build in CI-like environments.
	// Follow the repo's existing integration-test convention: skip if the live stack
	// isn't already up (developers can run `make up` before `make test-integration`).
	// We still actively wait for health for a bounded time in case the stack is mid-start.
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not installed: %v", err)
	}

	waitHealthy := func(service string, timeout time.Duration) error {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			cmd := exec.CommandContext(ctx, "docker", "compose", "ps", "-q", service)
			cmd.Dir = dir
			b, _ := cmd.CombinedOutput()
			cid := strings.TrimSpace(string(b))
			if cid == "" {
				time.Sleep(1 * time.Second)
				continue
			}
			ins := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Health.Status}}", cid)
			ins.Dir = dir
			hb, _ := ins.CombinedOutput()
			if strings.TrimSpace(string(hb)) == "healthy" {
				return nil
			}
			time.Sleep(1 * time.Second)
		}
		return fmt.Errorf("%s not healthy within %s", service, timeout)
	}

	// Wait for the core services needed by repave-all (skip if not up).
	for _, svc := range []string{"spire-server", "spire-agent", "keydb", "spike-keeper-1", "spike-nexus", "mock-mcp-server", "mock-guard-model", "mcp-security-gateway"} {
		if err := waitHealthy(svc, 2*time.Minute); err != nil {
			t.Skipf("compose stack not healthy; skipping repave-all integration test. Start it with `make up`. (%v)", err)
		}
	}
	// Gateway should also respond.
	{
		client := &http.Client{Timeout: 2 * time.Second}
		deadline := time.Now().Add(2 * time.Minute)
		for {
			resp, err := client.Get("http://localhost:9090/health")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Skipf("gateway /health not reachable; skipping repave-all integration test: %v", err)
			}
			time.Sleep(1 * time.Second)
		}
	}

	// Remove runtime artifacts to make assertions deterministic.
	_ = os.Remove(filepath.Join(dir, ".repave-state.json"))
	_ = os.RemoveAll(filepath.Join(dir, "reports"))

	// Seed KeyDB with a key to prove volume preservation across full-stack repave.
	key := fmt.Sprintf("repave_all_test_key_%d", time.Now().UnixNano())
	want := "repave_all_test_value"
	if out, code := run(nil, "docker", "compose", "exec", "-T", "keydb", "keydb-cli", "set", key, want); code != 0 {
		t.Skipf("could not seed keydb (stack may be unstable):\n%s", out)
	}

	// Run full-stack repave (AC1-4,6-8).
	out, code := run(nil, "make", "repave")
	if code != 0 {
		t.Fatalf("make repave failed:\n%s", out)
	}

	// Order check: verify the expected ordered steps appear in output in sequence.
	expectedOrder := []string{
		"[repave-all] step 1/9 repaving spire-server",
		"[repave-all] step 2/9 repaving spire-agent",
		"[repave-all] step 3/9 repaving keydb",
		"[repave-all] step 4/9 repaving spike-keeper-1",
		"[repave-all] step 5/9 repaving spike-nexus",
		"[repave-all] step 6/9 repaving mcp-security-gateway",
		"[repave-all] step 7/9 repaving mock-mcp-server",
		"[repave-all] step 8/9 repaving otel-collector",
		"[repave-all] step 9/9 repaving phoenix",
	}
	last := -1
	for _, marker := range expectedOrder {
		i := strings.Index(out, marker)
		if i < 0 {
			t.Fatalf("repave output missing order marker %q\noutput:\n%s", marker, out)
		}
		if i <= last {
			t.Fatalf("repave order marker %q appeared out of order\noutput:\n%s", marker, out)
		}
		last = i
	}

	// Report check (AC6): file exists and includes table header.
	reportsDir := filepath.Join(dir, "reports")
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		t.Fatalf("expected reports dir at %s: %v", reportsDir, err)
	}
	var reportPath string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), "repave-") && strings.HasSuffix(e.Name(), ".md") {
			reportPath = filepath.Join(reportsDir, e.Name())
			break
		}
	}
	if reportPath == "" {
		t.Fatalf("expected a repave report file in %s; found %d entries", reportsDir, len(entries))
	}
	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read report %s: %v", reportPath, err)
	}
	report := string(reportBytes)
	if !strings.Contains(report, "| Container | Image Hash Before | Image Hash After | Health | Duration |") {
		t.Fatalf("report missing table header:\n%s", report)
	}

	// State check (AC7): .repave-state.json updated for all containers.
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
	wantComps := []string{"spire-server", "spire-agent", "keydb", "spike-keeper-1", "spike-nexus", "mcp-security-gateway", "mock-mcp-server", "otel-collector", "phoenix"}
	for _, c := range wantComps {
		v, ok := state.LastRepave[c]
		if !ok {
			t.Fatalf("expected last_repave.%s to exist in %s", c, statePath)
		}
		if v.Timestamp == "" || v.ImageHash == "" || v.Health == "" {
			t.Fatalf("expected last_repave.%s fields populated, got: %+v", c, v)
		}
	}

	// Volume preservation (AC5): KeyDB data should still be present after repave.
	if out, code := run(nil, "docker", "compose", "exec", "-T", "keydb", "keydb-cli", "get", key); code != 0 {
		t.Fatalf("failed to read keydb after repave:\n%s", out)
	} else {
		got := strings.TrimSpace(out)
		if got != want {
			t.Fatalf("expected keydb get after repave to return %q, got %q", want, got)
		}
	}

	// Cleanup.
	_, _ = run(nil, "docker", "compose", "exec", "-T", "keydb", "keydb-cli", "del", key)
}

func TestRepaveAll_StopOnFailure_Simulated(t *testing.T) {
	for _, bin := range []string{"docker", "make", "jq"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed: %v", bin, err)
		}
	}

	dir := pocDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "make", "phoenix-up")
	cmd.Dir = dir
	_ = cmd.Run() // best-effort

	// Bring up the main stack using the repo's resilient readiness path.
	up := exec.CommandContext(ctx, "make", "up")
	up.Dir = dir
	if out, err := up.CombinedOutput(); err != nil {
		t.Skipf("compose stack not healthy; skipping stop-on-failure test.\nOutput:\n%s", string(out))
	}

	_ = os.Remove(filepath.Join(dir, ".repave-state.json"))
	_ = os.RemoveAll(filepath.Join(dir, "reports"))

	// Simulate failure at keydb so the script must stop before spike-keeper-1.
	failEnv := append(os.Environ(), "REPAVE_SIMULATE_HEALTH_FAIL_COMPONENT=keydb")
	repave := exec.CommandContext(ctx, "make", "repave")
	repave.Dir = dir
	repave.Env = failEnv
	outBytes, err := repave.CombinedOutput()
	if err == nil {
		t.Fatalf("expected make repave to fail under simulated failure; output:\n%s", string(outBytes))
	}
	out := string(outBytes)

	if !strings.Contains(out, "stop-on-failure") {
		t.Fatalf("expected stop-on-failure message in output:\n%s", out)
	}
	if strings.Contains(out, "repaving spike-keeper-1") {
		t.Fatalf("expected repave to stop before spike-keeper-1; output:\n%s", out)
	}

	// Report should still be generated (partial, but present).
	reportsDir := filepath.Join(dir, "reports")
	entries, _ := os.ReadDir(reportsDir)
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "repave-") && strings.HasSuffix(e.Name(), ".md") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a repave report file in %s after failure", reportsDir)
	}

	// State file should NOT record the failing component (since failure happens before update_state).
	b, err2 := os.ReadFile(filepath.Join(dir, ".repave-state.json"))
	if err2 == nil {
		var state struct {
			LastRepave map[string]any `json:"last_repave"`
		}
		_ = json.Unmarshal(b, &state)
		if _, ok := state.LastRepave["keydb"]; ok {
			t.Fatalf("expected keydb not to be recorded in .repave-state.json when simulated health failure triggers")
		}
	}
}

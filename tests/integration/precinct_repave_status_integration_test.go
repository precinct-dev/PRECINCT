//go:build integration
// +build integration

package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrecinctRepaveStatusIntegration_JSON(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	currentHash, err := currentServiceImageHash(t, "keydb")
	if err != nil {
		t.Fatalf("resolve current keydb image hash: %v", err)
	}

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".repave-state.json")
	state := map[string]any{
		"last_repave": map[string]any{
			"keydb": map[string]any{
				"timestamp":  time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339),
				"image_hash": currentHash,
				"health":     "healthy",
			},
		},
	}
	b, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(statePath, b, 0o644); err != nil {
		t.Fatalf("write state file: %v", err)
	}

	cmd := exec.Command("go", "run", "./cli/precinct", "repave", "status", "--state-file", statePath, "--format", "json")
	cmd.Dir = pocDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("precinct repave status failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var out struct {
		Containers []struct {
			Name       string   `json:"name"`
			LastRepave string   `json:"last_repave"`
			HashMatch  bool     `json:"hash_match"`
			Health     string   `json:"health"`
			AgeHours   int64    `json:"age_hours"`
			Warnings   []string `json:"warnings"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("invalid json output: %v raw=%q", err, stdout.String())
	}
	if len(out.Containers) == 0 {
		t.Fatalf("expected at least one container in repave status output")
	}

	var keydbFound bool
	var neverFound bool
	for _, c := range out.Containers {
		if c.Name == "keydb" {
			keydbFound = true
			if c.LastRepave == "NEVER" || !c.HashMatch {
				t.Fatalf("expected keydb to use state-file repave record and hash match, got %+v", c)
			}
			if c.AgeHours < 1 {
				t.Fatalf("expected keydb age >= 1h, got %+v", c)
			}
			if strings.TrimSpace(c.Health) == "" {
				t.Fatalf("expected keydb health status, got %+v", c)
			}
		}
		if c.LastRepave == "NEVER" {
			neverFound = true
		}
	}

	if !keydbFound {
		t.Fatalf("expected keydb entry in repave status output")
	}
	if !neverFound {
		t.Fatalf("expected at least one NEVER entry for non-repaved containers")
	}
}

func currentServiceImageHash(t *testing.T, service string) (string, error) {
	t.Helper()
	cmd := composeCommand("ps", "--format", "json", service)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row struct {
			Labels string `json:"Labels"`
			Image  string `json:"Image"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		for _, pair := range strings.Split(row.Labels, ",") {
			pair = strings.TrimSpace(pair)
			if strings.HasPrefix(pair, "com.docker.compose.image=") {
				return strings.TrimPrefix(pair, "com.docker.compose.image="), nil
			}
		}
		if strings.TrimSpace(row.Image) != "" {
			return strings.TrimSpace(row.Image), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", os.ErrNotExist
}

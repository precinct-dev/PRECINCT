package agw

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectRepaveStatus_AgeAndNeverRepaved(t *testing.T) {
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".repave-state.json")
	ts := time.Date(2026, 2, 9, 10, 0, 0, 0, time.UTC)
	state := RepaveStateFile{
		LastRepave: map[string]RepaveStateRecord{
			"keydb": {
				Timestamp: ts.Format(time.RFC3339),
				ImageHash: "sha256:abc12345",
				Health:    "healthy",
			},
		},
	}
	b, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(statePath, b, 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}

	runner := fakeRepaveRunner{
		stdout: strings.Join([]string{
			`{"Service":"keydb","Health":"healthy","Labels":"com.docker.compose.image=sha256:abc12345","State":"running"}`,
			`{"Service":"mcp-security-gateway","Health":"healthy","Labels":"com.docker.compose.image=sha256:def67890","State":"running"}`,
		}, "\n"),
	}

	out, err := CollectRepaveStatus(context.Background(), RepaveStatusParams{
		StateFile: statePath,
		Now:       ts.Add(51 * time.Hour),
		Runner:    runner,
	})
	if err != nil {
		t.Fatalf("CollectRepaveStatus: %v", err)
	}
	if len(out.Containers) != 2 {
		t.Fatalf("expected 2 containers, got %+v", out.Containers)
	}

	byName := map[string]RepaveContainerStatus{}
	for _, c := range out.Containers {
		byName[c.Name] = c
	}

	keydb := byName["keydb"]
	if keydb.LastRepave != ts.Format(time.RFC3339) {
		t.Fatalf("unexpected keydb last repave: %+v", keydb)
	}
	if !keydb.HashMatch || keydb.AgeHours != 51 {
		t.Fatalf("expected keydb hash match and age=51h, got %+v", keydb)
	}

	gw := byName["mcp-security-gateway"]
	if gw.LastRepave != "NEVER" {
		t.Fatalf("expected NEVER for non-repaved container, got %+v", gw)
	}
	if !contains(gw.Warnings, "never_repaved") {
		t.Fatalf("expected never_repaved warning, got %+v", gw.Warnings)
	}
}

func TestCollectRepaveStatus_HashMismatchWarning(t *testing.T) {
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".repave-state.json")
	state := RepaveStateFile{
		LastRepave: map[string]RepaveStateRecord{
			"keydb": {
				Timestamp: "2026-02-10T00:00:00Z",
				ImageHash: "sha256:oldhash",
				Health:    "healthy",
			},
		},
	}
	b, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(statePath, b, 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}

	runner := fakeRepaveRunner{
		stdout: `{"Service":"keydb","Health":"healthy","Labels":"com.docker.compose.image=sha256:newhash","State":"running"}`,
	}
	out, err := CollectRepaveStatus(context.Background(), RepaveStatusParams{
		StateFile: statePath,
		Now:       time.Date(2026, 2, 11, 0, 0, 0, 0, time.UTC),
		Runner:    runner,
	})
	if err != nil {
		t.Fatalf("CollectRepaveStatus: %v", err)
	}
	if len(out.Containers) != 1 {
		t.Fatalf("expected 1 container, got %+v", out.Containers)
	}
	got := out.Containers[0]
	if got.HashMatch {
		t.Fatalf("expected hash mismatch, got %+v", got)
	}
	if !contains(got.Warnings, "hash_mismatch") {
		t.Fatalf("expected hash_mismatch warning, got %+v", got)
	}
}

func TestRenderRepaveStatusOutputs(t *testing.T) {
	out := RepaveStatusOutput{
		Containers: []RepaveContainerStatus{
			{
				Name:        "gateway",
				LastRepave:  "NEVER",
				ImageHash:   "sha256:abcdef",
				CurrentHash: "sha256:abcdef",
				HashMatch:   false,
				Health:      "healthy",
				Warnings:    []string{"never_repaved"},
			},
		},
	}

	jsonOut, err := RenderRepaveStatusJSON(out)
	if err != nil {
		t.Fatalf("RenderRepaveStatusJSON: %v", err)
	}
	var parsed struct {
		Containers []map[string]any `json:"containers"`
	}
	if err := json.Unmarshal(jsonOut, &parsed); err != nil {
		t.Fatalf("parse json output: %v raw=%q", err, string(jsonOut))
	}
	if len(parsed.Containers) != 1 {
		t.Fatalf("unexpected json output: %+v", parsed)
	}

	tableOut, err := RenderRepaveStatusTable(out)
	if err != nil {
		t.Fatalf("RenderRepaveStatusTable: %v", err)
	}
	if !strings.Contains(tableOut, "CONTAINER") || !strings.Contains(tableOut, "gateway") || !strings.Contains(tableOut, "WARNING:") {
		t.Fatalf("unexpected table output: %q", tableOut)
	}
}

type fakeRepaveRunner struct {
	stdout string
	stderr string
	err    error
}

func (f fakeRepaveRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	return f.stdout, f.stderr, f.err
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/agw"
)

func TestAgwRepaveStatus_JSON(t *testing.T) {
	orig := collectRepaveStatus
	t.Cleanup(func() { collectRepaveStatus = orig })

	collectRepaveStatus = func(_ctx context.Context, p agw.RepaveStatusParams) (agw.RepaveStatusOutput, error) {
		if p.StateFile != ".repave-state.json" {
			t.Fatalf("unexpected state file: %+v", p)
		}
		return agw.RepaveStatusOutput{
			Containers: []agw.RepaveContainerStatus{
				{
					Name:       "keydb",
					LastRepave: "2026-02-09T10:00:00Z",
					ImageHash:  "sha256:abc123",
					Health:     "healthy",
					AgeHours:   51,
				},
			},
		}, nil
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"repave", "status", "--format", "json"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed struct {
		Containers []struct {
			Name       string `json:"name"`
			LastRepave string `json:"last_repave"`
			AgeHours   int64  `json:"age_hours"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json output: %v raw=%q", err, stdout.String())
	}
	if len(parsed.Containers) != 1 || parsed.Containers[0].Name != "keydb" {
		t.Fatalf("unexpected parsed output: %+v", parsed)
	}
}

func TestAgwRepaveStatus_TableDefault(t *testing.T) {
	orig := collectRepaveStatus
	t.Cleanup(func() { collectRepaveStatus = orig })

	collectRepaveStatus = func(_ctx context.Context, p agw.RepaveStatusParams) (agw.RepaveStatusOutput, error) {
		return agw.RepaveStatusOutput{
			Containers: []agw.RepaveContainerStatus{
				{
					Name:       "gateway",
					LastRepave: "NEVER",
					ImageHash:  "sha256:def456",
					Health:     "healthy",
					Warnings:   []string{"never_repaved"},
				},
			},
		}, nil
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"repave", "status"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "CONTAINER") || !strings.Contains(out, "gateway") || !strings.Contains(out, "WARNING:") {
		t.Fatalf("unexpected table output: %q", out)
	}
}

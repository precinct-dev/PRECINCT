package agw

import (
	"strings"
	"testing"
	"time"
)

func TestRenderLoopRunsOutputs(t *testing.T) {
	out := LoopRunsOutput{
		Status: "ok",
		Runs: []LoopRunStatus{
			{
				RunID:      "run-1",
				State:      "RUNNING",
				HaltReason: "",
				Usage: LoopUsageSnapshot{
					Steps:      2,
					ToolCalls:  1,
					ModelCalls: 1,
					RiskScore:  0.3,
				},
				UpdatedAt: time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC),
			},
		},
	}

	jsonBytes, err := RenderLoopRunsJSON(out)
	if err != nil {
		t.Fatalf("RenderLoopRunsJSON err=%v", err)
	}
	if !strings.Contains(string(jsonBytes), `"run_id":"run-1"`) {
		t.Fatalf("unexpected JSON output: %s", string(jsonBytes))
	}

	table, err := RenderLoopRunsTable(out)
	if err != nil {
		t.Fatalf("RenderLoopRunsTable err=%v", err)
	}
	if !strings.Contains(table, "RUN_ID") || !strings.Contains(table, "run-1") {
		t.Fatalf("unexpected table output:\n%s", table)
	}
}

package agw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"text/tabwriter"
)

func RenderLoopRunsJSON(out LoopRunsOutput) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderLoopRunsTable(out LoopRunsOutput) (string, error) {
	records := out.Runs
	if out.Run != nil {
		records = []LoopRunStatus{*out.Run}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].RunID < records[j].RunID })

	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "RUN_ID\tSTATE\tHALT_REASON\tSTEPS\tTOOL_CALLS\tMODEL_CALLS\tRISK_SCORE\tUPDATED_AT")
	for _, r := range records {
		_, _ = fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%d\t%d\t%d\t%.2f\t%s\n",
			r.RunID,
			r.State,
			emptyDash(r.HaltReason),
			r.Usage.Steps,
			r.Usage.ToolCalls,
			r.Usage.ModelCalls,
			r.Usage.RiskScore,
			r.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		)
	}
	_ = tw.Flush()
	return buf.String(), nil
}

func emptyDash(s string) string {
	if s == "" {
		return "--"
	}
	return s
}

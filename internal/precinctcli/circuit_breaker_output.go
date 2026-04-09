// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"text/tabwriter"
	"time"
)

type CircuitBreakersOutput struct {
	CircuitBreakers []CircuitBreakerEntry `json:"circuit_breakers"`
}

func RenderCircuitBreakersJSON(out CircuitBreakersOutput) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderCircuitBreakersTable(out CircuitBreakersOutput) (string, error) {
	// Stable-ish output for tests/demos.
	sort.Slice(out.CircuitBreakers, func(i, j int) bool { return out.CircuitBreakers[i].Tool < out.CircuitBreakers[j].Tool })

	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TOOL\tSTATE\tFAILURES\tTHRESHOLD\tRESET_TIMEOUT\tSINCE")

	now := time.Now()
	for _, cb := range out.CircuitBreakers {
		since := "--"
		if cb.LastStateChange != nil {
			d := now.Sub(cb.LastStateChange.UTC()).Truncate(time.Second)
			if d < 0 {
				d = 0
			}
			since = fmt.Sprintf("%s ago", d)
		}
		reset := fmt.Sprintf("%ds", cb.ResetTimeoutSec)
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\n", cb.Tool, cb.State, cb.Failures, cb.Threshold, reset, since)
	}

	_ = tw.Flush()
	return buf.String(), nil
}

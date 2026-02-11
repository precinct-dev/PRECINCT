package agw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"text/tabwriter"
)

func RenderCircuitBreakerResetJSON(out CircuitBreakersResetOutput) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderCircuitBreakerResetTable(out CircuitBreakersResetOutput) (string, error) {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TOOL\tPREVIOUS_STATE\tNEW_STATE")
	for _, e := range out.Reset {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Tool, e.PreviousState, e.NewState)
	}
	_ = tw.Flush()
	return buf.String(), nil
}

package agw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
)

// ComponentStatus is the structured output contract for agw status.
type ComponentStatus struct {
	Name    string         `json:"name"`
	Status  string         `json:"status"`
	Details map[string]any `json:"details,omitempty"`
}

type StatusOutput struct {
	Components []ComponentStatus `json:"components"`
}

func RenderJSON(out StatusOutput) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	// Make CLI output friendly to terminals/pipes.
	return append(b, '\n'), nil
}

func RenderTable(out StatusOutput) (string, error) {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "COMPONENT\tSTATUS\tDETAILS")
	for _, c := range out.Components {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Name, colorizeStatus(strings.ToUpper(c.Status), c.Status), detailsToString(c.Details))
	}
	_ = tw.Flush()
	return buf.String(), nil
}

func colorizeStatus(label, status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "ok":
		return "\x1b[32m" + label + "\x1b[0m"
	case "degraded":
		return "\x1b[33m" + label + "\x1b[0m"
	case "fail":
		return "\x1b[31m" + label + "\x1b[0m"
	default:
		return label
	}
}

func detailsToString(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}

	// Stable-ish output for tests and demos.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, formatAny(m[k])))
	}
	return strings.Join(parts, " ")
}

func formatAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		// Use JSON for nested objects (e.g. circuit_breaker={"state":"closed"}).
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

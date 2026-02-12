package agw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
)

type SessionResetOutput struct {
	Mode     string   `json:"mode"`
	SPIFFEID string   `json:"spiffe_id,omitempty"`
	Deleted  int64    `json:"deleted"`
	Keys     []string `json:"keys"`
}

func RenderSessionResetJSON(out SessionResetOutput) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderSessionResetTable(out SessionResetOutput) (string, error) {
	target := "all sessions"
	if strings.TrimSpace(out.SPIFFEID) != "" {
		target = out.SPIFFEID
	}
	keys := "-"
	if len(out.Keys) > 0 {
		keys = strings.Join(out.Keys, ",")
	}

	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TARGET\tDELETED\tKEYS")
	_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\n", target, out.Deleted, keys)
	_ = tw.Flush()
	return buf.String(), nil
}

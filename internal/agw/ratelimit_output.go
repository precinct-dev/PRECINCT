package agw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"text/tabwriter"
)

type RateLimitEntry struct {
	SPIFFEID    string `json:"spiffe_id"`
	Remaining   int    `json:"remaining"`
	Limit       int    `json:"limit"`
	Burst       int    `json:"burst"`
	TTLSeconds  int    `json:"ttl_seconds"`
	ObservedKey string `json:"-"`
}

type RateLimitOutput struct {
	RateLimits []RateLimitEntry `json:"rate_limits"`
}

func RenderRateLimitJSON(out RateLimitOutput) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderRateLimitTable(out RateLimitOutput) (string, error) {
	// Stable-ish output for tests/demos.
	sort.Slice(out.RateLimits, func(i, j int) bool { return out.RateLimits[i].SPIFFEID < out.RateLimits[j].SPIFFEID })

	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SPIFFE_ID\tREMAINING\tLIMIT\tBURST\tTTL")
	for _, rl := range out.RateLimits {
		ttl := fmt.Sprintf("%ds", rl.TTLSeconds)
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\n", rl.SPIFFEID, rl.Remaining, rl.Limit, rl.Burst, ttl)
	}
	_ = tw.Flush()
	return buf.String(), nil
}

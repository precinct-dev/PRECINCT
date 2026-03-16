package agw

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// AuditSearchFilter defines filters for searching audit entries.
type AuditSearchFilter struct {
	DecisionID string
	SPIFFEID   string
	Tool       string
	DeniedOnly bool
	Last       string
	Now        time.Time
}

// LoadAuditEntries loads audit entries from either docker compose logs (default)
// or a local JSONL file.
func LoadAuditEntries(ctx context.Context, source, projectRoot, auditLogPath string) ([]map[string]any, error) {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "docker":
		return loadAuditFromDockerComposeLogs(ctx, projectRoot)
	case "file":
		if strings.TrimSpace(auditLogPath) == "" {
			auditLogPath = "/tmp/audit.jsonl"
		}
		return loadAuditJSONLEntries(auditLogPath)
	default:
		return nil, fmt.Errorf("invalid --source %q (expected docker|file)", source)
	}
}

// ParseAuditWindow parses --last values. Supports time.ParseDuration syntax
// plus day suffixes (e.g. 7d).
func ParseAuditWindow(v string) (time.Duration, error) {
	s := strings.TrimSpace(strings.ToLower(v))
	if s == "" {
		return 0, nil
	}

	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid --last %q (expected 5m, 1h, 24h, 7d)", v)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid --last %q (expected 5m, 1h, 24h, 7d)", v)
	}
	return d, nil
}

// FilterAuditEntries applies decision-id, SPIFFE ID, denied-only, tool, and time-window filters.
func FilterAuditEntries(entries []map[string]any, filter AuditSearchFilter) ([]map[string]any, error) {
	window, err := ParseAuditWindow(filter.Last)
	if err != nil {
		return nil, err
	}

	now := filter.Now
	if now.IsZero() {
		now = time.Now()
	}
	cutoff := now.Add(-window)

	out := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(filter.DecisionID) != "" && getString(entry, "decision_id") != filter.DecisionID {
			continue
		}
		if strings.TrimSpace(filter.SPIFFEID) != "" && getString(entry, "spiffe_id") != filter.SPIFFEID {
			continue
		}
		if strings.TrimSpace(filter.Tool) != "" && getString(entry, "tool") != filter.Tool {
			continue
		}
		if filter.DeniedOnly && !isDeniedEntry(entry) {
			continue
		}

		if window > 0 {
			ts, ok := parseEntryTimestamp(entry)
			if !ok || ts.Before(cutoff) {
				continue
			}
		}

		out = append(out, entry)
	}

	return out, nil
}

// RenderAuditSearchJSON renders entries as a JSON array.
func RenderAuditSearchJSON(entries []map[string]any) ([]byte, error) {
	b, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// RenderAuditSearchTable renders a compact, human-readable table.
func RenderAuditSearchTable(entries []map[string]any) (string, error) {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TIMESTAMP\tDECISION_ID\tSPIFFE_ID\tTOOL\tRESULT\tCODE")
	for _, e := range entries {
		code := ""
		if v, ok := getInt(e, "status_code"); ok {
			code = strconv.Itoa(v)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			getString(e, "timestamp"),
			getString(e, "decision_id"),
			getString(e, "spiffe_id"),
			getString(e, "tool"),
			getString(e, "result"),
			code,
		)
	}
	_ = tw.Flush()
	return buf.String(), nil
}

func loadAuditJSONLEntries(path string) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()
	return parseAuditJSONLLines(f)
}

func loadAuditFromDockerComposeLogs(ctx context.Context, projectRoot string) ([]map[string]any, error) {
	cmd := exec.CommandContext(ctx, "docker", "compose", "logs", "--no-log-prefix", "precinct-gateway")
	cmd.Dir = projectRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker compose logs failed: %w (output=%s)", err, string(out))
	}
	return parseAuditJSONLLines(bytes.NewReader(out))
}

func parseAuditJSONLLines(r io.Reader) ([]map[string]any, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var entries []map[string]any
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if i := strings.IndexByte(line, '{'); i >= 0 {
			line = line[i:]
		} else {
			continue
		}

		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		entries = append(entries, m)
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func parseEntryTimestamp(entry map[string]any) (time.Time, bool) {
	raw := getString(entry, "timestamp")
	if raw == "" {
		return time.Time{}, false
	}

	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

func getString(entry map[string]any, key string) string {
	v, ok := entry[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func getInt(entry map[string]any, key string) (int, bool) {
	v, ok := entry[key]
	if !ok || v == nil {
		return 0, false
	}
	switch t := v.(type) {
	case int:
		return t, true
	case int32:
		return int(t), true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

func isDeniedEntry(entry map[string]any) bool {
	if strings.EqualFold(getString(entry, "result"), "denied") {
		return true
	}
	if code, ok := getInt(entry, "status_code"); ok && code >= 400 {
		return true
	}
	return false
}

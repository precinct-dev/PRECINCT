package precinctcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/redis/go-redis/v9"
)

type SessionEntry struct {
	SessionID     string  `json:"session_id"`
	SPIFFEID      string  `json:"spiffe_id"`
	RiskScore     float64 `json:"risk_score"`
	ToolsAccessed int     `json:"tools_accessed"`
	TTLSeconds    int     `json:"ttl_seconds"`
}

type SessionsOutput struct {
	Sessions []SessionEntry `json:"sessions"`
}

func (k *KeyDB) ListSessions(ctx context.Context, spiffeID string) ([]SessionEntry, error) {
	if k.composeService != "" {
		return k.composeListSessions(ctx, spiffeID)
	}

	var cursor uint64
	out := make([]SessionEntry, 0, 32)
	for {
		keys, next, err := k.client.Scan(ctx, cursor, "session:*", 200).Result()
		if err != nil {
			return nil, fmt.Errorf("scan session keys: %w", err)
		}
		for _, key := range keys {
			e, ok, err := k.sessionEntryFromKey(ctx, key, spiffeID)
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, e)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SPIFFEID == out[j].SPIFFEID {
			return out[i].SessionID < out[j].SessionID
		}
		return out[i].SPIFFEID < out[j].SPIFFEID
	})
	return out, nil
}

func (k *KeyDB) composeListSessions(ctx context.Context, spiffeID string) ([]SessionEntry, error) {
	keys, err := k.composeScan(ctx, "session:*")
	if err != nil {
		return nil, fmt.Errorf("scan session keys: %w", err)
	}

	out := make([]SessionEntry, 0, len(keys))
	for _, key := range keys {
		e, ok, err := k.composeSessionEntryFromKey(ctx, key, spiffeID)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, e)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].SPIFFEID == out[j].SPIFFEID {
			return out[i].SessionID < out[j].SessionID
		}
		return out[i].SPIFFEID < out[j].SPIFFEID
	})
	return out, nil
}

func (k *KeyDB) sessionEntryFromKey(ctx context.Context, key, spiffeFilter string) (SessionEntry, bool, error) {
	if !strings.HasPrefix(key, "session:") || strings.HasSuffix(key, ":actions") {
		return SessionEntry{}, false, nil
	}
	rest := strings.TrimPrefix(key, "session:")
	idx := strings.LastIndex(rest, ":")
	if idx <= 0 || idx+1 >= len(rest) {
		return SessionEntry{}, false, nil
	}
	spiffeID := rest[:idx]
	sessionID := rest[idx+1:]
	if strings.TrimSpace(spiffeFilter) != "" && spiffeID != strings.TrimSpace(spiffeFilter) {
		return SessionEntry{}, false, nil
	}

	raw, err := k.client.Get(ctx, key).Bytes()
	if err != nil {
		// key disappeared during scan; ignore.
		if errors.Is(err, redis.Nil) {
			return SessionEntry{}, false, nil
		}
		return SessionEntry{}, false, fmt.Errorf("get session key %s: %w", key, err)
	}

	var session struct {
		RiskScore float64 `json:"RiskScore"`
	}
	if err := json.Unmarshal(raw, &session); err != nil {
		return SessionEntry{}, false, fmt.Errorf("unmarshal session key %s: %w", key, err)
	}

	actionsKey := key + ":actions"
	toolsAccessed, err := k.client.LLen(ctx, actionsKey).Result()
	if err != nil {
		return SessionEntry{}, false, fmt.Errorf("llen actions key %s: %w", actionsKey, err)
	}

	ttl, err := k.client.TTL(ctx, key).Result()
	if err != nil {
		return SessionEntry{}, false, fmt.Errorf("ttl for session key %s: %w", key, err)
	}
	ttlSeconds := int(ttl.Seconds())
	if ttlSeconds < 0 {
		ttlSeconds = 0
	}

	return SessionEntry{
		SessionID:     sessionID,
		SPIFFEID:      spiffeID,
		RiskScore:     session.RiskScore,
		ToolsAccessed: int(toolsAccessed),
		TTLSeconds:    ttlSeconds,
	}, true, nil
}

func (k *KeyDB) composeSessionEntryFromKey(ctx context.Context, key, spiffeFilter string) (SessionEntry, bool, error) {
	if !strings.HasPrefix(key, "session:") || strings.HasSuffix(key, ":actions") {
		return SessionEntry{}, false, nil
	}
	rest := strings.TrimPrefix(key, "session:")
	idx := strings.LastIndex(rest, ":")
	if idx <= 0 || idx+1 >= len(rest) {
		return SessionEntry{}, false, nil
	}
	spiffeID := rest[:idx]
	sessionID := rest[idx+1:]
	if strings.TrimSpace(spiffeFilter) != "" && spiffeID != strings.TrimSpace(spiffeFilter) {
		return SessionEntry{}, false, nil
	}

	raw, ok, err := k.composeGet(ctx, key)
	if err != nil {
		return SessionEntry{}, false, fmt.Errorf("get session key %s: %w", key, err)
	}
	if !ok {
		return SessionEntry{}, false, nil
	}

	var session struct {
		RiskScore float64 `json:"RiskScore"`
	}
	if err := json.Unmarshal([]byte(raw), &session); err != nil {
		return SessionEntry{}, false, fmt.Errorf("unmarshal session key %s: %w", key, err)
	}

	toolsAccessed, err := k.composeLLen(ctx, key+":actions")
	if err != nil {
		return SessionEntry{}, false, fmt.Errorf("llen actions key %s: %w", key+":actions", err)
	}

	ttlSeconds, err := k.composeTTL(ctx, key)
	if err != nil {
		return SessionEntry{}, false, fmt.Errorf("ttl for session key %s: %w", key, err)
	}
	if ttlSeconds < 0 {
		ttlSeconds = 0
	}

	return SessionEntry{
		SessionID:     sessionID,
		SPIFFEID:      spiffeID,
		RiskScore:     session.RiskScore,
		ToolsAccessed: int(toolsAccessed),
		TTLSeconds:    ttlSeconds,
	}, true, nil
}

func RenderSessionsJSON(out SessionsOutput) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderSessionsTable(out SessionsOutput) (string, error) {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SESSION_ID\tSPIFFE_ID\tRISK_SCORE\tTOOLS_ACCESSED\tTTL")
	for _, s := range out.Sessions {
		_, _ = fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%d\t%s\n",
			s.SessionID,
			s.SPIFFEID,
			colorizedRisk(s.RiskScore),
			s.ToolsAccessed,
			humanTTL(s.TTLSeconds),
		)
	}
	_ = tw.Flush()
	return buf.String(), nil
}

func colorizedRisk(score float64) string {
	base := strconv.FormatFloat(score, 'f', 2, 64)
	switch {
	case score >= 0.7:
		return "\033[0;31m" + base + "\033[0m"
	case score >= 0.5:
		return "\033[1;33m" + base + "\033[0m"
	default:
		return base
	}
}

func humanTTL(seconds int) string {
	if seconds <= 0 {
		return "0s"
	}
	d := time.Duration(seconds) * time.Second
	if d >= time.Hour {
		h := int(d / time.Hour)
		m := int((d % time.Hour) / time.Minute)
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
	if d >= time.Minute {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return fmt.Sprintf("%ds", seconds)
}

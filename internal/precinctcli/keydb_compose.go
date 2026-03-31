package precinctcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
)

func (k *KeyDB) composeListRateLimits(ctx context.Context, rpm, burst int) ([]RateLimitEntry, error) {
	keys, err := k.composeScan(ctx, "ratelimit:*:tokens")
	if err != nil {
		return nil, err
	}

	entries := make([]RateLimitEntry, 0, len(keys))
	for _, key := range keys {
		spiffeID, ok := parseSpiffeIDFromTokensKey(key)
		if !ok {
			continue
		}
		entry, err := k.composeGetRateLimitByKey(ctx, key, spiffeID, rpm, burst)
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue
			}
			return nil, err
		}
		if entry != nil {
			entries = append(entries, *entry)
		}
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].SPIFFEID < entries[j].SPIFFEID })
	return entries, nil
}

func (k *KeyDB) composeGetRateLimit(ctx context.Context, spiffeID string, rpm, burst int) (*RateLimitEntry, error) {
	return k.composeGetRateLimitByKey(ctx, rateLimitTokensKey(spiffeID), spiffeID, rpm, burst)
}

func (k *KeyDB) composeGetRateLimitByKey(ctx context.Context, key, spiffeID string, rpm, burst int) (*RateLimitEntry, error) {
	val, ttlSeconds, ok, err := k.composeGetValueAndTTL(ctx, key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, redis.Nil
	}

	f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
	if err != nil {
		return nil, fmt.Errorf("parse tokens for %s: %w", key, err)
	}
	if ttlSeconds < 0 {
		ttlSeconds = 0
	}

	remaining := int(math.Floor(f))
	if remaining < 0 {
		remaining = 0
	}

	return &RateLimitEntry{
		SPIFFEID:    spiffeID,
		Remaining:   remaining,
		Limit:       rpm,
		Burst:       burst,
		TTLSeconds:  ttlSeconds,
		ObservedKey: key,
	}, nil
}

func (k *KeyDB) composeGetValueAndTTL(ctx context.Context, key string) (string, int, bool, error) {
	const script = `
local key = ARGV[1]
local value = redis.call("GET", key)
if not value then
  return ""
end
return cjson.encode({value = value, ttl = redis.call("TTL", key)})
`

	out, err := k.runComposeKeyDBCLI(ctx, "--raw", "EVAL", script, "0", key)
	if err != nil {
		return "", 0, false, fmt.Errorf("get+ttl %s: %w", key, err)
	}

	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return "", 0, false, nil
	}

	var payload struct {
		Value string `json:"value"`
		TTL   int    `json:"ttl"`
	}
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return "", 0, false, fmt.Errorf("parse get+ttl response for %s: %w", key, err)
	}
	return payload.Value, payload.TTL, true, nil
}

func (k *KeyDB) composeGetSessionRiskScore(ctx context.Context, sessionID string) (float64, bool, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return 0, false, fmt.Errorf("session-id is empty")
	}

	keys, err := k.composeScan(ctx, "session:*:"+sessionID)
	if err != nil {
		return 0, false, fmt.Errorf("scan session keys: %w", err)
	}
	for _, key := range keys {
		if strings.HasSuffix(key, ":actions") {
			continue
		}
		raw, ok, err := k.composeGet(ctx, key)
		if err != nil {
			return 0, false, fmt.Errorf("get session key %s: %w", key, err)
		}
		if !ok {
			continue
		}

		var payload map[string]any
		if err := json.Unmarshal([]byte(raw), &payload); err != nil {
			return 0, false, fmt.Errorf("unmarshal session key %s: %w", key, err)
		}
		if score, ok := parseRiskScore(payload); ok {
			return score, true, nil
		}
		return 0, false, fmt.Errorf("session key %s missing RiskScore", key)
	}

	return 0, false, nil
}

func (k *KeyDB) DeleteSessionKeysForSPIFFEID(ctx context.Context, spiffeID string) (int64, []string, error) {
	if k.composeService == "" {
		return DeleteSessionKeysForSPIFFEID(ctx, k.client, spiffeID)
	}
	return k.composeDeleteByPattern(ctx, "session:"+strings.TrimSpace(spiffeID)+":*")
}

func (k *KeyDB) DeleteAllSessionKeys(ctx context.Context) (int64, []string, error) {
	if k.composeService == "" {
		return DeleteAllSessionKeys(ctx, k.client)
	}
	return k.composeDeleteByPattern(ctx, "session:*")
}

func (k *KeyDB) DeleteRateLimitKeysForSPIFFEID(ctx context.Context, spiffeID string) (int64, []string, error) {
	if k.composeService == "" {
		return DeleteRateLimitKeysForSPIFFEID(ctx, k.client, spiffeID)
	}
	spiffeID = strings.TrimSpace(spiffeID)
	if spiffeID == "" {
		return 0, nil, fmt.Errorf("spiffe id is empty")
	}
	keys := []string{
		"ratelimit:" + spiffeID,
		"ratelimit:" + spiffeID + ":tokens",
		"ratelimit:" + spiffeID + ":last_fill",
	}
	deleted, err := k.composeDel(ctx, keys...)
	if err != nil {
		return 0, nil, fmt.Errorf("delete rate limit keys: %w", err)
	}
	return deleted, keys, nil
}

func (k *KeyDB) DeleteAllRateLimitKeys(ctx context.Context) (int64, error) {
	if k.composeService == "" {
		return DeleteAllRateLimitKeys(ctx, k.client)
	}
	keys, err := k.composeScan(ctx, "ratelimit:*")
	if err != nil {
		return 0, err
	}
	if len(keys) == 0 {
		return 0, nil
	}
	return k.composeDel(ctx, keys...)
}

func (k *KeyDB) CollectDSARSessions(ctx context.Context, spiffeID string) ([]DSARSessionData, error) {
	if k.composeService == "" {
		return collectDSARSessions(ctx, k.client, spiffeID)
	}

	return k.composeCollectDSARSessions(ctx, spiffeID)
}

func (k *KeyDB) composeCollectDSARSessions(ctx context.Context, spiffeID string) ([]DSARSessionData, error) {
	const script = `
local pattern = ARGV[1]
local cursor = "0"
local sessions = {}
repeat
  local reply = redis.call("SCAN", cursor, "MATCH", pattern, "COUNT", 200)
  cursor = tostring(reply[1])
  local keys = reply[2]
  for _, key in ipairs(keys) do
    if string.sub(key, -8) ~= ":actions" then
      local session = redis.call("GET", key)
      if session then
        table.insert(sessions, {
          redis_key = key,
          ttl = redis.call("TTL", key),
          session_raw = session,
          actions = redis.call("LRANGE", key .. ":actions", 0, -1)
        })
      end
    end
  end
until cursor == "0"
return cjson.encode(sessions)
`

	pattern := "session:" + spiffeID + ":*"
	raw, err := k.runComposeKeyDBCLI(ctx, "--raw", "EVAL", script, "0", pattern)
	if err != nil {
		return nil, fmt.Errorf("collect DSAR sessions: %w", err)
	}

	type sessionRow struct {
		RedisKey   string   `json:"redis_key"`
		TTL        int      `json:"ttl"`
		SessionRaw string   `json:"session_raw"`
		Actions    []string `json:"actions"`
	}

	var rows []sessionRow
	if strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &rows); err != nil {
			return nil, fmt.Errorf("parse DSAR sessions response: %w", err)
		}
	}

	out := make([]DSARSessionData, 0, len(rows))
	for _, row := range rows {
		sessionPayload := map[string]any{}
		if err := json.Unmarshal([]byte(row.SessionRaw), &sessionPayload); err != nil {
			sessionPayload = map[string]any{"raw": row.SessionRaw}
		}

		actions := make([]any, 0, len(row.Actions))
		for _, actionRow := range row.Actions {
			var parsed any
			if err := json.Unmarshal([]byte(actionRow), &parsed); err != nil {
				actions = append(actions, map[string]any{"raw": actionRow})
				continue
			}
			actions = append(actions, parsed)
		}

		ttlSeconds := row.TTL
		if ttlSeconds < 0 {
			ttlSeconds = 0
		}

		out = append(out, DSARSessionData{
			SessionID:  parseSessionIDFromSessionKey(spiffeID, row.RedisKey),
			RedisKey:   row.RedisKey,
			TTLSeconds: ttlSeconds,
			Session:    sessionPayload,
			Actions:    actions,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].SessionID == out[j].SessionID {
			return out[i].RedisKey < out[j].RedisKey
		}
		return out[i].SessionID < out[j].SessionID
	})
	return out, nil
}

func (k *KeyDB) CollectDSARRateLimitData(ctx context.Context, spiffeID string) (DSARRateLimitData, error) {
	if k.composeService == "" {
		return collectDSARRateLimitData(ctx, k.client, spiffeID)
	}

	keys := []string{
		"ratelimit:" + spiffeID,
		"ratelimit:" + spiffeID + ":tokens",
		"ratelimit:" + spiffeID + ":last_fill",
	}
	out := DSARRateLimitData{
		SPIFFEID:   spiffeID,
		Keys:       make(map[string]any, len(keys)),
		TTLSeconds: make(map[string]int, len(keys)),
	}

	for _, key := range keys {
		val, ok, err := k.composeGet(ctx, key)
		if err != nil {
			return DSARRateLimitData{}, fmt.Errorf("get rate limit key %s: %w", key, err)
		}
		if !ok {
			continue
		}
		out.Keys[key] = val

		ttlSeconds, err := k.composeTTL(ctx, key)
		if err != nil {
			return DSARRateLimitData{}, fmt.Errorf("ttl for rate limit key %s: %w", key, err)
		}
		if ttlSeconds < 0 {
			ttlSeconds = 0
		}
		out.TTLSeconds[key] = ttlSeconds
	}

	return out, nil
}

func (k *KeyDB) composeDeleteByPattern(ctx context.Context, pattern string) (int64, []string, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return 0, nil, fmt.Errorf("pattern is empty")
	}
	keys, err := k.composeScan(ctx, pattern)
	if err != nil {
		return 0, nil, err
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return 0, keys, nil
	}
	deleted, err := k.composeDel(ctx, keys...)
	if err != nil {
		return 0, nil, err
	}
	return deleted, keys, nil
}

func (k *KeyDB) composeScan(ctx context.Context, pattern string) ([]string, error) {
	out, err := k.runComposeKeyDBCLI(ctx, "--scan", "--pattern", pattern)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out) == "" {
		return nil, nil
	}
	return splitNonEmptyLines(out), nil
}

func (k *KeyDB) composeGet(ctx context.Context, key string) (string, bool, error) {
	out, err := k.runComposeKeyDBCLI(ctx, "--raw", "GET", key)
	if err != nil {
		return "", false, err
	}
	value := strings.TrimRight(out, "\n")
	if value == "" {
		return "", false, nil
	}
	return value, true, nil
}

func (k *KeyDB) composeTTL(ctx context.Context, key string) (int, error) {
	out, err := k.runComposeKeyDBCLI(ctx, "--raw", "TTL", key)
	if err != nil {
		return 0, err
	}
	return parseComposeInt(out)
}

func (k *KeyDB) composeLRange(ctx context.Context, key string) ([]string, error) {
	out, err := k.runComposeKeyDBCLI(ctx, "--raw", "LRANGE", key, "0", "-1")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out) == "" {
		return nil, nil
	}
	return splitNonEmptyLines(out), nil
}

func (k *KeyDB) composeLLen(ctx context.Context, key string) (int64, error) {
	out, err := k.runComposeKeyDBCLI(ctx, "--raw", "LLEN", key)
	if err != nil {
		return 0, err
	}
	n, err := parseComposeInt(out)
	if err != nil {
		return 0, err
	}
	return int64(n), nil
}

func (k *KeyDB) composeExists(ctx context.Context, keys ...string) (int64, error) {
	args := append([]string{"--raw", "EXISTS"}, keys...)
	out, err := k.runComposeKeyDBCLI(ctx, args...)
	if err != nil {
		return 0, err
	}
	n, err := parseComposeInt(out)
	if err != nil {
		return 0, err
	}
	return int64(n), nil
}

func (k *KeyDB) composeDel(ctx context.Context, keys ...string) (int64, error) {
	if len(keys) == 0 {
		return 0, nil
	}
	args := append([]string{"--raw", "DEL"}, keys...)
	out, err := k.runComposeKeyDBCLI(ctx, args...)
	if err != nil {
		return 0, err
	}
	n, err := parseComposeInt(out)
	if err != nil {
		return 0, err
	}
	return int64(n), nil
}

func (k *KeyDB) runComposeKeyDBCLI(ctx context.Context, args ...string) (string, error) {
	service := strings.TrimSpace(k.composeService)
	if service == "" {
		service = "keydb"
	}

	cmdArgs := append([]string{"keydb-cli"}, args...)
	out, err := RunComposeServiceCommand(ctx, service, cmdArgs...)
	if err != nil {
		return "", err
	}
	return out, nil
}

func splitNonEmptyLines(out string) []string {
	lines := strings.Split(strings.ReplaceAll(strings.TrimSpace(out), "\r\n", "\n"), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		filtered = append(filtered, line)
	}
	return filtered
}

func parseComposeInt(out string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("parse integer output %q: %w", strings.TrimSpace(out), err)
	}
	return n, nil
}

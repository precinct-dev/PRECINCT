package precinctcli

import (
	"context"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
)

// DeleteRateLimitKeysForSPIFFEID deletes KeyDB keys associated with a single
// identity's rate limit bucket.
//
// The gateway rate limiter currently persists:
//   - ratelimit:<spiffe-id>:tokens
//   - ratelimit:<spiffe-id>:last_fill
//
// We also attempt to delete the legacy/base key ratelimit:<spiffe-id> to
// preserve compatibility with older assumptions in story text.
func DeleteRateLimitKeysForSPIFFEID(ctx context.Context, client *redis.Client, spiffeID string) (deleted int64, keys []string, err error) {
	spiffeID = strings.TrimSpace(spiffeID)
	if spiffeID == "" {
		return 0, nil, fmt.Errorf("spiffe id is empty")
	}
	if client == nil {
		return 0, nil, fmt.Errorf("keydb client is nil")
	}

	keys = []string{
		"ratelimit:" + spiffeID,
		"ratelimit:" + spiffeID + ":tokens",
		"ratelimit:" + spiffeID + ":last_fill",
	}
	deleted, err = client.Del(ctx, keys...).Result()
	if err != nil {
		return 0, keys, fmt.Errorf("delete rate limit keys: %w", err)
	}
	return deleted, keys, nil
}

var deleteAllRateLimitKeysScript = redis.NewScript(`
local count = 0
local cursor = "0"
repeat
  local result = redis.call("SCAN", cursor, "MATCH", "ratelimit:*", "COUNT", 1000)
  cursor = result[1]
  local keys = result[2]
  for i, key in ipairs(keys) do
    redis.call("DEL", key)
    count = count + 1
  end
until cursor == "0"
return count
`)

// DeleteAllRateLimitKeys deletes all rate limit keys matching ratelimit:* using
// a targeted Lua SCAN+MATCH+DEL pattern (NOT FLUSHALL).
func DeleteAllRateLimitKeys(ctx context.Context, client *redis.Client) (int64, error) {
	if client == nil {
		return 0, fmt.Errorf("keydb client is nil")
	}
	n, err := deleteAllRateLimitKeysScript.Run(ctx, client, nil).Int64()
	if err != nil {
		return 0, fmt.Errorf("delete all rate limit keys: %w", err)
	}
	return n, nil
}

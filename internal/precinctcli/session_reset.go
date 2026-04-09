// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/redis/go-redis/v9"
)

var deleteSessionKeysByPatternScript = redis.NewScript(`
local deleted = {}
local cursor = "0"
local pattern = ARGV[1]
repeat
  local result = redis.call("SCAN", cursor, "MATCH", pattern, "COUNT", 1000)
  cursor = result[1]
  local keys = result[2]
  for i, key in ipairs(keys) do
    redis.call("DEL", key)
    table.insert(deleted, key)
  end
until cursor == "0"
return deleted
`)

func DeleteSessionKeysForSPIFFEID(ctx context.Context, client *redis.Client, spiffeID string) (int64, []string, error) {
	spiffeID = strings.TrimSpace(spiffeID)
	if spiffeID == "" {
		return 0, nil, fmt.Errorf("spiffe id is empty")
	}
	if client == nil {
		return 0, nil, fmt.Errorf("keydb client is nil")
	}

	pattern := "session:" + spiffeID + ":*"
	return deleteSessionKeysByPattern(ctx, client, pattern)
}

func DeleteAllSessionKeys(ctx context.Context, client *redis.Client) (int64, []string, error) {
	if client == nil {
		return 0, nil, fmt.Errorf("keydb client is nil")
	}
	return deleteSessionKeysByPattern(ctx, client, "session:*")
}

func deleteSessionKeysByPattern(ctx context.Context, client *redis.Client, pattern string) (int64, []string, error) {
	raw, err := deleteSessionKeysByPatternScript.Run(ctx, client, nil, pattern).Result()
	if err != nil {
		return 0, nil, fmt.Errorf("delete session keys by pattern %q: %w", pattern, err)
	}

	list, err := redisResultToStringSlice(raw)
	if err != nil {
		return 0, nil, err
	}
	sort.Strings(list)
	return int64(len(list)), list, nil
}

func redisResultToStringSlice(v any) ([]string, error) {
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("unexpected redis lua result type %T", v)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected redis lua item type %T", item)
		}
		out = append(out, s)
	}
	return out, nil
}

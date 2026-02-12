package agw

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// NewKeyDBClient returns a raw *redis.Client for use by commands that operate
// directly on KeyDB (e.g. rate-limit reset). For higher-level introspection
// (list/get rate limits), use the KeyDB wrapper below.
func NewKeyDBClient(keydbURL string) (*redis.Client, error) {
	keydbURL = strings.TrimSpace(keydbURL)
	if keydbURL == "" {
		return nil, fmt.Errorf("keydb url is empty")
	}
	opt, err := redis.ParseURL(keydbURL)
	if err != nil {
		return nil, fmt.Errorf("parse keydb url: %w", err)
	}
	return redis.NewClient(opt), nil
}

type KeyDB struct {
	client *redis.Client
}

type RateLimitCounters struct {
	Found      bool `json:"found"`
	Remaining  int  `json:"remaining"`
	Limit      int  `json:"limit"`
	Burst      int  `json:"burst"`
	TTLSeconds int  `json:"ttl_seconds"`
}

func NewKeyDB(url string) (*KeyDB, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse keydb url: %w", err)
	}
	return &KeyDB{client: redis.NewClient(opt)}, nil
}

func (k *KeyDB) Close() error { return k.client.Close() }

func rateLimitTokensKey(spiffeID string) string {
	// Must match internal/gateway/middleware/rate_limiter.go
	return "ratelimit:" + spiffeID + ":tokens"
}

func parseSpiffeIDFromTokensKey(key string) (string, bool) {
	if !strings.HasPrefix(key, "ratelimit:") || !strings.HasSuffix(key, ":tokens") {
		return "", false
	}
	spiffeID := strings.TrimSuffix(strings.TrimPrefix(key, "ratelimit:"), ":tokens")
	if spiffeID == "" {
		return "", false
	}
	return spiffeID, true
}

func (k *KeyDB) ListRateLimits(ctx context.Context, rpm, burst int) ([]RateLimitEntry, error) {
	var cursor uint64
	var keys []string

	for {
		batch, next, err := k.client.Scan(ctx, cursor, "ratelimit:*:tokens", 200).Result()
		if err != nil {
			return nil, fmt.Errorf("scan ratelimit keys: %w", err)
		}
		keys = append(keys, batch...)
		cursor = next
		if cursor == 0 {
			break
		}
	}

	entries := make([]RateLimitEntry, 0, len(keys))
	for _, key := range keys {
		spiffeID, ok := parseSpiffeIDFromTokensKey(key)
		if !ok {
			continue
		}
		e, err := k.getByTokensKey(ctx, key, spiffeID, rpm, burst)
		if err != nil {
			// Treat missing keys as non-entries; other errors are fatal.
			if err == redis.Nil {
				continue
			}
			return nil, err
		}
		if e != nil {
			entries = append(entries, *e)
		}
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].SPIFFEID < entries[j].SPIFFEID })
	return entries, nil
}

func (k *KeyDB) GetRateLimit(ctx context.Context, spiffeID string, rpm, burst int) (*RateLimitEntry, error) {
	key := rateLimitTokensKey(spiffeID)
	e, err := k.getByTokensKey(ctx, key, spiffeID, rpm, burst)
	if err == redis.Nil {
		return nil, nil
	}
	return e, err
}

func (k *KeyDB) GetRateLimitCounters(ctx context.Context, spiffeID string, rpm, burst int) (RateLimitCounters, error) {
	spiffeID = strings.TrimSpace(spiffeID)
	if spiffeID == "" {
		return RateLimitCounters{}, fmt.Errorf("spiffe-id is empty")
	}

	entry, err := k.GetRateLimit(ctx, spiffeID, rpm, burst)
	if err != nil {
		return RateLimitCounters{}, err
	}
	if entry == nil {
		return RateLimitCounters{
			Found:      false,
			Remaining:  burst,
			Limit:      rpm,
			Burst:      burst,
			TTLSeconds: 0,
		}, nil
	}

	return RateLimitCounters{
		Found:      true,
		Remaining:  entry.Remaining,
		Limit:      entry.Limit,
		Burst:      entry.Burst,
		TTLSeconds: entry.TTLSeconds,
	}, nil
}

func (k *KeyDB) GetSessionRiskScore(ctx context.Context, sessionID string) (float64, bool, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return 0, false, fmt.Errorf("session-id is empty")
	}

	var cursor uint64
	pattern := "session:*:" + sessionID

	for {
		keys, next, err := k.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return 0, false, fmt.Errorf("scan session keys: %w", err)
		}
		for _, key := range keys {
			if strings.HasSuffix(key, ":actions") {
				continue
			}
			raw, err := k.client.Get(ctx, key).Bytes()
			if err != nil {
				if err == redis.Nil {
					continue
				}
				return 0, false, fmt.Errorf("get session key %s: %w", key, err)
			}

			var payload map[string]any
			if err := json.Unmarshal(raw, &payload); err != nil {
				return 0, false, fmt.Errorf("unmarshal session key %s: %w", key, err)
			}

			if score, ok := parseRiskScore(payload); ok {
				return score, true, nil
			}
			return 0, false, fmt.Errorf("session key %s missing RiskScore", key)
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}

	return 0, false, nil
}

func parseRiskScore(payload map[string]any) (float64, bool) {
	for _, key := range []string{"RiskScore", "risk_score"} {
		v, exists := payload[key]
		if !exists {
			continue
		}
		switch n := v.(type) {
		case float64:
			return n, true
		case int:
			return float64(n), true
		case int64:
			return float64(n), true
		}
	}
	return 0, false
}

func (k *KeyDB) getByTokensKey(ctx context.Context, key, spiffeID string, rpm, burst int) (*RateLimitEntry, error) {
	val, err := k.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
	if err != nil {
		return nil, fmt.Errorf("parse tokens for %s: %w", key, err)
	}

	ttl, err := k.client.TTL(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("ttl for %s: %w", key, err)
	}
	ttlSeconds := int(ttl.Seconds())
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

// For tests, allow setting TTL without relying on internal store TTL behavior.
func (k *KeyDB) SetTokensForTest(ctx context.Context, spiffeID string, tokens float64, ttl time.Duration) error {
	return k.client.Set(ctx, rateLimitTokensKey(spiffeID), strconv.FormatFloat(tokens, 'f', -1, 64), ttl).Err()
}

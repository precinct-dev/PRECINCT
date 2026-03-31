package precinctcli

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client, mr
}

func TestDeleteRateLimitKeysForSPIFFEID_DeletesTokensAndLastFill(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	spiffe := "spiffe://poc.local/agents/test/dev"
	if err := mr.Set("ratelimit:"+spiffe+":tokens", "1.5"); err != nil {
		t.Fatalf("seed tokens: %v", err)
	}
	if err := mr.Set("ratelimit:"+spiffe+":last_fill", "123"); err != nil {
		t.Fatalf("seed last_fill: %v", err)
	}
	if err := mr.Set("unrelated", "keep"); err != nil {
		t.Fatalf("seed unrelated key: %v", err)
	}

	n, keys, err := DeleteRateLimitKeysForSPIFFEID(ctx, rdb, spiffe)
	if err != nil {
		t.Fatalf("DeleteRateLimitKeysForSPIFFEID: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected deleted=2, got %d (keys=%v)", n, keys)
	}
	if mr.Exists("ratelimit:"+spiffe+":tokens") || mr.Exists("ratelimit:"+spiffe+":last_fill") {
		t.Fatalf("expected ratelimit keys removed")
	}
	if !mr.Exists("unrelated") {
		t.Fatalf("expected unrelated key to remain")
	}
}

func TestDeleteAllRateLimitKeys_DeletesOnlyRatelimitPrefix(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := mr.Set("ratelimit:spiffe://a:tokens", "1"); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := mr.Set("ratelimit:spiffe://a:last_fill", "1"); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := mr.Set("ratelimit:spiffe://b:tokens", "1"); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := mr.Set("session:spiffe://a", "keep"); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	n, err := DeleteAllRateLimitKeys(ctx, rdb)
	if err != nil {
		t.Fatalf("DeleteAllRateLimitKeys: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected deleted=3, got %d", n)
	}
	if mr.Exists("ratelimit:spiffe://a:tokens") || mr.Exists("ratelimit:spiffe://a:last_fill") || mr.Exists("ratelimit:spiffe://b:tokens") {
		t.Fatalf("expected ratelimit keys removed")
	}
	if !mr.Exists("session:spiffe://a") {
		t.Fatalf("expected non-ratelimit keys to remain")
	}
}

package agw

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestKeyDB_ListAndGetRateLimits_WithTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()

	kdb, err := NewKeyDB("redis://" + mr.Addr())
	if err != nil {
		t.Fatalf("NewKeyDB err: %v", err)
	}
	t.Cleanup(func() { _ = kdb.Close() })

	spiffeID := "spiffe://poc.local/agents/example/dev"

	// Seed token key with TTL and advance time to exercise TTL reporting.
	if err := kdb.SetTokensForTest(ctx, spiffeID, 45.9, 32*time.Second); err != nil {
		t.Fatalf("SetTokensForTest err: %v", err)
	}
	mr.FastForward(2 * time.Second)

	// List
	list, err := kdb.ListRateLimits(ctx, 60, 10)
	if err != nil {
		t.Fatalf("ListRateLimits err: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(list))
	}
	if list[0].SPIFFEID != spiffeID {
		t.Fatalf("expected spiffe_id=%q, got %q", spiffeID, list[0].SPIFFEID)
	}
	if list[0].Remaining != 45 {
		t.Fatalf("expected remaining=45, got %d", list[0].Remaining)
	}
	if list[0].Limit != 60 || list[0].Burst != 10 {
		t.Fatalf("expected limit=60 burst=10, got limit=%d burst=%d", list[0].Limit, list[0].Burst)
	}
	if list[0].TTLSeconds <= 0 || list[0].TTLSeconds > 32 {
		t.Fatalf("expected ttl_seconds in (0,32], got %d", list[0].TTLSeconds)
	}

	// Get
	got, err := kdb.GetRateLimit(ctx, spiffeID, 60, 10)
	if err != nil {
		t.Fatalf("GetRateLimit err: %v", err)
	}
	if got == nil || got.SPIFFEID != spiffeID {
		t.Fatalf("expected non-nil entry for %q, got %+v", spiffeID, got)
	}

	// Unknown should return nil, nil.
	missing, err := kdb.GetRateLimit(ctx, "spiffe://poc.local/agents/missing/dev", 60, 10)
	if err != nil {
		t.Fatalf("GetRateLimit(missing) err: %v", err)
	}
	if missing != nil {
		t.Fatalf("expected nil for missing spiffe id, got %+v", missing)
	}
}


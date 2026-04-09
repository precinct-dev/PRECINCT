// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcli

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

func TestKeyDB_GetSessionRiskScore(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()

	kdb, err := NewKeyDB("redis://" + mr.Addr())
	if err != nil {
		t.Fatalf("NewKeyDB err: %v", err)
	}
	t.Cleanup(func() { _ = kdb.Close() })

	spiffeID := "spiffe://poc.local/agents/example/dev"
	sessionID := "sid-runtime-test"
	key := "session:" + spiffeID + ":" + sessionID

	if err := mr.Set(key, `{"RiskScore":0.73}`); err != nil {
		t.Fatalf("seed session value: %v", err)
	}
	mr.SetTTL(key, 30*time.Minute)
	if _, err := mr.RPush(key+":actions", `{"Tool":"read"}`); err != nil {
		t.Fatalf("seed actions: %v", err)
	}

	score, found, err := kdb.GetSessionRiskScore(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetSessionRiskScore err: %v", err)
	}
	if !found {
		t.Fatalf("expected session risk to be found")
	}
	if score < 0.72 || score > 0.74 {
		t.Fatalf("expected risk around 0.73, got %f", score)
	}

	missingScore, missingFound, err := kdb.GetSessionRiskScore(ctx, "sid-does-not-exist")
	if err != nil {
		t.Fatalf("GetSessionRiskScore(missing) err: %v", err)
	}
	if missingFound || missingScore != 0 {
		t.Fatalf("expected missing session to return not found, got score=%f found=%v", missingScore, missingFound)
	}
}

func TestKeyDB_GetRateLimitCounters(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()

	kdb, err := NewKeyDB("redis://" + mr.Addr())
	if err != nil {
		t.Fatalf("NewKeyDB err: %v", err)
	}
	t.Cleanup(func() { _ = kdb.Close() })

	spiffeID := "spiffe://poc.local/agents/example/dev"
	rpm := 600
	burst := 100

	// Missing key => Found=false with burst fallback.
	missing, err := kdb.GetRateLimitCounters(ctx, spiffeID, rpm, burst)
	if err != nil {
		t.Fatalf("GetRateLimitCounters(missing) err: %v", err)
	}
	if missing.Found {
		t.Fatalf("expected missing counters Found=false, got %+v", missing)
	}
	if missing.Remaining != burst || missing.Limit != rpm {
		t.Fatalf("unexpected missing counters fallback: %+v", missing)
	}

	if err := kdb.SetTokensForTest(ctx, spiffeID, 55.1, 20*time.Second); err != nil {
		t.Fatalf("SetTokensForTest err: %v", err)
	}
	got, err := kdb.GetRateLimitCounters(ctx, spiffeID, rpm, burst)
	if err != nil {
		t.Fatalf("GetRateLimitCounters(found) err: %v", err)
	}
	if !got.Found {
		t.Fatalf("expected Found=true, got %+v", got)
	}
	if got.Remaining != 55 {
		t.Fatalf("expected remaining=55, got %+v", got)
	}
	if got.Limit != rpm || got.Burst != burst {
		t.Fatalf("unexpected limit/burst: %+v", got)
	}
	if got.TTLSeconds <= 0 {
		t.Fatalf("expected ttl > 0, got %+v", got)
	}

	_, err = kdb.GetRateLimitCounters(ctx, " ", rpm, burst)
	if err == nil {
		t.Fatalf("expected error for empty spiffe-id")
	}
}

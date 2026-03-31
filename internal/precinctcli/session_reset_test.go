package precinctcli

import (
	"context"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
)

func TestDeleteSessionKeysForSPIFFEID(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()

	client, err := NewKeyDBClient("redis://" + mr.Addr())
	if err != nil {
		t.Fatalf("NewKeyDBClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	spiffeA := "spiffe://poc.local/agents/a/dev"
	spiffeB := "spiffe://poc.local/agents/b/dev"

	if err := client.Set(ctx, "session:"+spiffeA+":sid-a", `{"RiskScore":0.4}`, 0).Err(); err != nil {
		t.Fatalf("seed a: %v", err)
	}
	if err := client.Set(ctx, "session:"+spiffeA+":sid-a:actions", `[]`, 0).Err(); err != nil {
		t.Fatalf("seed a actions: %v", err)
	}
	if err := client.Set(ctx, "session:"+spiffeB+":sid-b", `{"RiskScore":0.2}`, 0).Err(); err != nil {
		t.Fatalf("seed b: %v", err)
	}
	if err := client.Set(ctx, "ratelimit:"+spiffeA+":tokens", "1", 0).Err(); err != nil {
		t.Fatalf("seed ratelimit: %v", err)
	}

	deleted, keys, err := DeleteSessionKeysForSPIFFEID(ctx, client, spiffeA)
	if err != nil {
		t.Fatalf("DeleteSessionKeysForSPIFFEID: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("expected deleted=2, got %d keys=%v", deleted, keys)
	}
	if mr.Exists("session:"+spiffeA+":sid-a") || mr.Exists("session:"+spiffeA+":sid-a:actions") {
		t.Fatalf("expected spiffeA session keys deleted")
	}
	if !mr.Exists("session:" + spiffeB + ":sid-b") {
		t.Fatalf("expected spiffeB session key to remain")
	}
	if !mr.Exists("ratelimit:" + spiffeA + ":tokens") {
		t.Fatalf("expected non-session key to remain")
	}
}

func TestDeleteAllSessionKeys(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()

	client, err := NewKeyDBClient("redis://" + mr.Addr())
	if err != nil {
		t.Fatalf("NewKeyDBClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	seeds := []string{
		"session:spiffe://poc.local/agents/a/dev:sid-a",
		"session:spiffe://poc.local/agents/a/dev:sid-a:actions",
		"session:spiffe://poc.local/agents/b/dev:sid-b",
	}
	for _, key := range seeds {
		if err := client.Set(ctx, key, "x", 0).Err(); err != nil {
			t.Fatalf("seed key %q: %v", key, err)
		}
	}
	if err := client.Set(ctx, "ratelimit:spiffe://poc.local/agents/a/dev:tokens", "1", 0).Err(); err != nil {
		t.Fatalf("seed ratelimit: %v", err)
	}

	deleted, keys, err := DeleteAllSessionKeys(ctx, client)
	if err != nil {
		t.Fatalf("DeleteAllSessionKeys: %v", err)
	}
	if deleted != int64(len(seeds)) {
		t.Fatalf("expected deleted=%d, got %d keys=%v", len(seeds), deleted, keys)
	}
	for _, key := range seeds {
		if mr.Exists(key) {
			t.Fatalf("expected key deleted: %s", key)
		}
	}
	if !mr.Exists("ratelimit:spiffe://poc.local/agents/a/dev:tokens") {
		t.Fatalf("expected non-session key to remain")
	}
}

func TestDeleteSessionKeysForSPIFFEID_EmptySPIFFE(t *testing.T) {
	mr := miniredis.RunT(t)
	client, err := NewKeyDBClient("redis://" + mr.Addr())
	if err != nil {
		t.Fatalf("NewKeyDBClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	_, _, err = DeleteSessionKeysForSPIFFEID(context.Background(), client, "")
	if err == nil {
		t.Fatalf("expected error for empty spiffe id")
	}
	if got := fmt.Sprint(err); got == "" {
		t.Fatalf("expected non-empty error message")
	}
}

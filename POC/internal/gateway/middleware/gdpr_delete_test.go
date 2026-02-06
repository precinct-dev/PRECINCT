package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// ---------------------------------------------------------------------------
// Helper: create a miniredis-backed redis.Client for GDPR delete tests
// ---------------------------------------------------------------------------

func newTestRedisClient(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	t.Cleanup(func() { _ = client.Close() })

	return client, mr
}

// seedSessionData populates KeyDB with session data, actions, and rate limit
// entries for a given SPIFFE ID, simulating what the gateway creates during
// normal operation.
func seedSessionData(t *testing.T, client *redis.Client, spiffeID string, sessionIDs []string) {
	t.Helper()
	ctx := context.Background()

	store := NewKeyDBStoreFromClient(client, 3600)

	for _, sessionID := range sessionIDs {
		session := &AgentSession{
			ID:                  sessionID,
			SPIFFEID:            spiffeID,
			StartTime:           time.Now().UTC(),
			Actions:             make([]ToolAction, 0),
			DataClassifications: []string{"sensitive"},
			RiskScore:           0.5,
			Flags:               make([]string, 0),
		}

		if err := store.SaveSession(ctx, spiffeID, sessionID, session); err != nil {
			t.Fatalf("Failed to seed session %s: %v", sessionID, err)
		}

		// Append some actions to each session
		for i := 0; i < 3; i++ {
			action := ToolAction{
				Timestamp:      time.Now().UTC(),
				Tool:           "database_query",
				Resource:       "users",
				Classification: "sensitive",
				ExternalTarget: false,
			}
			if err := store.AppendAction(ctx, spiffeID, sessionID, action); err != nil {
				t.Fatalf("Failed to seed action for session %s: %v", sessionID, err)
			}
		}
	}

	// Seed rate limit data
	rlStore := NewKeyDBRateLimitStore(client)
	if err := rlStore.SetTokens(ctx, spiffeID, 7.5, time.Now()); err != nil {
		t.Fatalf("Failed to seed rate limit data: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: Deletion logic
// ---------------------------------------------------------------------------

func TestGDPRDeleteAllData_RemovesAllKeys(t *testing.T) {
	client, _ := newTestRedisClient(t)
	ctx := context.Background()

	spiffeID := "spiffe://poc.local/agents/test-agent"
	sessionIDs := []string{"session-1", "session-2", "session-3"}

	// Seed data
	seedSessionData(t, client, spiffeID, sessionIDs)

	// Verify data exists before deletion
	for _, sid := range sessionIDs {
		val, err := client.Get(ctx, keyDBSessionKey(spiffeID, sid)).Result()
		if err != nil {
			t.Fatalf("Session key should exist before deletion: %v", err)
		}
		if val == "" {
			t.Fatal("Session key should have data before deletion")
		}

		actionsLen, err := client.LLen(ctx, keyDBActionsKey(spiffeID, sid)).Result()
		if err != nil {
			t.Fatalf("Actions key should exist before deletion: %v", err)
		}
		if actionsLen != 3 {
			t.Fatalf("Expected 3 actions, got %d", actionsLen)
		}
	}

	// Verify GDPR tracking set exists
	members, err := client.SMembers(ctx, keyDBGDPRKey(spiffeID)).Result()
	if err != nil {
		t.Fatalf("GDPR set should exist: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("Expected 3 members in GDPR set, got %d", len(members))
	}

	// Verify rate limit keys exist
	_, err = client.Get(ctx, rateLimitTokensKey(spiffeID)).Result()
	if err != nil {
		t.Fatalf("Rate limit tokens key should exist before deletion: %v", err)
	}
	_, err = client.Get(ctx, rateLimitLastFillKey(spiffeID)).Result()
	if err != nil {
		t.Fatalf("Rate limit last_fill key should exist before deletion: %v", err)
	}

	// Execute deletion
	result, err := GDPRDeleteAllData(ctx, client, spiffeID)
	if err != nil {
		t.Fatalf("GDPRDeleteAllData failed: %v", err)
	}

	// Verify result
	if result.SPIFFEID != spiffeID {
		t.Errorf("Expected SPIFFE ID %s, got %s", spiffeID, result.SPIFFEID)
	}
	if result.SessionsFound != 3 {
		t.Errorf("Expected 3 sessions found, got %d", result.SessionsFound)
	}
	// 3 sessions * 2 keys (session + actions) + 2 rate limit keys + 1 GDPR set = 9
	if result.KeysDeleted != 9 {
		t.Errorf("Expected 9 keys deleted, got %d", result.KeysDeleted)
	}
	if !result.RateLimitPurged {
		t.Error("Expected RateLimitPurged=true")
	}

	// Verify ALL keys are gone
	for _, sid := range sessionIDs {
		// Session key
		exists, err := client.Exists(ctx, keyDBSessionKey(spiffeID, sid)).Result()
		if err != nil {
			t.Fatalf("Exists check failed: %v", err)
		}
		if exists != 0 {
			t.Errorf("Session key for %s should be deleted", sid)
		}

		// Actions key
		exists, err = client.Exists(ctx, keyDBActionsKey(spiffeID, sid)).Result()
		if err != nil {
			t.Fatalf("Exists check failed: %v", err)
		}
		if exists != 0 {
			t.Errorf("Actions key for %s should be deleted", sid)
		}
	}

	// Rate limit keys
	exists, err := client.Exists(ctx, rateLimitTokensKey(spiffeID)).Result()
	if err != nil {
		t.Fatalf("Exists check failed: %v", err)
	}
	if exists != 0 {
		t.Error("Rate limit tokens key should be deleted")
	}

	exists, err = client.Exists(ctx, rateLimitLastFillKey(spiffeID)).Result()
	if err != nil {
		t.Fatalf("Exists check failed: %v", err)
	}
	if exists != 0 {
		t.Error("Rate limit last_fill key should be deleted")
	}

	// GDPR tracking set
	exists, err = client.Exists(ctx, keyDBGDPRKey(spiffeID)).Result()
	if err != nil {
		t.Fatalf("Exists check failed: %v", err)
	}
	if exists != 0 {
		t.Error("GDPR tracking set should be deleted")
	}
}

func TestGDPRDeleteAllData_NonExistentSPIFFEID_NoOp(t *testing.T) {
	client, _ := newTestRedisClient(t)
	ctx := context.Background()

	// Delete data for a SPIFFE ID that never existed
	result, err := GDPRDeleteAllData(ctx, client, "spiffe://poc.local/agents/does-not-exist")
	if err != nil {
		t.Fatalf("GDPRDeleteAllData should not error on nonexistent SPIFFE ID: %v", err)
	}

	if result.SessionsFound != 0 {
		t.Errorf("Expected 0 sessions found, got %d", result.SessionsFound)
	}
	if result.KeysDeleted != 0 {
		t.Errorf("Expected 0 keys deleted, got %d", result.KeysDeleted)
	}
	if !result.RateLimitPurged {
		t.Error("RateLimitPurged should still be true (no-op is valid)")
	}
}

func TestGDPRDeleteAllData_OnlyRateLimitData(t *testing.T) {
	client, _ := newTestRedisClient(t)
	ctx := context.Background()

	spiffeID := "spiffe://poc.local/agents/rate-only"

	// Seed ONLY rate limit data (no sessions)
	rlStore := NewKeyDBRateLimitStore(client)
	if err := rlStore.SetTokens(ctx, spiffeID, 5.0, time.Now()); err != nil {
		t.Fatalf("Failed to seed rate limit data: %v", err)
	}

	// Execute deletion
	result, err := GDPRDeleteAllData(ctx, client, spiffeID)
	if err != nil {
		t.Fatalf("GDPRDeleteAllData failed: %v", err)
	}

	if result.SessionsFound != 0 {
		t.Errorf("Expected 0 sessions, got %d", result.SessionsFound)
	}
	// 2 rate limit keys deleted
	if result.KeysDeleted != 2 {
		t.Errorf("Expected 2 keys deleted (rate limit), got %d", result.KeysDeleted)
	}

	// Verify rate limit keys are gone
	exists, _ := client.Exists(ctx, rateLimitTokensKey(spiffeID)).Result()
	if exists != 0 {
		t.Error("Rate limit tokens key should be deleted")
	}
	exists, _ = client.Exists(ctx, rateLimitLastFillKey(spiffeID)).Result()
	if exists != 0 {
		t.Error("Rate limit last_fill key should be deleted")
	}
}

func TestGDPRDeleteAllData_DoesNotAffectOtherSPIFFEIDs(t *testing.T) {
	client, _ := newTestRedisClient(t)
	ctx := context.Background()

	// Seed data for two different SPIFFE IDs
	spiffeA := "spiffe://poc.local/agents/agent-a"
	spiffeB := "spiffe://poc.local/agents/agent-b"

	seedSessionData(t, client, spiffeA, []string{"session-a1"})
	seedSessionData(t, client, spiffeB, []string{"session-b1"})

	// Delete only agent-a
	result, err := GDPRDeleteAllData(ctx, client, spiffeA)
	if err != nil {
		t.Fatalf("GDPRDeleteAllData failed: %v", err)
	}
	if result.SessionsFound != 1 {
		t.Errorf("Expected 1 session found for agent-a, got %d", result.SessionsFound)
	}

	// Verify agent-a data is gone
	exists, _ := client.Exists(ctx, keyDBSessionKey(spiffeA, "session-a1")).Result()
	if exists != 0 {
		t.Error("Agent-a session should be deleted")
	}

	// Verify agent-b data is UNTOUCHED
	exists, _ = client.Exists(ctx, keyDBSessionKey(spiffeB, "session-b1")).Result()
	if exists == 0 {
		t.Error("Agent-b session should NOT be deleted")
	}
	exists, _ = client.Exists(ctx, keyDBActionsKey(spiffeB, "session-b1")).Result()
	if exists == 0 {
		t.Error("Agent-b actions should NOT be deleted")
	}
	exists, _ = client.Exists(ctx, rateLimitTokensKey(spiffeB)).Result()
	if exists == 0 {
		t.Error("Agent-b rate limit tokens should NOT be deleted")
	}
	members, _ := client.SMembers(ctx, keyDBGDPRKey(spiffeB)).Result()
	if len(members) != 1 {
		t.Errorf("Agent-b GDPR set should still have 1 member, got %d", len(members))
	}
}

func TestGDPRDeleteAllData_ResultContainsSessionIDs(t *testing.T) {
	client, _ := newTestRedisClient(t)
	ctx := context.Background()

	spiffeID := "spiffe://poc.local/agents/audit-trail"
	sessionIDs := []string{"audit-session-1", "audit-session-2"}

	seedSessionData(t, client, spiffeID, sessionIDs)

	result, err := GDPRDeleteAllData(ctx, client, spiffeID)
	if err != nil {
		t.Fatalf("GDPRDeleteAllData failed: %v", err)
	}

	if len(result.SessionIDs) != 2 {
		t.Fatalf("Expected 2 session IDs in result, got %d", len(result.SessionIDs))
	}

	// Check both session IDs are present (order may vary due to SET)
	found := map[string]bool{}
	for _, sid := range result.SessionIDs {
		found[sid] = true
	}
	for _, expected := range sessionIDs {
		if !found[expected] {
			t.Errorf("Expected session ID %s in result, not found", expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration Test: Full lifecycle -- create sessions, delete, verify
// ---------------------------------------------------------------------------

func TestGDPRDeleteAllData_Integration_FullLifecycle(t *testing.T) {
	client, _ := newTestRedisClient(t)
	ctx := context.Background()

	spiffeID := "spiffe://poc.local/agents/integration-test"

	// Phase 1: Create sessions via the real SessionContext + KeyDBStore
	store := NewKeyDBStoreFromClient(client, 3600)
	sc := NewSessionContext(store)

	// Simulate gateway creating sessions across multiple requests
	session1 := sc.GetOrCreateSession(spiffeID, "int-session-1")
	sc.RecordAction(session1, ToolAction{
		Timestamp:      time.Now(),
		Tool:           "database_query",
		Resource:       "user_passwords",
		Classification: "sensitive",
		ExternalTarget: false,
	})
	sc.RecordAction(session1, ToolAction{
		Timestamp:      time.Now(),
		Tool:           "file_read",
		Resource:       "config.yaml",
		Classification: "internal",
		ExternalTarget: false,
	})

	session2 := sc.GetOrCreateSession(spiffeID, "int-session-2")
	sc.RecordAction(session2, ToolAction{
		Timestamp:      time.Now(),
		Tool:           "s3_list",
		Resource:       "bucket/data",
		Classification: "confidential",
		ExternalTarget: false,
	})

	// Phase 2: Also create rate limit data
	rlStore := NewKeyDBRateLimitStore(client)
	if err := rlStore.SetTokens(ctx, spiffeID, 8.0, time.Now()); err != nil {
		t.Fatalf("Failed to set rate limit tokens: %v", err)
	}

	// Verify everything exists
	s1, err := store.GetSession(ctx, spiffeID, "int-session-1")
	if err != nil || s1 == nil {
		t.Fatal("Session 1 should exist before deletion")
	}
	if len(s1.Actions) != 2 {
		t.Fatalf("Session 1 should have 2 actions, got %d", len(s1.Actions))
	}

	s2, err := store.GetSession(ctx, spiffeID, "int-session-2")
	if err != nil || s2 == nil {
		t.Fatal("Session 2 should exist before deletion")
	}

	tokens, _, err := rlStore.GetTokens(ctx, spiffeID)
	if err != nil || tokens < 0 {
		t.Fatal("Rate limit tokens should exist before deletion")
	}

	// Phase 3: Execute GDPR deletion
	result, err := GDPRDeleteAllData(ctx, client, spiffeID)
	if err != nil {
		t.Fatalf("GDPR deletion failed: %v", err)
	}

	// Phase 4: Verify everything is gone
	if result.SessionsFound != 2 {
		t.Errorf("Expected 2 sessions found, got %d", result.SessionsFound)
	}
	// 2 sessions * 2 keys + 2 rate limit keys + 1 GDPR set = 7
	if result.KeysDeleted != 7 {
		t.Errorf("Expected 7 keys deleted, got %d", result.KeysDeleted)
	}

	// Session 1 gone
	s1After, err := store.GetSession(ctx, spiffeID, "int-session-1")
	if err != nil {
		t.Fatalf("GetSession error after deletion: %v", err)
	}
	if s1After != nil {
		t.Error("Session 1 should be nil after GDPR deletion")
	}

	// Session 2 gone
	s2After, err := store.GetSession(ctx, spiffeID, "int-session-2")
	if err != nil {
		t.Fatalf("GetSession error after deletion: %v", err)
	}
	if s2After != nil {
		t.Error("Session 2 should be nil after GDPR deletion")
	}

	// Actions gone
	actions1, _ := store.GetRecentActions(ctx, spiffeID, "int-session-1", 100)
	if len(actions1) != 0 {
		t.Errorf("Session 1 actions should be empty after deletion, got %d", len(actions1))
	}

	actions2, _ := store.GetRecentActions(ctx, spiffeID, "int-session-2", 100)
	if len(actions2) != 0 {
		t.Errorf("Session 2 actions should be empty after deletion, got %d", len(actions2))
	}

	// Rate limit gone
	tokensAfter, _, err := rlStore.GetTokens(ctx, spiffeID)
	if err != nil {
		t.Fatalf("GetTokens error after deletion: %v", err)
	}
	if tokensAfter != -1 {
		t.Errorf("Rate limit tokens should return -1 (new bucket) after deletion, got %f", tokensAfter)
	}

	// GDPR set gone
	gdprMembers, err := client.SMembers(ctx, keyDBGDPRKey(spiffeID)).Result()
	if err != nil {
		t.Fatalf("SMembers error: %v", err)
	}
	if len(gdprMembers) != 0 {
		t.Errorf("GDPR set should be empty after deletion, got %d members", len(gdprMembers))
	}
}

func TestGDPRDeleteAllData_Integration_DoubleDelete(t *testing.T) {
	client, _ := newTestRedisClient(t)
	ctx := context.Background()

	spiffeID := "spiffe://poc.local/agents/double-delete"

	// Seed data
	seedSessionData(t, client, spiffeID, []string{"session-x"})

	// First deletion
	result1, err := GDPRDeleteAllData(ctx, client, spiffeID)
	if err != nil {
		t.Fatalf("First deletion failed: %v", err)
	}
	if result1.KeysDeleted == 0 {
		t.Error("First deletion should have deleted keys")
	}

	// Second deletion -- should be a no-op
	result2, err := GDPRDeleteAllData(ctx, client, spiffeID)
	if err != nil {
		t.Fatalf("Second deletion should not error: %v", err)
	}
	if result2.SessionsFound != 0 {
		t.Errorf("Second deletion should find 0 sessions, got %d", result2.SessionsFound)
	}
	if result2.KeysDeleted != 0 {
		t.Errorf("Second deletion should delete 0 keys, got %d", result2.KeysDeleted)
	}
}

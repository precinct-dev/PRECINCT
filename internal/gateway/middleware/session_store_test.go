// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// ---------------------------------------------------------------------------
// InMemoryStore Tests
// ---------------------------------------------------------------------------

func TestInMemoryStore_GetSession_NotFound(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()

	session, err := store.GetSession(ctx, "spiffe://test/agent", "nonexistent")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if session != nil {
		t.Error("Expected nil session for nonexistent key")
	}
}

func TestInMemoryStore_SaveAndGetSession(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	sessionID := "session-abc"
	session := &AgentSession{
		ID:                  sessionID,
		SPIFFEID:            spiffeID,
		StartTime:           time.Now(),
		Actions:             make([]ToolAction, 0),
		DataClassifications: []string{"sensitive"},
		RiskScore:           0.5,
		Flags:               make([]string, 0),
	}

	if err := store.SaveSession(ctx, spiffeID, sessionID, session); err != nil {
		t.Fatalf("SaveSession error: %v", err)
	}

	retrieved, err := store.GetSession(ctx, spiffeID, sessionID)
	if err != nil {
		t.Fatalf("GetSession error: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected session, got nil")
	}
	if retrieved.ID != sessionID {
		t.Errorf("Expected session ID %s, got %s", sessionID, retrieved.ID)
	}
	if retrieved.SPIFFEID != spiffeID {
		t.Errorf("Expected SPIFFE ID %s, got %s", spiffeID, retrieved.SPIFFEID)
	}
	if retrieved.RiskScore != 0.5 {
		t.Errorf("Expected risk score 0.5, got %f", retrieved.RiskScore)
	}
}

func TestInMemoryStore_AppendAction(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	sessionID := "session-def"
	session := &AgentSession{
		ID:       sessionID,
		SPIFFEID: spiffeID,
		Actions:  make([]ToolAction, 0),
	}
	_ = store.SaveSession(ctx, spiffeID, sessionID, session)

	action := ToolAction{
		Timestamp:      time.Now(),
		Tool:           "database_query",
		Resource:       "passwords",
		Classification: "sensitive",
		ExternalTarget: false,
	}

	if err := store.AppendAction(ctx, spiffeID, sessionID, action); err != nil {
		t.Fatalf("AppendAction error: %v", err)
	}

	// Verify action was appended
	retrieved, _ := store.GetSession(ctx, spiffeID, sessionID)
	if len(retrieved.Actions) != 1 {
		t.Fatalf("Expected 1 action, got %d", len(retrieved.Actions))
	}
	if retrieved.Actions[0].Tool != "database_query" {
		t.Errorf("Expected tool database_query, got %s", retrieved.Actions[0].Tool)
	}
}

func TestInMemoryStore_AppendAction_SessionNotFound(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()

	action := ToolAction{Tool: "test"}
	err := store.AppendAction(ctx, "spiffe://test", "nonexistent", action)
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}

func TestInMemoryStore_GetRecentActions(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	sessionID := "session-ghi"
	session := &AgentSession{
		ID:       sessionID,
		SPIFFEID: spiffeID,
		Actions: []ToolAction{
			{Tool: "action1"},
			{Tool: "action2"},
			{Tool: "action3"},
			{Tool: "action4"},
			{Tool: "action5"},
		},
	}
	_ = store.SaveSession(ctx, spiffeID, sessionID, session)

	// Get last 3 actions
	actions, err := store.GetRecentActions(ctx, spiffeID, sessionID, 3)
	if err != nil {
		t.Fatalf("GetRecentActions error: %v", err)
	}
	if len(actions) != 3 {
		t.Fatalf("Expected 3 actions, got %d", len(actions))
	}
	if actions[0].Tool != "action3" {
		t.Errorf("Expected action3, got %s", actions[0].Tool)
	}
	if actions[2].Tool != "action5" {
		t.Errorf("Expected action5, got %s", actions[2].Tool)
	}
}

func TestInMemoryStore_GetRecentActions_FewerThanRequested(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	sessionID := "session-jkl"
	session := &AgentSession{
		ID:       sessionID,
		SPIFFEID: spiffeID,
		Actions:  []ToolAction{{Tool: "only_one"}},
	}
	_ = store.SaveSession(ctx, spiffeID, sessionID, session)

	actions, err := store.GetRecentActions(ctx, spiffeID, sessionID, 10)
	if err != nil {
		t.Fatalf("GetRecentActions error: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("Expected 1 action, got %d", len(actions))
	}
}

func TestInMemoryStore_GetRecentActions_SessionNotFound(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()

	actions, err := store.GetRecentActions(ctx, "spiffe://test", "nonexistent", 5)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if actions != nil {
		t.Error("Expected nil actions for nonexistent session")
	}
}

// ---------------------------------------------------------------------------
// InMemoryStore TTL and Cleanup Tests
// ---------------------------------------------------------------------------

func TestInMemoryStore_SessionExpiresAfterTTL(t *testing.T) {
	store := NewInMemoryStoreWithTTL(100 * time.Millisecond)
	defer store.Close()
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	sessionID := "ttl-expire"
	session := &AgentSession{
		ID:       sessionID,
		SPIFFEID: spiffeID,
		Actions:  make([]ToolAction, 0),
	}

	if err := store.SaveSession(ctx, spiffeID, sessionID, session); err != nil {
		t.Fatalf("SaveSession error: %v", err)
	}

	// Session should be accessible before TTL
	retrieved, err := store.GetSession(ctx, spiffeID, sessionID)
	if err != nil {
		t.Fatalf("GetSession error: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Session should exist before TTL expiry")
	}

	// Wait past TTL
	time.Sleep(150 * time.Millisecond)

	// Session should be expired (inline check)
	retrieved, err = store.GetSession(ctx, spiffeID, sessionID)
	if err != nil {
		t.Fatalf("GetSession error after TTL: %v", err)
	}
	if retrieved != nil {
		t.Error("Session should have expired after TTL")
	}
}

func TestInMemoryStore_SessionValidBeforeTTL(t *testing.T) {
	store := NewInMemoryStoreWithTTL(2 * time.Second)
	defer store.Close()
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	sessionID := "ttl-valid"
	session := &AgentSession{
		ID:       sessionID,
		SPIFFEID: spiffeID,
		Actions:  make([]ToolAction, 0),
	}

	if err := store.SaveSession(ctx, spiffeID, sessionID, session); err != nil {
		t.Fatalf("SaveSession error: %v", err)
	}

	// Immediately retrieve -- should succeed
	retrieved, err := store.GetSession(ctx, spiffeID, sessionID)
	if err != nil {
		t.Fatalf("GetSession error: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Session should be valid before TTL expiry")
	}
	if retrieved.ID != sessionID {
		t.Errorf("Expected session ID %s, got %s", sessionID, retrieved.ID)
	}
}

func TestInMemoryStore_CleanupRemovesExpiredSessions(t *testing.T) {
	// Use a 100ms TTL so cleanup runs every 50ms (clamped to 1s minimum).
	// Since the minimum cleanup interval is 1 second, we use a TTL of 2s
	// and wait long enough for the cleanup to fire after expiry.
	store := NewInMemoryStoreWithTTL(2 * time.Second)
	defer store.Close()
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"

	// Save multiple sessions
	for i := 0; i < 5; i++ {
		sid := fmt.Sprintf("cleanup-%d", i)
		session := &AgentSession{
			ID:       sid,
			SPIFFEID: spiffeID,
			Actions:  make([]ToolAction, 0),
		}
		if err := store.SaveSession(ctx, spiffeID, sid, session); err != nil {
			t.Fatalf("SaveSession error for %s: %v", sid, err)
		}
	}

	// Verify all sessions exist
	for i := 0; i < 5; i++ {
		sid := fmt.Sprintf("cleanup-%d", i)
		s, _ := store.GetSession(ctx, spiffeID, sid)
		if s == nil {
			t.Fatalf("Session %s should exist before TTL", sid)
		}
	}

	// Manually trigger eviction rather than relying on timing-sensitive goroutine.
	// First wait for sessions to expire.
	time.Sleep(2100 * time.Millisecond)

	// Force eviction (the background loop would also do this, but explicit call
	// eliminates timing flakiness in CI).
	store.evictExpired()

	// Verify all sessions are gone
	store.mu.RLock()
	sessionCount := len(store.sessions)
	createdAtCount := len(store.createdAt)
	store.mu.RUnlock()

	if sessionCount != 0 {
		t.Errorf("Expected 0 sessions after cleanup, got %d", sessionCount)
	}
	if createdAtCount != 0 {
		t.Errorf("Expected 0 createdAt entries after cleanup, got %d", createdAtCount)
	}
}

func TestInMemoryStore_ConcurrentAccessDuringCleanup(t *testing.T) {
	store := NewInMemoryStoreWithTTL(50 * time.Millisecond)
	defer store.Close()
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"

	// Run concurrent saves and gets while cleanup is active
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			sid := fmt.Sprintf("concurrent-%d", i)
			session := &AgentSession{
				ID:       sid,
				SPIFFEID: spiffeID,
				Actions:  make([]ToolAction, 0),
			}
			_ = store.SaveSession(ctx, spiffeID, sid, session)
			_, _ = store.GetSession(ctx, spiffeID, sid)
			_ = store.AppendAction(ctx, spiffeID, sid, ToolAction{Tool: "test"})
			_, _ = store.GetRecentActions(ctx, spiffeID, sid, 5)
		}
	}()

	// Concurrently read sessions
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		for i := 0; i < 100; i++ {
			sid := fmt.Sprintf("concurrent-%d", i)
			_, _ = store.GetSession(ctx, spiffeID, sid)
		}
	}()

	<-done
	<-done2
	// If we reach here without a race condition panic, the test passes.
	// The -race flag will detect any data races.
}

func TestInMemoryStore_CloseStopsCleanupGoroutine(t *testing.T) {
	store := NewInMemoryStoreWithTTL(100 * time.Millisecond)

	// Close should not panic
	store.Close()

	// Double-close should not panic
	store.Close()

	// Operations after close should still work (store is usable, just no cleanup)
	ctx := context.Background()
	session := &AgentSession{
		ID:       "after-close",
		SPIFFEID: "spiffe://test/agent",
		Actions:  make([]ToolAction, 0),
	}
	if err := store.SaveSession(ctx, "spiffe://test/agent", "after-close", session); err != nil {
		t.Fatalf("SaveSession after Close should work: %v", err)
	}
	retrieved, err := store.GetSession(ctx, "spiffe://test/agent", "after-close")
	if err != nil {
		t.Fatalf("GetSession after Close should work: %v", err)
	}
	if retrieved == nil {
		t.Error("Session should be retrievable after Close (inline TTL check still works)")
	}
}

func TestInMemoryStore_DefaultTTLIsOneHour(t *testing.T) {
	store := NewInMemoryStore()
	defer store.Close()

	if store.ttl != time.Hour {
		t.Errorf("Expected default TTL of 1 hour, got %v", store.ttl)
	}
}

func TestInMemoryStore_SaveSessionPreservesOriginalCreatedAt(t *testing.T) {
	store := NewInMemoryStoreWithTTL(time.Hour)
	defer store.Close()
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	sessionID := "preserve-created"
	session := &AgentSession{
		ID:       sessionID,
		SPIFFEID: spiffeID,
		Actions:  make([]ToolAction, 0),
	}

	// First save
	if err := store.SaveSession(ctx, spiffeID, sessionID, session); err != nil {
		t.Fatalf("SaveSession error: %v", err)
	}

	store.mu.RLock()
	firstCreated := store.createdAt[sessionKey(spiffeID, sessionID)]
	store.mu.RUnlock()

	// Small delay then save again (update)
	time.Sleep(10 * time.Millisecond)
	session.RiskScore = 0.9
	if err := store.SaveSession(ctx, spiffeID, sessionID, session); err != nil {
		t.Fatalf("SaveSession (update) error: %v", err)
	}

	store.mu.RLock()
	secondCreated := store.createdAt[sessionKey(spiffeID, sessionID)]
	store.mu.RUnlock()

	// createdAt should not have changed on update
	if !firstCreated.Equal(secondCreated) {
		t.Errorf("createdAt should be preserved on update: first=%v, second=%v", firstCreated, secondCreated)
	}
}

// ---------------------------------------------------------------------------
// KeyDBStore Tests (using miniredis)
// ---------------------------------------------------------------------------

func newTestKeyDBStore(t *testing.T) (*KeyDBStore, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	store := NewKeyDBStoreFromClient(client, 3600)
	t.Cleanup(func() { _ = store.Close() })

	return store, mr
}

func TestKeyDBStore_GetSession_NotFound(t *testing.T) {
	store, _ := newTestKeyDBStore(t)
	ctx := context.Background()

	session, err := store.GetSession(ctx, "spiffe://test/agent", "nonexistent")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if session != nil {
		t.Error("Expected nil session for nonexistent key")
	}
}

func TestKeyDBStore_SaveAndGetSession(t *testing.T) {
	store, _ := newTestKeyDBStore(t)
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	sessionID := "session-keydb-1"
	session := &AgentSession{
		ID:                  sessionID,
		SPIFFEID:            spiffeID,
		StartTime:           time.Now().UTC().Truncate(time.Second), // Truncate for JSON round-trip
		Actions:             make([]ToolAction, 0),
		DataClassifications: []string{"sensitive", "internal"},
		RiskScore:           0.75,
		Flags:               []string{"high_risk"},
	}

	if err := store.SaveSession(ctx, spiffeID, sessionID, session); err != nil {
		t.Fatalf("SaveSession error: %v", err)
	}

	retrieved, err := store.GetSession(ctx, spiffeID, sessionID)
	if err != nil {
		t.Fatalf("GetSession error: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected session, got nil")
	}
	if retrieved.ID != sessionID {
		t.Errorf("Expected session ID %s, got %s", sessionID, retrieved.ID)
	}
	if retrieved.SPIFFEID != spiffeID {
		t.Errorf("Expected SPIFFE ID %s, got %s", spiffeID, retrieved.SPIFFEID)
	}
	if retrieved.RiskScore != 0.75 {
		t.Errorf("Expected risk score 0.75, got %f", retrieved.RiskScore)
	}
	if len(retrieved.DataClassifications) != 2 {
		t.Errorf("Expected 2 data classifications, got %d", len(retrieved.DataClassifications))
	}
	if len(retrieved.Flags) != 1 || retrieved.Flags[0] != "high_risk" {
		t.Errorf("Expected flags [high_risk], got %v", retrieved.Flags)
	}
}

func TestKeyDBStore_AppendAndGetActions(t *testing.T) {
	store, _ := newTestKeyDBStore(t)
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	sessionID := "session-keydb-2"

	// Save a session first
	session := &AgentSession{
		ID:       sessionID,
		SPIFFEID: spiffeID,
		Actions:  make([]ToolAction, 0),
	}
	_ = store.SaveSession(ctx, spiffeID, sessionID, session)

	// Append actions
	actions := []ToolAction{
		{Timestamp: time.Now().UTC(), Tool: "database_query", Resource: "users", Classification: "sensitive", ExternalTarget: false},
		{Timestamp: time.Now().UTC(), Tool: "file_read", Resource: "config", Classification: "internal", ExternalTarget: false},
		{Timestamp: time.Now().UTC(), Tool: "email_send", Classification: "public", ExternalTarget: true, DestinationDomain: "evil.com"},
	}

	for _, action := range actions {
		if err := store.AppendAction(ctx, spiffeID, sessionID, action); err != nil {
			t.Fatalf("AppendAction error: %v", err)
		}
	}

	// Get all actions via GetSession
	retrieved, err := store.GetSession(ctx, spiffeID, sessionID)
	if err != nil {
		t.Fatalf("GetSession error: %v", err)
	}
	if len(retrieved.Actions) != 3 {
		t.Fatalf("Expected 3 actions, got %d", len(retrieved.Actions))
	}
	if retrieved.Actions[0].Tool != "database_query" {
		t.Errorf("Expected first action database_query, got %s", retrieved.Actions[0].Tool)
	}
	if retrieved.Actions[2].Tool != "email_send" {
		t.Errorf("Expected last action email_send, got %s", retrieved.Actions[2].Tool)
	}
	if !retrieved.Actions[2].ExternalTarget {
		t.Error("Expected last action to be external target")
	}
}

func TestKeyDBStore_GetRecentActions(t *testing.T) {
	store, _ := newTestKeyDBStore(t)
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	sessionID := "session-keydb-3"

	// Save session and append 5 actions
	session := &AgentSession{
		ID:       sessionID,
		SPIFFEID: spiffeID,
		Actions:  make([]ToolAction, 0),
	}
	_ = store.SaveSession(ctx, spiffeID, sessionID, session)

	for i := 0; i < 5; i++ {
		action := ToolAction{
			Timestamp: time.Now().UTC(),
			Tool:      "tool_" + string(rune('A'+i)),
		}
		_ = store.AppendAction(ctx, spiffeID, sessionID, action)
	}

	// Get last 3
	recent, err := store.GetRecentActions(ctx, spiffeID, sessionID, 3)
	if err != nil {
		t.Fatalf("GetRecentActions error: %v", err)
	}
	if len(recent) != 3 {
		t.Fatalf("Expected 3 recent actions, got %d", len(recent))
	}
	if recent[0].Tool != "tool_C" {
		t.Errorf("Expected tool_C, got %s", recent[0].Tool)
	}
	if recent[2].Tool != "tool_E" {
		t.Errorf("Expected tool_E, got %s", recent[2].Tool)
	}
}

func TestKeyDBStore_SessionTTL(t *testing.T) {
	store, mr := newTestKeyDBStore(t)
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	sessionID := "session-ttl"
	session := &AgentSession{
		ID:       sessionID,
		SPIFFEID: spiffeID,
		Actions:  make([]ToolAction, 0),
	}

	_ = store.SaveSession(ctx, spiffeID, sessionID, session)

	// Verify session exists
	retrieved, _ := store.GetSession(ctx, spiffeID, sessionID)
	if retrieved == nil {
		t.Fatal("Session should exist before TTL expiry")
	}

	// Check that TTL is set on the session key
	key := keyDBSessionKey(spiffeID, sessionID)
	ttl := mr.TTL(key)
	if ttl <= 0 {
		t.Errorf("Expected positive TTL on session key, got %v", ttl)
	}
	if ttl > 3600*time.Second {
		t.Errorf("Expected TTL <= 3600s, got %v", ttl)
	}

	// Fast-forward time to expire session
	mr.FastForward(3601 * time.Second)

	// Session should be gone
	retrieved, _ = store.GetSession(ctx, spiffeID, sessionID)
	if retrieved != nil {
		t.Error("Session should have expired after TTL")
	}
}

func TestKeyDBStore_GDPRTracking(t *testing.T) {
	store, mr := newTestKeyDBStore(t)
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"

	// Save multiple sessions for same SPIFFE ID
	for _, sid := range []string{"session-1", "session-2", "session-3"} {
		session := &AgentSession{
			ID:       sid,
			SPIFFEID: spiffeID,
			Actions:  make([]ToolAction, 0),
		}
		_ = store.SaveSession(ctx, spiffeID, sid, session)
	}

	// Verify GDPR tracking set contains all session IDs
	gdprKey := keyDBGDPRKey(spiffeID)
	members, err := mr.Members(gdprKey)
	if err != nil {
		t.Fatalf("Failed to read GDPR set: %v", err)
	}
	if len(members) != 3 {
		t.Errorf("Expected 3 session IDs in GDPR set, got %d: %v", len(members), members)
	}
}

func TestKeyDBStore_Ping(t *testing.T) {
	store, _ := newTestKeyDBStore(t)
	ctx := context.Background()

	if err := store.Ping(ctx); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
}

func TestKeyDBStore_ActionsTTL(t *testing.T) {
	store, mr := newTestKeyDBStore(t)
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	sessionID := "session-actions-ttl"

	// Save session and append action
	session := &AgentSession{
		ID:       sessionID,
		SPIFFEID: spiffeID,
		Actions:  make([]ToolAction, 0),
	}
	_ = store.SaveSession(ctx, spiffeID, sessionID, session)
	_ = store.AppendAction(ctx, spiffeID, sessionID, ToolAction{Tool: "test_tool"})

	// Verify actions key has TTL
	actionsKey := keyDBActionsKey(spiffeID, sessionID)
	ttl := mr.TTL(actionsKey)
	if ttl <= 0 {
		t.Errorf("Expected positive TTL on actions key, got %v", ttl)
	}

	// Fast-forward to expire
	mr.FastForward(3601 * time.Second)

	actions, _ := store.GetRecentActions(ctx, spiffeID, sessionID, 10)
	if len(actions) != 0 {
		t.Error("Actions should have expired after TTL")
	}
}

// ---------------------------------------------------------------------------
// Cross-request exfiltration detection via KeyDB
// ---------------------------------------------------------------------------

func TestKeyDBStore_CrossRequestExfiltrationDetection(t *testing.T) {
	store, _ := newTestKeyDBStore(t)
	sc := NewSessionContext(store)

	spiffeID := "spiffe://poc.local/agents/attacker"
	sessionID := "cross-request-session"

	// --- Request 1: Read sensitive data ---
	session := sc.GetOrCreateSession(spiffeID, sessionID)
	if session == nil {
		t.Fatal("Failed to create session")
	}

	action1 := ToolAction{
		Timestamp:      time.Now(),
		Tool:           "database_query",
		Resource:       "user_passwords",
		Classification: "sensitive",
		ExternalTarget: false,
	}
	sc.RecordAction(session, action1)

	// Should NOT detect exfiltration yet (only one action)
	if sc.DetectsExfiltrationPattern(session) {
		t.Error("Should not detect exfiltration after just reading sensitive data")
	}

	// --- Simulate new request by re-loading session from store ---
	// This proves sessions persist across HTTP requests via KeyDB
	session2 := sc.GetOrCreateSession(spiffeID, sessionID)
	if session2 == nil {
		t.Fatal("Failed to retrieve session on second request")
	}

	// Verify the session was loaded from KeyDB with the action from request 1
	if len(session2.Actions) != 1 {
		t.Fatalf("Expected 1 action from previous request, got %d", len(session2.Actions))
	}
	if session2.Actions[0].Tool != "database_query" {
		t.Errorf("Expected database_query from previous request, got %s", session2.Actions[0].Tool)
	}

	// --- Request 2: Attempt exfiltration ---
	action2 := ToolAction{
		Timestamp:         time.Now(),
		Tool:              "email_send",
		Resource:          "",
		Classification:    "",
		ExternalTarget:    true,
		DestinationDomain: "evil.com",
	}
	sc.RecordAction(session2, action2)

	// NOW it should detect exfiltration: sensitive read (req 1) + external send (req 2)
	if !sc.DetectsExfiltrationPattern(session2) {
		t.Error("CRITICAL: Cross-request exfiltration NOT detected. " +
			"Session from request 1 (sensitive read) should combine with " +
			"request 2 (external send) to trigger detection")
	}
}

func TestKeyDBStore_SameSessionRetrieved(t *testing.T) {
	store, _ := newTestKeyDBStore(t)
	sc := NewSessionContext(store)

	spiffeID := "spiffe://poc.local/agents/test"
	sessionID := "persistent-session"

	// Create session
	session1 := sc.GetOrCreateSession(spiffeID, sessionID)
	if session1.ID != sessionID {
		t.Errorf("Expected session ID %s, got %s", sessionID, session1.ID)
	}

	// Record an action
	sc.RecordAction(session1, ToolAction{Tool: "action_a", Classification: "internal"})

	// Retrieve again (simulating new request)
	session2 := sc.GetOrCreateSession(spiffeID, sessionID)
	if session2.ID != sessionID {
		t.Errorf("Expected same session ID %s, got %s", sessionID, session2.ID)
	}
	if session2.SPIFFEID != spiffeID {
		t.Errorf("Expected same SPIFFE ID %s, got %s", spiffeID, session2.SPIFFEID)
	}
	if len(session2.Actions) != 1 {
		t.Errorf("Expected 1 action persisted across requests, got %d", len(session2.Actions))
	}
}

// ---------------------------------------------------------------------------
// InMemoryStore fallback behavior (Phase 1 compatibility)
// ---------------------------------------------------------------------------

func TestInMemoryStore_ExfiltrationDetection(t *testing.T) {
	store := NewInMemoryStore()
	sc := NewSessionContext(store)

	spiffeID := "spiffe://test/agent"
	sessionID := "memory-session"

	session := sc.GetOrCreateSession(spiffeID, sessionID)

	// Read sensitive data
	sc.RecordAction(session, ToolAction{
		Tool:           "database_query",
		Resource:       "api_keys",
		Classification: "sensitive",
		ExternalTarget: false,
	})

	// Attempt exfiltration
	sc.RecordAction(session, ToolAction{
		Tool:           "http_request",
		ExternalTarget: true,
	})

	if !sc.DetectsExfiltrationPattern(session) {
		t.Error("InMemoryStore should detect exfiltration within same process")
	}
}

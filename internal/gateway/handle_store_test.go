// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"
)

// TestHandleStoreStoreAndGet verifies basic store and retrieve functionality
func TestHandleStoreStoreAndGet(t *testing.T) {
	store := NewHandleStore(5 * time.Second)
	defer store.Close()

	rawData := []byte(`{"results": [{"id": 1, "amount": 5000}]}`)
	spiffeID := "spiffe://poc.local/agents/test/dev"
	toolName := "database_query"

	ref, err := store.Store(rawData, spiffeID, toolName)
	if err != nil {
		t.Fatalf("Failed to store handle: %v", err)
	}

	if ref == "" {
		t.Fatal("Expected non-empty reference")
	}

	// Retrieve the entry
	entry := store.Get(ref)
	if entry == nil {
		t.Fatal("Expected entry, got nil")
	}

	if string(entry.RawData) != string(rawData) {
		t.Errorf("Expected raw data %q, got %q", rawData, entry.RawData)
	}
	if entry.SPIFFEID != spiffeID {
		t.Errorf("Expected SPIFFE ID %q, got %q", spiffeID, entry.SPIFFEID)
	}
	if entry.ToolName != toolName {
		t.Errorf("Expected tool name %q, got %q", toolName, entry.ToolName)
	}
	if entry.Ref != ref {
		t.Errorf("Expected ref %q, got %q", ref, entry.Ref)
	}
}

// TestHandleStoreExpiry verifies that expired handles return nil
func TestHandleStoreExpiry(t *testing.T) {
	// Use a very short TTL to test expiry
	store := NewHandleStore(50 * time.Millisecond)
	defer store.Close()

	ref, err := store.Store([]byte(`{"data": "secret"}`), "spiffe://poc.local/agents/test/dev", "sensitive_tool")
	if err != nil {
		t.Fatalf("Failed to store handle: %v", err)
	}

	// Should be retrievable immediately
	entry := store.Get(ref)
	if entry == nil {
		t.Fatal("Expected entry before expiry, got nil")
	}

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	// Should be nil after expiry
	entry = store.Get(ref)
	if entry != nil {
		t.Error("Expected nil after expiry, got entry")
	}
}

// TestHandleStoreNonExistentRef verifies that non-existent refs return nil
func TestHandleStoreNonExistentRef(t *testing.T) {
	store := NewHandleStore(5 * time.Second)
	defer store.Close()

	entry := store.Get("nonexistent_ref")
	if entry != nil {
		t.Error("Expected nil for non-existent ref, got entry")
	}
}

// TestHandleStoreCount verifies the count of active entries
func TestHandleStoreCount(t *testing.T) {
	store := NewHandleStore(5 * time.Second)
	defer store.Close()

	if store.Count() != 0 {
		t.Errorf("Expected 0 entries, got %d", store.Count())
	}

	_, _ = store.Store([]byte("data1"), "spiffe://a", "tool1")
	_, _ = store.Store([]byte("data2"), "spiffe://b", "tool2")

	if store.Count() != 2 {
		t.Errorf("Expected 2 entries, got %d", store.Count())
	}
}

// TestHandleStoreDelete verifies explicit deletion of entries
func TestHandleStoreDelete(t *testing.T) {
	store := NewHandleStore(5 * time.Second)
	defer store.Close()

	ref, _ := store.Store([]byte("data"), "spiffe://a", "tool1")

	// Verify it exists
	if store.Get(ref) == nil {
		t.Fatal("Entry should exist before deletion")
	}

	// Delete it
	store.Delete(ref)

	// Verify it's gone
	if store.Get(ref) != nil {
		t.Error("Entry should be nil after deletion")
	}
}

// TestHandleEntryExpired verifies the Expired method
func TestHandleEntryExpired(t *testing.T) {
	t.Run("NotExpired", func(t *testing.T) {
		entry := &HandleEntry{
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		if entry.Expired() {
			t.Error("Entry should not be expired")
		}
	})

	t.Run("Expired", func(t *testing.T) {
		entry := &HandleEntry{
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		if !entry.Expired() {
			t.Error("Entry should be expired")
		}
	})
}

// TestFormatHandle verifies the handle string format
func TestFormatHandle(t *testing.T) {
	result := FormatHandle("abc123", 300)
	expected := "$DATA{ref:abc123,exp:300}"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// TestHandleStoreUniqueRefs verifies that each store call generates a unique reference
func TestHandleStoreUniqueRefs(t *testing.T) {
	store := NewHandleStore(5 * time.Second)
	defer store.Close()

	refs := make(map[string]bool)
	for i := 0; i < 100; i++ {
		ref, err := store.Store([]byte("data"), "spiffe://a", "tool")
		if err != nil {
			t.Fatalf("Failed to store handle on iteration %d: %v", i, err)
		}
		if refs[ref] {
			t.Fatalf("Duplicate reference generated: %s", ref)
		}
		refs[ref] = true
	}
}

// TestHandleRefHas128BitEntropy verifies that generateRef produces 32 hex characters (16 bytes / 128 bits)
func TestHandleRefHas128BitEntropy(t *testing.T) {
	ref, err := generateRef()
	if err != nil {
		t.Fatalf("generateRef failed: %v", err)
	}

	if len(ref) != 32 {
		t.Errorf("Expected 32 hex characters (128-bit entropy), got %d characters: %q", len(ref), ref)
	}

	// Verify all characters are valid hex
	for i, c := range ref {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("Invalid hex character at position %d: %c", i, c)
		}
	}

	// Verify uniqueness across multiple calls (statistical sanity check)
	refs := make(map[string]bool)
	for i := 0; i < 50; i++ {
		r, err := generateRef()
		if err != nil {
			t.Fatalf("generateRef failed on iteration %d: %v", i, err)
		}
		if len(r) != 32 {
			t.Errorf("Iteration %d: expected 32 hex chars, got %d", i, len(r))
		}
		if refs[r] {
			t.Fatalf("Duplicate ref generated on iteration %d: %s", i, r)
		}
		refs[r] = true
	}
}

// TestHandleStoreEvictExpired verifies that the eviction function works
func TestHandleStoreEvictExpired(t *testing.T) {
	store := NewHandleStore(50 * time.Millisecond)
	defer store.Close()

	_, _ = store.Store([]byte("data1"), "spiffe://a", "tool1")
	_, _ = store.Store([]byte("data2"), "spiffe://b", "tool2")

	if store.Count() != 2 {
		t.Fatalf("Expected 2 entries, got %d", store.Count())
	}

	// Wait for entries to expire
	time.Sleep(100 * time.Millisecond)

	// Manually trigger eviction
	store.evictExpired()

	if store.Count() != 0 {
		t.Errorf("Expected 0 entries after eviction, got %d", store.Count())
	}
}

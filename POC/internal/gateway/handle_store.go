// Handle Store - RFA-qq0.16
// In-memory cache for handle-ized tool responses.
// Stores raw response data with TTL and SPIFFE ID binding.
// Handles are opaque references in the format $DATA{ref:<hex>,exp:<seconds>}.
// Only the SPIFFE ID that originated the request can dereference the handle.
package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// HandleEntry represents a stored handle with its associated data
type HandleEntry struct {
	Ref       string    // Hex reference ID
	RawData   []byte    // The raw response data from the upstream tool
	SPIFFEID  string    // The SPIFFE ID that owns this handle
	ExpiresAt time.Time // When the handle expires
	ToolName  string    // The tool that produced this response
	CreatedAt time.Time // When the handle was created
}

// Expired returns true if the handle has passed its TTL
func (h *HandleEntry) Expired() bool {
	return time.Now().After(h.ExpiresAt)
}

// HandleStore is a thread-safe in-memory cache for handle-ized response data.
// Each entry is bound to a SPIFFE ID and has a configurable TTL.
type HandleStore struct {
	mu      sync.RWMutex
	entries map[string]*HandleEntry // ref -> entry
	ttl     time.Duration           // default TTL for new entries
	stopCh  chan struct{}           // signal to stop cleanup goroutine
}

// NewHandleStore creates a new handle store with the given default TTL.
// It starts a background goroutine that evicts expired entries every 30 seconds.
func NewHandleStore(ttl time.Duration) *HandleStore {
	hs := &HandleStore{
		entries: make(map[string]*HandleEntry),
		ttl:     ttl,
		stopCh:  make(chan struct{}),
	}

	// Start background cleanup
	go hs.cleanupLoop()

	return hs
}

// Store saves raw response data and returns a handle reference.
// The handle is bound to the given SPIFFE ID and expires after the store's TTL.
func (hs *HandleStore) Store(rawData []byte, spiffeID, toolName string) (string, error) {
	ref, err := generateRef()
	if err != nil {
		return "", fmt.Errorf("failed to generate handle reference: %w", err)
	}

	entry := &HandleEntry{
		Ref:       ref,
		RawData:   rawData,
		SPIFFEID:  spiffeID,
		ExpiresAt: time.Now().Add(hs.ttl),
		ToolName:  toolName,
		CreatedAt: time.Now(),
	}

	hs.mu.Lock()
	hs.entries[ref] = entry
	hs.mu.Unlock()

	return ref, nil
}

// Get retrieves a handle entry by reference.
// Returns nil if the handle does not exist or has expired.
// Expired handles are removed on access.
func (hs *HandleStore) Get(ref string) *HandleEntry {
	hs.mu.RLock()
	entry, exists := hs.entries[ref]
	hs.mu.RUnlock()

	if !exists {
		return nil
	}

	if entry.Expired() {
		// Remove expired entry
		hs.mu.Lock()
		delete(hs.entries, ref)
		hs.mu.Unlock()
		return nil
	}

	return entry
}

// Delete removes a handle entry by reference
func (hs *HandleStore) Delete(ref string) {
	hs.mu.Lock()
	delete(hs.entries, ref)
	hs.mu.Unlock()
}

// Count returns the number of active (non-expired) entries
func (hs *HandleStore) Count() int {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	return len(hs.entries)
}

// Close stops the background cleanup goroutine
func (hs *HandleStore) Close() {
	close(hs.stopCh)
}

// cleanupLoop periodically removes expired entries
func (hs *HandleStore) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hs.evictExpired()
		case <-hs.stopCh:
			return
		}
	}
}

// evictExpired removes all expired entries
func (hs *HandleStore) evictExpired() {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	now := time.Now()
	for ref, entry := range hs.entries {
		if now.After(entry.ExpiresAt) {
			delete(hs.entries, ref)
		}
	}
}

// FormatHandle returns the handle string in the standard format: $DATA{ref:<hex>,exp:<seconds>}
func FormatHandle(ref string, ttlSeconds int) string {
	return fmt.Sprintf("$DATA{ref:%s,exp:%d}", ref, ttlSeconds)
}

// generateRef creates a cryptographically random 6-byte hex reference
func generateRef() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

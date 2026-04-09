// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// sessionState represents the lifecycle state of an MCP session.
type sessionState int

const (
	stateCreated sessionState = iota
	stateActive
	stateExpired
)

// session represents a single MCP client session.
type session struct {
	id         string
	state      sessionState
	createdAt  time.Time
	lastAccess time.Time
	mu         sync.Mutex // per-session lock for serial execution
}

// sessionStore manages all active sessions with thread-safe access.
type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*session
}

// newSessionStore creates an empty session store.
func newSessionStore() *sessionStore {
	return &sessionStore{
		sessions: make(map[string]*session),
	}
}

// create generates a new session with a UUID v4 ID in "created" state.
func (ss *sessionStore) create() *session {
	s := &session{
		id:         uuid.New().String(),
		state:      stateCreated,
		createdAt:  time.Now(),
		lastAccess: time.Now(),
	}
	ss.mu.Lock()
	ss.sessions[s.id] = s
	ss.mu.Unlock()
	return s
}

// get looks up a session by ID. It returns false if the session is not
// found. It does NOT update lastAccess -- callers that want to refresh
// the session should call touch separately after validating state.
func (ss *sessionStore) get(id string) (*session, bool) {
	ss.mu.RLock()
	s, ok := ss.sessions[id]
	ss.mu.RUnlock()
	return s, ok
}

// markActive transitions a session from "created" to "active".
func (ss *sessionStore) markActive(id string) {
	ss.mu.RLock()
	s, ok := ss.sessions[id]
	ss.mu.RUnlock()
	if !ok {
		return
	}
	s.mu.Lock()
	s.state = stateActive
	s.lastAccess = time.Now()
	s.mu.Unlock()
}

// delete removes a session from the store immediately.
func (ss *sessionStore) delete(id string) {
	ss.mu.Lock()
	delete(ss.sessions, id)
	ss.mu.Unlock()
}

// isExpired reports whether the session's lastAccess exceeds the idle
// timeout. A zero timeout means sessions never expire.
func (s *session) isExpired(idleTimeout time.Duration) bool {
	if idleTimeout == 0 {
		return false
	}
	s.mu.Lock()
	expired := time.Since(s.lastAccess) > idleTimeout
	s.mu.Unlock()
	return expired
}

// touch updates the session's lastAccess timestamp.
func (s *session) touch() {
	s.mu.Lock()
	s.lastAccess = time.Now()
	s.mu.Unlock()
}

// getState returns the session state under the mutex.
func (s *session) getState() sessionState {
	s.mu.Lock()
	st := s.state
	s.mu.Unlock()
	return st
}

// cleanup removes sessions whose lastAccess exceeds the idle timeout.
func (ss *sessionStore) cleanup(idleTimeout time.Duration) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for id, s := range ss.sessions {
		if s.isExpired(idleTimeout) {
			delete(ss.sessions, id)
		}
	}
}

// startCleanup launches a background goroutine that periodically removes
// expired sessions. It stops when the context is cancelled.
func (ss *sessionStore) startCleanup(ctx context.Context, interval time.Duration, idleTimeout time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ss.cleanup(idleTimeout)
			}
		}
	}()
}

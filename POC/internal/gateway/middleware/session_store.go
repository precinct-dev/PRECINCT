package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// SessionStore defines the storage interface for session context middleware.
// Implementations must be safe for concurrent use.
type SessionStore interface {
	// GetSession retrieves an existing session or returns nil if not found.
	GetSession(ctx context.Context, spiffeID, sessionID string) (*AgentSession, error)

	// SaveSession persists the full session state.
	SaveSession(ctx context.Context, spiffeID, sessionID string, session *AgentSession) error

	// AppendAction adds a tool action to the session's action list.
	AppendAction(ctx context.Context, spiffeID, sessionID string, action ToolAction) error

	// GetRecentActions returns the most recent N actions for a session.
	GetRecentActions(ctx context.Context, spiffeID, sessionID string, count int) ([]ToolAction, error)
}

// ---------------------------------------------------------------------------
// InMemoryStore -- wraps the original sync.Map-based logic (Phase 1 behavior)
// ---------------------------------------------------------------------------

// InMemoryStore provides an in-memory implementation of SessionStore.
// Safe for concurrent use via internal mutex.
type InMemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*AgentSession
}

// NewInMemoryStore creates a new InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		sessions: make(map[string]*AgentSession),
	}
}

func sessionKey(spiffeID, sessionID string) string {
	return spiffeID + ":" + sessionID
}

func (s *InMemoryStore) GetSession(_ context.Context, spiffeID, sessionID string) (*AgentSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, exists := s.sessions[sessionKey(spiffeID, sessionID)]
	if !exists {
		return nil, nil
	}
	return session, nil
}

func (s *InMemoryStore) SaveSession(_ context.Context, spiffeID, sessionID string, session *AgentSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionKey(spiffeID, sessionID)] = session
	return nil
}

func (s *InMemoryStore) AppendAction(_ context.Context, spiffeID, sessionID string, action ToolAction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sessionKey(spiffeID, sessionID)
	session, exists := s.sessions[key]
	if !exists {
		return fmt.Errorf("session not found: %s", key)
	}
	session.Actions = append(session.Actions, action)
	return nil
}

func (s *InMemoryStore) GetRecentActions(_ context.Context, spiffeID, sessionID string, count int) ([]ToolAction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := sessionKey(spiffeID, sessionID)
	session, exists := s.sessions[key]
	if !exists {
		return nil, nil
	}
	actions := session.Actions
	if len(actions) <= count {
		result := make([]ToolAction, len(actions))
		copy(result, actions)
		return result, nil
	}
	result := make([]ToolAction, count)
	copy(result, actions[len(actions)-count:])
	return result, nil
}

// ---------------------------------------------------------------------------
// KeyDBStore -- Redis/KeyDB-backed implementation for cross-request persistence
// ---------------------------------------------------------------------------

// KeyDBStore provides a KeyDB/Redis-backed implementation of SessionStore.
// Data model:
//   - session:{spiffe_id}:{session_id}          -> JSON AgentSession, TTL=sessionTTL
//   - session:{spiffe_id}:{session_id}:actions   -> LIST of JSON ToolAction, TTL=sessionTTL
//   - gdpr:sessions:{spiffe_id}                  -> SET of session_ids (for right-to-deletion)
type KeyDBStore struct {
	client     *redis.Client
	sessionTTL time.Duration
}

// NewKeyDBStore creates a new KeyDBStore connecting to the given KeyDB/Redis URL.
// poolMin and poolMax configure the connection pool. sessionTTL is in seconds.
func NewKeyDBStore(url string, poolMin, poolMax, sessionTTLSeconds int) *KeyDBStore {
	opts, err := redis.ParseURL(url)
	if err != nil {
		// Fall back to simple address parsing for non-URL formats like "localhost:6379"
		opts = &redis.Options{
			Addr: url,
		}
	}
	opts.MinIdleConns = poolMin
	opts.PoolSize = poolMax

	return &KeyDBStore{
		client:     redis.NewClient(opts),
		sessionTTL: time.Duration(sessionTTLSeconds) * time.Second,
	}
}

// NewKeyDBStoreFromClient creates a KeyDBStore from an existing redis.Client.
// Useful for testing with miniredis.
func NewKeyDBStoreFromClient(client *redis.Client, sessionTTLSeconds int) *KeyDBStore {
	return &KeyDBStore{
		client:     client,
		sessionTTL: time.Duration(sessionTTLSeconds) * time.Second,
	}
}

func keyDBSessionKey(spiffeID, sessionID string) string {
	return "session:" + spiffeID + ":" + sessionID
}

func keyDBActionsKey(spiffeID, sessionID string) string {
	return "session:" + spiffeID + ":" + sessionID + ":actions"
}

func keyDBGDPRKey(spiffeID string) string {
	return "gdpr:sessions:" + spiffeID
}

func (s *KeyDBStore) GetSession(ctx context.Context, spiffeID, sessionID string) (*AgentSession, error) {
	key := keyDBSessionKey(spiffeID, sessionID)
	data, err := s.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("keydb get session: %w", err)
	}

	var session AgentSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("keydb unmarshal session: %w", err)
	}

	// Load actions from the actions list
	actions, err := s.loadActions(ctx, spiffeID, sessionID)
	if err != nil {
		return nil, err
	}
	session.Actions = actions

	return &session, nil
}

func (s *KeyDBStore) SaveSession(ctx context.Context, spiffeID, sessionID string, session *AgentSession) error {
	key := keyDBSessionKey(spiffeID, sessionID)

	// Store session metadata (without actions -- actions are in a separate LIST)
	sessionCopy := *session
	sessionCopy.Actions = nil // Actions stored separately in LIST

	data, err := json.Marshal(sessionCopy)
	if err != nil {
		return fmt.Errorf("keydb marshal session: %w", err)
	}

	if err := s.client.Set(ctx, key, data, s.sessionTTL).Err(); err != nil {
		return fmt.Errorf("keydb set session: %w", err)
	}

	// Track session ID in GDPR set for right-to-deletion
	gdprKey := keyDBGDPRKey(spiffeID)
	if err := s.client.SAdd(ctx, gdprKey, sessionID).Err(); err != nil {
		return fmt.Errorf("keydb sadd gdpr: %w", err)
	}
	// Refresh TTL on the GDPR tracking set
	s.client.Expire(ctx, gdprKey, s.sessionTTL)

	return nil
}

func (s *KeyDBStore) AppendAction(ctx context.Context, spiffeID, sessionID string, action ToolAction) error {
	actionsKey := keyDBActionsKey(spiffeID, sessionID)

	data, err := json.Marshal(action)
	if err != nil {
		return fmt.Errorf("keydb marshal action: %w", err)
	}

	if err := s.client.RPush(ctx, actionsKey, data).Err(); err != nil {
		return fmt.Errorf("keydb rpush action: %w", err)
	}
	// Refresh TTL on actions list
	s.client.Expire(ctx, actionsKey, s.sessionTTL)

	return nil
}

func (s *KeyDBStore) GetRecentActions(ctx context.Context, spiffeID, sessionID string, count int) ([]ToolAction, error) {
	actionsKey := keyDBActionsKey(spiffeID, sessionID)

	// LRANGE with negative indices to get the last N items
	start := int64(-count)
	stop := int64(-1)

	results, err := s.client.LRange(ctx, actionsKey, start, stop).Result()
	if err != nil {
		return nil, fmt.Errorf("keydb lrange actions: %w", err)
	}

	actions := make([]ToolAction, 0, len(results))
	for _, raw := range results {
		var action ToolAction
		if err := json.Unmarshal([]byte(raw), &action); err != nil {
			return nil, fmt.Errorf("keydb unmarshal action: %w", err)
		}
		actions = append(actions, action)
	}

	return actions, nil
}

// loadActions retrieves all actions from the actions list.
func (s *KeyDBStore) loadActions(ctx context.Context, spiffeID, sessionID string) ([]ToolAction, error) {
	actionsKey := keyDBActionsKey(spiffeID, sessionID)

	results, err := s.client.LRange(ctx, actionsKey, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("keydb lrange all actions: %w", err)
	}

	actions := make([]ToolAction, 0, len(results))
	for _, raw := range results {
		var action ToolAction
		if err := json.Unmarshal([]byte(raw), &action); err != nil {
			return nil, fmt.Errorf("keydb unmarshal action: %w", err)
		}
		actions = append(actions, action)
	}

	return actions, nil
}

// Close closes the KeyDB client connection.
func (s *KeyDBStore) Close() error {
	return s.client.Close()
}

// Ping checks the KeyDB connection health.
func (s *KeyDBStore) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

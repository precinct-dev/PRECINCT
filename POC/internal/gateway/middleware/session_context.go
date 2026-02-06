package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// GenerateID generates a unique identifier
func GenerateID() string {
	return uuid.New().String()
}

// SessionContext manages agent sessions and tracks behavior.
// It delegates storage to a SessionStore implementation (InMemoryStore or KeyDBStore).
type SessionContext struct {
	store SessionStore
}

// AgentSession represents a single agent's session
type AgentSession struct {
	ID                  string
	SPIFFEID            string
	StartTime           time.Time
	Actions             []ToolAction
	DataClassifications []string
	RiskScore           float64
	Flags               []string
}

// ToolAction represents a single tool invocation
type ToolAction struct {
	Timestamp         time.Time
	Tool              string
	Resource          string
	Classification    string
	ExternalTarget    bool
	DestinationDomain string
}

// NewSessionContext creates a new session context manager backed by the given store.
// Use NewInMemoryStore() for Phase 1 (in-process) behavior or
// NewKeyDBStore(...) for persistent cross-request sessions.
func NewSessionContext(store SessionStore) *SessionContext {
	return &SessionContext{
		store: store,
	}
}

// GetOrCreateSession retrieves or creates a session for the given SPIFFE ID and session ID.
// Uses the underlying SessionStore for persistence.
func (sc *SessionContext) GetOrCreateSession(spiffeID, sessionID string) *AgentSession {
	ctx := context.Background()

	session, err := sc.store.GetSession(ctx, spiffeID, sessionID)
	if err != nil {
		log.Printf("session store get error: %v (falling back to new session)", err)
	}
	if session != nil {
		return session
	}

	// Create new session
	session = &AgentSession{
		ID:                  sessionID,
		SPIFFEID:            spiffeID,
		StartTime:           time.Now(),
		Actions:             make([]ToolAction, 0),
		DataClassifications: make([]string, 0),
		RiskScore:           0.0,
		Flags:               make([]string, 0),
	}

	if err := sc.store.SaveSession(ctx, spiffeID, sessionID, session); err != nil {
		log.Printf("session store save error: %v", err)
	}

	return session
}

// RecordAction adds a tool action to the session and persists it via the store.
// The store handles action list persistence. Session metadata (risk score,
// classifications) is updated in-memory first, then persisted.
func (sc *SessionContext) RecordAction(session *AgentSession, action ToolAction) {
	ctx := context.Background()

	// Update data classifications (in-memory, then persisted via SaveSession)
	if action.Classification != "" && !contains(session.DataClassifications, action.Classification) {
		session.DataClassifications = append(session.DataClassifications, action.Classification)
	}

	// Accumulate risk score
	session.RiskScore += computeActionRisk(action)

	// Persist action to store. For InMemoryStore, this modifies session.Actions
	// directly via the stored pointer. For KeyDB, this writes to a Redis LIST.
	if err := sc.store.AppendAction(ctx, session.SPIFFEID, session.ID, action); err != nil {
		log.Printf("session store append action error: %v", err)
	}

	// For KeyDB: also update the local session.Actions so that exfiltration
	// detection (which reads session.Actions) works within the same request.
	// For InMemoryStore: AppendAction already modified session.Actions via pointer.
	if _, isInMemory := sc.store.(*InMemoryStore); !isInMemory {
		session.Actions = append(session.Actions, action)
	}

	// Persist updated session metadata (risk score, classifications, flags)
	if err := sc.store.SaveSession(ctx, session.SPIFFEID, session.ID, session); err != nil {
		log.Printf("session store save session error: %v", err)
	}
}

// DetectsExfiltrationPattern checks if current session shows exfiltration behavior.
// It operates on the in-memory session object whose Actions are already populated
// (either from InMemoryStore directly or loaded from KeyDB on GetOrCreateSession).
func (sc *SessionContext) DetectsExfiltrationPattern(session *AgentSession) bool {
	if len(session.Actions) < 2 {
		return false
	}

	// Look at current action (most recent)
	for i := len(session.Actions) - 1; i >= 1; i-- {
		current := session.Actions[i]
		if !current.ExternalTarget {
			continue
		}

		// Look back up to 5 actions for sensitive data access
		for j := i - 1; j >= 0 && j >= i-5; j-- {
			previous := session.Actions[j]
			if previous.Classification == "sensitive" {
				return true
			}
		}
	}

	return false
}

// computeActionRisk calculates risk score for an action
func computeActionRisk(action ToolAction) float64 {
	risk := 0.0

	// External targets increase risk
	if action.ExternalTarget {
		risk += 0.2
	}

	// Sensitive data access increases risk
	switch action.Classification {
	case "sensitive":
		risk += 0.3
	case "confidential":
		risk += 0.2
	case "internal":
		risk += 0.1
	}

	return risk
}

// classifyResource determines data classification based on resource
// This is a simplified implementation - in production, this would check
// against a data catalog or use pattern matching
func classifyResource(resource string) string {
	// For POC, use simple heuristics
	// In production, this would query a data catalog
	if resource == "" {
		return "public"
	}

	// Check for sensitive keywords (case-insensitive substring match)
	sensitiveKeywords := []string{"password", "secret", "token", "key", "credential"}
	resourceLower := resource
	for _, keyword := range sensitiveKeywords {
		if containsSubstring(resourceLower, keyword) {
			return "sensitive"
		}
	}

	return "internal"
}

// containsSubstring checks if s contains substr (case-insensitive)
func containsSubstring(s, substr string) bool {
	// Simple case-insensitive contains check
	sLen := len(s)
	subLen := len(substr)
	if subLen > sLen {
		return false
	}
	for i := 0; i <= sLen-subLen; i++ {
		match := true
		for j := 0; j < subLen; j++ {
			c1 := s[i+j]
			c2 := substr[j]
			// Convert to lowercase for comparison
			if c1 >= 'A' && c1 <= 'Z' {
				c1 = c1 + ('a' - 'A')
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 = c2 + ('a' - 'A')
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// isExternalTarget determines if destination is external
func isExternalTarget(tool string, params map[string]interface{}) (bool, string) {
	// Tools that typically access external services
	externalTools := map[string]bool{
		"email_send":    true,
		"http_request":  true,
		"file_upload":   true,
		"webhook_call":  true,
		"tavily_search": true,
	}

	if externalTools[tool] {
		// Extract destination domain if available
		if dest, ok := params["destination"].(string); ok {
			return true, dest
		}
		if url, ok := params["url"].(string); ok {
			return true, url
		}
		return true, ""
	}

	return false, ""
}

// SessionContextMiddleware tracks agent behavior and detects exfiltration patterns
// Position: Step 8 (after DLP step 7, before step-up step 9)
func SessionContextMiddleware(next http.Handler, sessionCtx *SessionContext) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get SPIFFE ID and session ID
		spiffeID := GetSPIFFEID(ctx)
		sessionID := GetSessionID(ctx)
		if sessionID == "" {
			// Generate session ID if not present
			sessionID = uuid.New().String()
			ctx = WithSessionID(ctx, sessionID)
		}

		// Get or create session
		session := sessionCtx.GetOrCreateSession(spiffeID, sessionID)

		// Parse tool invocation
		body := GetRequestBody(ctx)
		var toolName string
		var params map[string]interface{}
		if len(body) > 0 {
			var mcpReq MCPRequest
			if err := json.Unmarshal(body, &mcpReq); err == nil {
				toolName = mcpReq.Method
				if toolName == "" {
					if tn, ok := mcpReq.Params["tool"]; ok {
						if toolNameStr, ok := tn.(string); ok {
							toolName = toolNameStr
						}
					}
				}
				params = mcpReq.Params
			}
		}

		// Determine resource classification
		resource := ""
		if path, ok := params["path"].(string); ok {
			resource = path
		} else if file, ok := params["file"].(string); ok {
			resource = file
		}
		classification := classifyResource(resource)

		// Determine if external target
		externalTarget, destination := isExternalTarget(toolName, params)

		// Create action record
		action := ToolAction{
			Timestamp:         time.Now(),
			Tool:              toolName,
			Resource:          resource,
			Classification:    classification,
			ExternalTarget:    externalTarget,
			DestinationDomain: destination,
		}

		// Record action
		sessionCtx.RecordAction(session, action)

		// Detect exfiltration pattern
		if sessionCtx.DetectsExfiltrationPattern(session) {
			// Add flag to session
			session.Flags = append(session.Flags, "exfiltration_detected")

			// Add security flag to context for audit
			existingFlags := GetSecurityFlags(ctx)
			if existingFlags == nil {
				existingFlags = make([]string, 0)
			}
			existingFlags = append(existingFlags, "exfiltration_detected")
			r = r.WithContext(WithSecurityFlags(ctx, existingFlags))

			// Block with 403
			http.Error(w, "Forbidden: Exfiltration pattern detected", http.StatusForbidden)
			return
		}

		// Store session in context for OPA
		ctx = WithSessionContextData(ctx, session)

		// Continue to next middleware
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// WithSessionContextData adds session data to context
func WithSessionContextData(ctx context.Context, session *AgentSession) context.Context {
	return context.WithValue(ctx, contextKeySessionContext, session)
}

// GetSessionContextData retrieves session data from context
func GetSessionContextData(ctx context.Context) *AgentSession {
	if v := ctx.Value(contextKeySessionContext); v != nil {
		return v.(*AgentSession)
	}
	return nil
}

package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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
	ID                           string
	SPIFFEID                     string
	StartTime                    time.Time
	Actions                      []ToolAction
	DataClassifications          []string
	RiskScore                    float64
	Flags                        []string
	EscalationScore              float64           // OC-h4m7: cumulative escalation score for session risk tracking
	EscalationHistory            []EscalationEvent // OC-d77k: ordered history of escalation-contributing actions
	EscalationFlags              []string          // OC-d77k: threshold-crossing flags (e.g., "escalation_critical")
	DestructiveActionsAuthorized int               // OC-lmzm: count of authorized actions that required backup (Score >= 2)
}

// EscalationEvent records a single action's contribution to the session escalation score.
// OC-d77k: Created by RecordAction when a tool action has non-zero escalation contribution.
type EscalationEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	Tool          string    `json:"tool"`
	ImpactScore   int       `json:"impact_score"`
	Reversibility int       `json:"reversibility"`
	Contribution  float64   `json:"contribution"`
	CumulativeAt  float64   `json:"cumulative_at"`
}

// Escalation threshold constants (OC-h4m7)
const (
	EscalationWarningThreshold   float64 = 15
	EscalationCriticalThreshold  float64 = 25
	EscalationEmergencyThreshold float64 = 40
)

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
		slog.Error("session store get error, falling back to new session", "error", err)
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
		slog.Error("session store save error", "error", err)
	}

	return session
}

// RecordAction adds a tool action to the session and persists it via the store.
// The store handles action list persistence. Session metadata (risk score,
// classifications) is updated in-memory first, then persisted.
//
// OC-d77k: After recording the action, computes escalation contribution based
// on the tool's impact and reversibility. Destructive actions (high impact,
// low reversibility) contribute more to the escalation score. When threshold
// crossings are detected, escalation flags are added and the SecurityFlagsCollector
// is updated (if available in the provided context).
func (sc *SessionContext) RecordAction(session *AgentSession, action ToolAction) {
	sc.RecordActionWithContext(context.Background(), session, action)
}

// RecordActionWithContext is like RecordAction but accepts a context for
// SecurityFlagsCollector propagation. OC-d77k: The context is used to
// propagate escalation threshold crossing flags upstream to the audit middleware.
func (sc *SessionContext) RecordActionWithContext(ctx context.Context, session *AgentSession, action ToolAction) {
	// Update data classifications (in-memory, then persisted via SaveSession)
	if action.Classification != "" && !contains(session.DataClassifications, action.Classification) {
		session.DataClassifications = append(session.DataClassifications, action.Classification)
	}

	// Accumulate risk score
	session.RiskScore += computeActionRisk(action)

	// OC-d77k: Compute escalation contribution from this action.
	// Classify reversibility of the tool action to get impact and reversibility scores.
	rev := ClassifyReversibility(action.Tool, action.Tool, nil, nil)
	impact := computeImpactFromAction(action)
	contribution := float64(impact) * float64(4-rev.Score)
	prevScore := session.EscalationScore

	if contribution > 0 {
		session.EscalationScore += contribution
		event := EscalationEvent{
			Timestamp:     action.Timestamp,
			Tool:          action.Tool,
			ImpactScore:   impact,
			Reversibility: rev.Score,
			Contribution:  contribution,
			CumulativeAt:  session.EscalationScore,
		}
		session.EscalationHistory = append(session.EscalationHistory, event)
	}

	// OC-d77k: Check for threshold crossings and add escalation flags.
	collector := GetFlagsCollector(ctx)
	checkEscalationThreshold(session, prevScore, EscalationWarningThreshold, "escalation_warning", collector)
	checkEscalationThreshold(session, prevScore, EscalationCriticalThreshold, "escalation_critical", collector)
	checkEscalationThreshold(session, prevScore, EscalationEmergencyThreshold, "escalation_emergency", collector)

	// Persist action to store. For InMemoryStore, this modifies session.Actions
	// directly via the stored pointer. For KeyDB, this writes to a Redis LIST.
	if err := sc.store.AppendAction(ctx, session.SPIFFEID, session.ID, action); err != nil {
		slog.Error("session store append action error", "error", err)
	}

	// For KeyDB: also update the local session.Actions so that exfiltration
	// detection (which reads session.Actions) works within the same request.
	// For InMemoryStore: AppendAction already modified session.Actions via pointer.
	if _, isInMemory := sc.store.(*InMemoryStore); !isInMemory {
		session.Actions = append(session.Actions, action)
	}

	// Persist updated session metadata (risk score, classifications, flags)
	if err := sc.store.SaveSession(ctx, session.SPIFFEID, session.ID, session); err != nil {
		slog.Error("session store save session error", "error", err)
	}
}

// checkEscalationThreshold checks if a threshold was crossed by this action
// and adds the appropriate flag to the session and collector.
// OC-d77k: Only fires once per threshold per session (idempotent).
func checkEscalationThreshold(session *AgentSession, prevScore, threshold float64, flag string, collector *SecurityFlagsCollector) {
	if session.EscalationScore >= threshold && prevScore < threshold {
		if !containsFlag(session.EscalationFlags, flag) {
			session.EscalationFlags = append(session.EscalationFlags, flag)
		}
		if collector != nil {
			collector.Append(flag)
		}
	}
}

// containsFlag checks if a string slice contains a given flag.
func containsFlag(flags []string, flag string) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}

// computeImpactFromAction derives an impact score (0-3) from a ToolAction.
// This mirrors the computeImpact function used in step-up gating but operates
// on action metadata rather than tool definitions.
// OC-d77k: Used for escalation contribution calculation.
func computeImpactFromAction(action ToolAction) int {
	impact := 0

	// External targets have higher impact
	if action.ExternalTarget {
		impact = 2
	}

	// Sensitive data access increases impact
	switch action.Classification {
	case "sensitive":
		if impact < 3 {
			impact = 3
		}
	case "confidential":
		if impact < 2 {
			impact = 2
		}
	case "internal":
		if impact < 1 {
			impact = 1
		}
	}

	return impact
}

// EscalationState returns the current escalation state label for a session.
// OC-d77k: Used for audit enrichment.
//
//	"normal":    EscalationScore < Warning (15)
//	"warning":   Warning (15) <= EscalationScore < Critical (25)
//	"critical":  Critical (25) <= EscalationScore < Emergency (40)
//	"emergency": EscalationScore >= Emergency (40)
func EscalationState(score float64) string {
	switch {
	case score >= EscalationEmergencyThreshold:
		return "emergency"
	case score >= EscalationCriticalThreshold:
		return "critical"
	case score >= EscalationWarningThreshold:
		return "warning"
	default:
		return "normal"
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
		"email_send":       true,
		"http_request":     true,
		"file_upload":      true,
		"webhook_call":     true,
		"tavily_search":    true,
		"messaging_send":   true,
		"messaging_status": true,
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
		// RFA-m6j.2: Create OTel span for step 8
		ctx, span := tracer.Start(r.Context(), "gateway.session_context",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 8),
				attribute.String("mcp.gateway.middleware", "session_context"),
			),
		)
		defer span.End()

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
			if parsed, err := ParseMCPRequestBody(body); err == nil {
				if tn, err := parsed.EffectiveToolName(); err == nil {
					toolName = tn
				}
				params = parsed.EffectiveToolParams()
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

		// RFA-m6j.2: Set per-middleware span attributes
		span.SetAttributes(
			attribute.String("session_id", session.ID),
			attribute.Float64("risk_score", session.RiskScore),
			attribute.Int("action_count", len(session.Actions)),
		)

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
			ctx = WithSecurityFlags(ctx, existingFlags)

			span.SetAttributes(
				attribute.String("mcp.result", "denied"),
				attribute.String("mcp.reason", "exfiltration pattern detected"),
			)
			// Block with 403
			WriteGatewayError(w, r.WithContext(ctx), http.StatusForbidden, GatewayError{
				Code:           ErrExfiltrationDetected,
				Message:        "Exfiltration pattern detected",
				Middleware:     "session_context",
				MiddlewareStep: 8,
				Remediation:    "Sensitive data access followed by external transmission is not permitted.",
			})
			return
		}

		span.SetAttributes(
			attribute.String("mcp.result", "allowed"),
			attribute.String("mcp.reason", "session tracked"),
		)

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

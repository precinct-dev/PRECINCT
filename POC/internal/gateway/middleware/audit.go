package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// AuditEvent represents a structured audit log event
type AuditEvent struct {
	Timestamp  string `json:"timestamp"`
	SessionID  string `json:"session_id"`
	DecisionID string `json:"decision_id"`
	TraceID    string `json:"trace_id"`
	SPIFFEID   string `json:"spiffe_id"`
	Action     string `json:"action"`
	Result     string `json:"result"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	StatusCode int    `json:"status_code,omitempty"`
}

// Auditor handles audit logging
type Auditor struct{}

// NewAuditor creates a new auditor
func NewAuditor() *Auditor {
	return &Auditor{}
}

// Log emits a structured audit event to stdout
func (a *Auditor) Log(event AuditEvent) {
	event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	jsonBytes, err := json.Marshal(event)
	if err != nil {
		log.Printf("ERROR: Failed to marshal audit event: %v", err)
		return
	}
	log.Println(string(jsonBytes))
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// AuditLog middleware logs all requests with structured JSON
func AuditLog(next http.Handler, auditor *Auditor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call next handler
		next.ServeHTTP(wrapped, r)

		// Log audit event after request completes
		ctx := r.Context()
		auditor.Log(AuditEvent{
			SessionID:  GetSessionID(ctx),
			DecisionID: GetDecisionID(ctx),
			TraceID:    GetTraceID(ctx),
			SPIFFEID:   GetSPIFFEID(ctx),
			Action:     "mcp_request",
			Result:     "completed",
			Method:     r.Method,
			Path:       r.URL.Path,
			StatusCode: wrapped.statusCode,
		})
	})
}

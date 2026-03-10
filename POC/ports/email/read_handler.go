// OC-di1n: Email read handler with content classification.
// Implements /email/read with automatic sensitive data detection.
// When the read content contains SSN, credit card, or API key patterns,
// the session context is annotated with data_classification=sensitive
// to enable cross-channel exfiltration detection.
package email

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway"
	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
	"github.com/precinct-dev/PRECINCT/POC/ports/email/protocol"
)

// sensitivePatterns are compiled regexes for detecting sensitive data in email content.
var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),                   // SSN
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                    // AWS key
	regexp.MustCompile(`\bsk-proj-[a-zA-Z0-9]{20,}\b`),            // OpenAI key
	regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`), // Credit card
}

// classifyContent checks if email body contains sensitive data patterns.
// Returns "sensitive" if any pattern matches, "standard" otherwise.
func classifyContent(body string) string {
	for _, pat := range sensitivePatterns {
		if pat.MatchString(body) {
			return "sensitive"
		}
	}
	return "standard"
}

// handleReadImpl implements the /email/read handler.
// It returns a simulated email body and records the data classification
// in the session context header so the session tracking middleware
// can detect exfiltration patterns on subsequent requests.
func (a *Adapter) handleReadImpl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.gw.WriteGatewayError(w, r, http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest, "method not allowed",
			"email_read", gateway.ReasonContractInvalid,
			map[string]any{"route": pathRead, "expected_method": http.MethodPost})
		return
	}

	var req protocol.EmailReadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest, "unable to parse request body: "+err.Error(),
			"email_read", gateway.ReasonContractInvalid,
			map[string]any{"route": pathRead})
		return
	}
	if strings.TrimSpace(req.MessageID) == "" {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrContractValidationFailed, "message_id is required",
			"email_read", gateway.ReasonContractInvalid,
			map[string]any{"route": pathRead})
		return
	}

	// Simulate email content for demo purposes.
	// In production this would fetch from an email provider.
	emailBody := r.Header.Get("X-Demo-Email-Body")
	if emailBody == "" {
		emailBody = "This is a simulated email body for message " + req.MessageID
	}

	// Classify content for sensitive data.
	classification := classifyContent(emailBody)

	// Build PlaneRequestV2 for policy evaluation.
	spiffeID := spiffeIDFromRequest(r)
	sessionID := strings.TrimSpace(middleware.GetSessionID(r.Context()))
	if sessionID == "" {
		sessionID = "email-read-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}

	envelope := gateway.RunEnvelope{
		RunID:         "email-read-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		SessionID:     sessionID,
		Tenant:        gateway.DefaultString(strings.TrimSpace(r.Header.Get("X-Tenant")), "default"),
		ActorSPIFFEID: spiffeID,
		Plane:         gateway.PlaneTool,
	}

	traceID, decisionID := gateway.GetDecisionCorrelationIDs(r, envelope)

	// Log the read with classification metadata so session context
	// can detect subsequent exfiltration patterns.
	a.gw.AuditLog(middleware.AuditEvent{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		EventType:  "email.read",
		Severity:   "Info",
		SessionID:  sessionID,
		DecisionID: decisionID,
		TraceID:    traceID,
		SPIFFEID:   spiffeID,
		Action:     "email.read",
		Result:     "allowed",
		Method:     r.Method,
		Path:       r.URL.Path,
		Security: &middleware.SecurityAudit{
			SafeZoneFlags: []string{
				"data_classification:" + classification,
				"email_read_completed",
			},
		},
	})

	// Set response headers for session tracking.
	// X-Data-Classification enables downstream exfiltration detection.
	w.Header().Set("X-Data-Classification", classification)
	w.Header().Set("X-Precinct-Decision-ID", decisionID)
	w.Header().Set("X-Precinct-Trace-ID", traceID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(protocol.EmailContent{
		MessageID:  req.MessageID,
		Subject:    fmt.Sprintf("Email %s", req.MessageID),
		From:       "sender@example.com",
		Body:       emailBody,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

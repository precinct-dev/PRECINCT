package email

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway"
	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
	"github.com/precinct-dev/PRECINCT/POC/ports/email/protocol"
)

const (
	// massEmailThreshold is the recipient count above which the mass_email
	// attribute is set to "true", triggering step-up gating in OPA policy.
	massEmailThreshold = 10

	middlewareNameEmail = "email_send"
)

// handleSendImpl implements the real /email/send handler. It parses the
// SendEmailRequest, builds a PlaneRequestV2 for policy evaluation (DLP,
// OPA, step-up gating), redeems SPIKE tokens for attachment references,
// and executes messaging egress.
//
// Attachment size enforcement is handled by the existing MaxRequestSizeBytes
// middleware (step 1 in the chain) -- no per-handler size checks needed.
func (a *Adapter) handleSendImpl(w http.ResponseWriter, r *http.Request) {
	// 1. Only accept POST.
	if r.Method != http.MethodPost {
		a.gw.WriteGatewayError(w, r, http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest, "method not allowed",
			middlewareNameEmail, gateway.ReasonContractInvalid,
			map[string]any{"route": pathSend, "expected_method": http.MethodPost})
		return
	}

	// 2. Parse request body.
	var req protocol.SendEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest, "unable to parse request body: "+err.Error(),
			middlewareNameEmail, gateway.ReasonContractInvalid,
			map[string]any{"route": pathSend})
		return
	}

	// 3. Validate required fields.
	if err := req.Validate(); err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrContractValidationFailed, err.Error(),
			middlewareNameEmail, gateway.ReasonContractInvalid,
			map[string]any{"route": pathSend})
		return
	}

	// 4. Count recipients.
	totalRecipients := len(req.To) + len(req.CC) + len(req.BCC)

	// 5. Build PlaneRequestV2 for policy evaluation.
	// Concatenate subject + body so DLP middleware scans full content.
	payload := []byte(req.Subject + "\n" + req.Body)

	attrs := map[string]any{
		"capability_id":     "tool.messaging.email",
		"tool_name":         "messaging_send",
		"recipient_count":   strconv.Itoa(totalRecipients),
		"has_attachments":   strconv.FormatBool(len(req.AttachmentRefs) > 0),
		"subject_preview":   truncate(req.Subject, 50),
		"mass_email":        strconv.FormatBool(totalRecipients > massEmailThreshold),
		"recipient_domains": strings.Join(extractDomains(req.To, req.CC, req.BCC), ","),
	}

	spiffeID := spiffeIDFromRequest(r)
	sessionID := strings.TrimSpace(middleware.GetSessionID(r.Context()))
	if sessionID == "" {
		sessionID = "email-send-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}

	envelope := gateway.RunEnvelope{
		RunID:         "email-send-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		SessionID:     sessionID,
		Tenant:        gateway.DefaultString(strings.TrimSpace(r.Header.Get("X-Tenant")), "default"),
		ActorSPIFFEID: spiffeID,
		Plane:         gateway.PlaneTool,
	}

	planeReq := gateway.PlaneRequestV2{
		Envelope: envelope,
		Policy: gateway.PolicyInputV2{
			Envelope:   envelope,
			Action:     "tool.invoke",
			Resource:   "messaging_send",
			Attributes: attrs,
		},
	}

	// 5b. OC-di1n: Mass email step-up check. When recipient count exceeds
	// the threshold, require step-up approval before policy evaluation.
	if totalRecipients > massEmailThreshold {
		traceID, decisionID := gateway.GetDecisionCorrelationIDs(r, envelope)
		a.gw.LogPlaneDecision(r, gateway.PlaneDecisionV2{
			Decision:   gateway.DecisionDeny,
			ReasonCode: gateway.ReasonCode(middleware.ErrStepUpApprovalRequired),
			Envelope:   envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata: map[string]any{
				"email_route":     pathSend,
				"recipient_count": totalRecipients,
				"mass_email":      true,
				"reason":          "mass email requires step-up approval",
			},
		}, http.StatusForbidden)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":            middleware.ErrStepUpApprovalRequired,
			"message":         fmt.Sprintf("Mass email to %d recipients requires step-up approval", totalRecipients),
			"middleware":      "step_up_gating",
			"middleware_step": 9,
			"decision_id":    decisionID,
			"trace_id":       traceID,
		})
		return
	}

	// 6. Evaluate tool request through policy engine (DLP, OPA, step-up).
	result := a.gw.EvaluateToolRequest(planeReq)
	if result.Decision != gateway.DecisionAllow {
		traceID, decisionID := gateway.GetDecisionCorrelationIDs(r, envelope)
		a.gw.LogPlaneDecision(r, gateway.PlaneDecisionV2{
			Decision:   result.Decision,
			ReasonCode: result.Reason,
			Envelope:   envelope,
			TraceID:    traceID,
			DecisionID: decisionID,
			Metadata: map[string]any{
				"email_route":     pathSend,
				"recipient_count": totalRecipients,
			},
		}, result.HTTPStatus)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.HTTPStatus)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":       "policy_denied",
			"reason_code": result.Reason,
			"message":     "email send denied by policy",
		})
		return
	}

	// 7. Redeem SPIKE tokens for attachment references.
	for i, ref := range req.AttachmentRefs {
		if strings.HasPrefix(ref, "$SPIKE{") {
			resolved, err := a.gw.RedeemSPIKESecret(r.Context(), ref)
			if err != nil {
				a.gw.WriteGatewayError(w, r, http.StatusUnauthorized,
					"spike_resolution_failed",
					fmt.Sprintf("failed to resolve SPIKE token for attachment %d: %s", i, err.Error()),
					middlewareNameEmail, gateway.ReasonToolCapabilityDenied,
					map[string]any{"route": pathSend, "attachment_index": i})
				return
			}
			req.AttachmentRefs[i] = resolved
		}
	}

	// 8. Execute messaging egress.
	egressAttrs := map[string]string{
		"to":       strings.Join(req.To, ","),
		"subject":  req.Subject,
		"body":     req.Body,
		"platform": "email",
	}

	_, err := a.gw.ExecuteMessagingEgress(r.Context(), egressAttrs, payload, "")
	if err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadGateway,
			"messaging_egress_failed", "email egress failed: "+err.Error(),
			middlewareNameEmail, gateway.ReasonToolCapabilityDenied,
			map[string]any{"route": pathSend})
		return
	}

	// 9. Return success.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(protocol.SendEmailResponse{
		MessageID: generateMessageID(),
		Status:    "queued",
	})
}

// extractDomains parses email addresses from the To, CC, and BCC lists
// and extracts the unique domain parts (after @).
func extractDomains(to, cc, bcc []string) []string {
	seen := make(map[string]struct{})
	var domains []string

	for _, lists := range [][]string{to, cc, bcc} {
		for _, addr := range lists {
			addr = strings.TrimSpace(addr)
			if idx := strings.LastIndex(addr, "@"); idx >= 0 {
				domain := strings.ToLower(strings.TrimSpace(addr[idx+1:]))
				// Strip trailing '>' for "Name <user@example.com>" format.
				domain = strings.TrimRight(domain, ">")
				if domain != "" {
					if _, ok := seen[domain]; !ok {
						seen[domain] = struct{}{}
						domains = append(domains, domain)
					}
				}
			}
		}
	}
	return domains
}

// truncate returns the first n characters of s. If s is shorter than n,
// it is returned as-is.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

// spiffeIDFromRequest extracts the SPIFFE ID from the middleware context
// (set by the SPIFFE auth middleware) or falls back to the X-SPIFFE-ID header.
func spiffeIDFromRequest(r *http.Request) string {
	if id := strings.TrimSpace(middleware.GetSPIFFEID(r.Context())); id != "" {
		return id
	}
	return strings.TrimSpace(r.Header.Get("X-SPIFFE-ID"))
}

// generateMessageID produces a simple unique message ID for the response.
func generateMessageID() string {
	return "msg-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

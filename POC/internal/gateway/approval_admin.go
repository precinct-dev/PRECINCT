package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
)

const approvalAdminPath = "/admin/approvals"

type approvalRequestPayload struct {
	Scope       middleware.ApprovalScope `json:"scope"`
	RequestedBy string                   `json:"requested_by,omitempty"`
	Reason      string                   `json:"reason,omitempty"`
	TTLSeconds  int                      `json:"ttl_seconds,omitempty"`
}

type approvalGrantPayload struct {
	RequestID  string `json:"request_id"`
	ApprovedBy string `json:"approved_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type approvalDenyPayload struct {
	RequestID string `json:"request_id"`
	DeniedBy  string `json:"denied_by,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type approvalConsumePayload struct {
	CapabilityToken string                   `json:"capability_token"`
	Scope           middleware.ApprovalScope `json:"scope,omitempty"`
}

func (g *Gateway) adminApprovalsHandler(w http.ResponseWriter, r *http.Request) {
	if g == nil || g.approvalCapabilities == nil {
		writeV24GatewayError(
			w,
			r,
			http.StatusServiceUnavailable,
			middleware.ErrMCPTransportFailed,
			"approval capabilities unavailable",
			v24MiddlewareApprovalAdmin,
			ReasonContractInvalid,
			nil,
		)
		return
	}

	pathSuffix := strings.TrimPrefix(r.URL.Path, approvalAdminPath)
	if pathSuffix == r.URL.Path {
		http.NotFound(w, r)
		return
	}

	switch pathSuffix {
	case "", "/":
		if r.Method != http.MethodGet {
			writeApprovalMethodNotAllowed(w, r, http.MethodGet)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"paths": []string{
				"POST /admin/approvals/request",
				"POST /admin/approvals/grant",
				"POST /admin/approvals/deny",
				"POST /admin/approvals/consume",
			},
		})
		return
	case "/request":
		g.handleApprovalRequest(w, r)
		return
	case "/grant":
		g.handleApprovalGrant(w, r)
		return
	case "/deny":
		g.handleApprovalDeny(w, r)
		return
	case "/consume":
		g.handleApprovalConsume(w, r)
		return
	default:
		http.NotFound(w, r)
		return
	}
}

func (g *Gateway) handleApprovalRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeApprovalMethodNotAllowed(w, r, http.MethodPost)
		return
	}

	var req approvalRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV24GatewayError(
			w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest,
			"invalid json payload",
			v24MiddlewareApprovalAdmin,
			ReasonContractInvalid,
			map[string]any{"operation": "request"},
		)
		return
	}
	if strings.TrimSpace(req.Scope.ActorSPIFFEID) == "" {
		req.Scope.ActorSPIFFEID = middleware.GetSPIFFEID(r.Context())
	}
	if strings.TrimSpace(req.Scope.SessionID) == "" {
		req.Scope.SessionID = middleware.GetSessionID(r.Context())
	}
	if strings.TrimSpace(req.RequestedBy) == "" {
		req.RequestedBy = req.Scope.ActorSPIFFEID
	}

	record, err := g.approvalCapabilities.CreateRequest(middleware.ApprovalRequestInput{
		Scope:       req.Scope,
		RequestedBy: req.RequestedBy,
		Reason:      req.Reason,
		TTLSeconds:  req.TTLSeconds,
	})
	if err != nil {
		writeApprovalError(w, r, "request", err)
		return
	}

	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"operation":   "request",
		"record":      record,
		"decision_id": decisionID,
		"trace_id":    traceID,
	})
}

func (g *Gateway) handleApprovalGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeApprovalMethodNotAllowed(w, r, http.MethodPost)
		return
	}

	var req approvalGrantPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV24GatewayError(
			w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest,
			"invalid json payload",
			v24MiddlewareApprovalAdmin,
			ReasonContractInvalid,
			map[string]any{"operation": "grant"},
		)
		return
	}
	if strings.TrimSpace(req.ApprovedBy) == "" {
		req.ApprovedBy = middleware.GetSPIFFEID(r.Context())
	}

	result, err := g.approvalCapabilities.GrantRequest(middleware.ApprovalGrantInput{
		RequestID:  req.RequestID,
		ApprovedBy: req.ApprovedBy,
		Reason:     req.Reason,
	})
	if err != nil {
		writeApprovalError(w, r, "grant", err)
		return
	}

	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":           "ok",
		"operation":        "grant",
		"record":           result.Record,
		"claims":           result.Claims,
		"capability_token": result.Token,
		"decision_id":      decisionID,
		"trace_id":         traceID,
	})
}

func (g *Gateway) handleApprovalDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeApprovalMethodNotAllowed(w, r, http.MethodPost)
		return
	}

	var req approvalDenyPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV24GatewayError(
			w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest,
			"invalid json payload",
			v24MiddlewareApprovalAdmin,
			ReasonContractInvalid,
			map[string]any{"operation": "deny"},
		)
		return
	}
	if strings.TrimSpace(req.DeniedBy) == "" {
		req.DeniedBy = middleware.GetSPIFFEID(r.Context())
	}

	record, err := g.approvalCapabilities.DenyRequest(middleware.ApprovalDenyInput{
		RequestID: req.RequestID,
		DeniedBy:  req.DeniedBy,
		Reason:    req.Reason,
	})
	if err != nil {
		writeApprovalError(w, r, "deny", err)
		return
	}

	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"operation":   "deny",
		"record":      record,
		"decision_id": decisionID,
		"trace_id":    traceID,
	})
}

func (g *Gateway) handleApprovalConsume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeApprovalMethodNotAllowed(w, r, http.MethodPost)
		return
	}

	var req approvalConsumePayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV24GatewayError(
			w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest,
			"invalid json payload",
			v24MiddlewareApprovalAdmin,
			ReasonContractInvalid,
			map[string]any{"operation": "consume"},
		)
		return
	}

	if strings.TrimSpace(req.Scope.ActorSPIFFEID) == "" {
		req.Scope.ActorSPIFFEID = middleware.GetSPIFFEID(r.Context())
	}
	if strings.TrimSpace(req.Scope.SessionID) == "" {
		req.Scope.SessionID = middleware.GetSessionID(r.Context())
	}
	claims, err := g.approvalCapabilities.ValidateAndConsume(req.CapabilityToken, req.Scope)
	if err != nil {
		writeApprovalError(w, r, "consume", err)
		return
	}

	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"operation":   "consume",
		"claims":      claims,
		"decision_id": decisionID,
		"trace_id":    traceID,
	})
}

func writeApprovalMethodNotAllowed(w http.ResponseWriter, r *http.Request, allowed string) {
	w.Header().Set("Allow", allowed)
	writeV24GatewayError(
		w, r, http.StatusMethodNotAllowed,
		middleware.ErrMCPInvalidRequest,
		"method not allowed",
		v24MiddlewareApprovalAdmin,
		ReasonContractInvalid,
		map[string]any{"allow": allowed},
	)
}

func writeApprovalError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	status := http.StatusBadRequest
	code := middleware.ErrContractValidationFailed
	reason := ReasonContractInvalid
	message := err.Error()

	switch {
	case errors.Is(err, middleware.ErrApprovalRequestNotFound):
		status = http.StatusNotFound
	case errors.Is(err, middleware.ErrApprovalInvalidState):
		status = http.StatusConflict
	case errors.Is(err, middleware.ErrApprovalTokenExpired):
		status = http.StatusGone
		code = middleware.ErrStepUpApprovalRequired
		reason = ReasonToolStepUpRequired
		message = "approval capability token expired"
	case errors.Is(err, middleware.ErrApprovalTokenConsumed):
		status = http.StatusConflict
		code = middleware.ErrStepUpDenied
		reason = ReasonToolStepUpRequired
		message = "approval capability token already consumed"
	case errors.Is(err, middleware.ErrApprovalTokenInvalid), errors.Is(err, middleware.ErrApprovalScopeMismatch), errors.Is(err, middleware.ErrApprovalIdentityMismatch):
		status = http.StatusForbidden
		code = middleware.ErrStepUpDenied
		reason = ReasonToolStepUpRequired
		message = "approval capability token invalid for this operation"
	}

	writeV24GatewayError(
		w, r, status,
		code,
		message,
		v24MiddlewareApprovalAdmin,
		reason,
		map[string]any{
			"operation": operation,
		},
	)
}

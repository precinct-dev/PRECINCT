package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

const breakGlassAdminPath = "/admin/breakglass"

type breakGlassRequestPayload struct {
	IncidentID  string          `json:"incident_id"`
	Scope       breakGlassScope `json:"scope"`
	RequestedBy string          `json:"requested_by,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	TTLSeconds  int             `json:"ttl_seconds,omitempty"`
}

type breakGlassApprovePayload struct {
	RequestID  string `json:"request_id"`
	ApprovedBy string `json:"approved_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type breakGlassActivatePayload struct {
	RequestID   string `json:"request_id"`
	ActivatedBy string `json:"activated_by,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type breakGlassRevertPayload struct {
	RequestID  string `json:"request_id"`
	RevertedBy string `json:"reverted_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

func (g *Gateway) adminBreakGlassHandler(w http.ResponseWriter, r *http.Request) {
	if g == nil || g.breakGlass == nil {
		writeV24GatewayError(
			w, r, http.StatusServiceUnavailable,
			middleware.ErrMCPTransportFailed,
			"break-glass control plane unavailable",
			v24MiddlewareBreakGlassAdmin,
			ReasonContractInvalid,
			nil,
		)
		return
	}

	pathSuffix := strings.TrimPrefix(r.URL.Path, breakGlassAdminPath)
	if pathSuffix == r.URL.Path {
		http.NotFound(w, r)
		return
	}

	switch pathSuffix {
	case "", "/":
		if r.Method != http.MethodGet {
			writeBreakGlassMethodNotAllowed(w, r, http.MethodGet)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"paths": []string{
				"POST /admin/breakglass/request",
				"POST /admin/breakglass/approve",
				"POST /admin/breakglass/activate",
				"POST /admin/breakglass/revert",
				"GET  /admin/breakglass/status",
			},
		})
		return
	case "/status":
		if r.Method != http.MethodGet {
			writeBreakGlassMethodNotAllowed(w, r, http.MethodGet)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":   "ok",
			"requests": g.breakGlass.list(),
		})
		return
	case "/request":
		g.handleBreakGlassRequest(w, r)
		return
	case "/approve":
		g.handleBreakGlassApprove(w, r)
		return
	case "/activate":
		g.handleBreakGlassActivate(w, r)
		return
	case "/revert":
		g.handleBreakGlassRevert(w, r)
		return
	default:
		http.NotFound(w, r)
		return
	}
}

func (g *Gateway) handleBreakGlassRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeBreakGlassMethodNotAllowed(w, r, http.MethodPost)
		return
	}
	var req breakGlassRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV24GatewayError(
			w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest,
			"invalid json payload",
			v24MiddlewareBreakGlassAdmin,
			ReasonContractInvalid,
			map[string]any{"operation": "request"},
		)
		return
	}
	if strings.TrimSpace(req.RequestedBy) == "" {
		req.RequestedBy = middleware.GetSPIFFEID(r.Context())
	}
	record, err := g.breakGlass.request(breakGlassRequestInput{
		IncidentID:  req.IncidentID,
		Scope:       req.Scope,
		RequestedBy: req.RequestedBy,
		Reason:      req.Reason,
		TTLSeconds:  req.TTLSeconds,
	})
	if err != nil {
		writeBreakGlassError(w, r, "request", err)
		return
	}
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"operation":   "request",
		"record":      record,
		"decision_id": decisionID,
		"trace_id":    traceID,
	})
}

func (g *Gateway) handleBreakGlassApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeBreakGlassMethodNotAllowed(w, r, http.MethodPost)
		return
	}
	var req breakGlassApprovePayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV24GatewayError(
			w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest,
			"invalid json payload",
			v24MiddlewareBreakGlassAdmin,
			ReasonContractInvalid,
			map[string]any{"operation": "approve"},
		)
		return
	}
	if strings.TrimSpace(req.ApprovedBy) == "" {
		req.ApprovedBy = middleware.GetSPIFFEID(r.Context())
	}
	record, err := g.breakGlass.approve(breakGlassApprovalInput{
		RequestID:  req.RequestID,
		ApprovedBy: req.ApprovedBy,
		Reason:     req.Reason,
	})
	if err != nil {
		writeBreakGlassError(w, r, "approve", err)
		return
	}
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"operation":   "approve",
		"record":      record,
		"decision_id": decisionID,
		"trace_id":    traceID,
	})
}

func (g *Gateway) handleBreakGlassActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeBreakGlassMethodNotAllowed(w, r, http.MethodPost)
		return
	}
	var req breakGlassActivatePayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV24GatewayError(
			w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest,
			"invalid json payload",
			v24MiddlewareBreakGlassAdmin,
			ReasonContractInvalid,
			map[string]any{"operation": "activate"},
		)
		return
	}
	if strings.TrimSpace(req.ActivatedBy) == "" {
		req.ActivatedBy = middleware.GetSPIFFEID(r.Context())
	}
	record, err := g.breakGlass.activate(breakGlassActivateInput{
		RequestID:   req.RequestID,
		ActivatedBy: req.ActivatedBy,
		Reason:      req.Reason,
	})
	if err != nil {
		writeBreakGlassError(w, r, "activate", err)
		return
	}
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"operation":   "activate",
		"record":      record,
		"decision_id": decisionID,
		"trace_id":    traceID,
	})
}

func (g *Gateway) handleBreakGlassRevert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeBreakGlassMethodNotAllowed(w, r, http.MethodPost)
		return
	}
	var req breakGlassRevertPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV24GatewayError(
			w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest,
			"invalid json payload",
			v24MiddlewareBreakGlassAdmin,
			ReasonContractInvalid,
			map[string]any{"operation": "revert"},
		)
		return
	}
	if strings.TrimSpace(req.RevertedBy) == "" {
		req.RevertedBy = middleware.GetSPIFFEID(r.Context())
	}
	record, err := g.breakGlass.revert(breakGlassRevertInput{
		RequestID:  req.RequestID,
		RevertedBy: req.RevertedBy,
		Reason:     req.Reason,
	})
	if err != nil {
		writeBreakGlassError(w, r, "revert", err)
		return
	}
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"operation":   "revert",
		"record":      record,
		"decision_id": decisionID,
		"trace_id":    traceID,
	})
}

func writeBreakGlassMethodNotAllowed(w http.ResponseWriter, r *http.Request, allowed string) {
	w.Header().Set("Allow", allowed)
	writeV24GatewayError(
		w, r, http.StatusMethodNotAllowed,
		middleware.ErrMCPInvalidRequest,
		"method not allowed",
		v24MiddlewareBreakGlassAdmin,
		ReasonContractInvalid,
		map[string]any{"allow": allowed},
	)
}

func writeBreakGlassError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	status := http.StatusBadRequest
	code := middleware.ErrContractValidationFailed
	message := err.Error()

	switch {
	case errors.Is(err, errBreakGlassNotFound):
		status = http.StatusNotFound
	case errors.Is(err, errBreakGlassInvalidState):
		status = http.StatusConflict
	case errors.Is(err, errBreakGlassDualAuthNeeded):
		status = http.StatusForbidden
		code = middleware.ErrAuthzPolicyDenied
		message = "break-glass activation requires dual authorization"
	}

	writeV24GatewayError(
		w, r, status,
		code,
		message,
		v24MiddlewareBreakGlassAdmin,
		ReasonContractInvalid,
		map[string]any{"operation": operation},
	)
}

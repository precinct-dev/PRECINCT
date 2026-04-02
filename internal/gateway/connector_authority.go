package gateway

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"github.com/precinct-dev/precinct/internal/precinctcontrol"
	"github.com/precinct-dev/precinct/internal/precinctevidence"
)

const connectorManifestSchemaVersion = precinctcontrol.ConnectorManifestSchemaVersion
const connectorSignatureAlgorithm = precinctcontrol.ConnectorSignatureAlgorithm

type connectorState = precinctcontrol.ConnectorState

const (
	connectorStateRegistered connectorState = precinctcontrol.ConnectorStateRegistered
	connectorStateValidated  connectorState = precinctcontrol.ConnectorStateValidated
	connectorStateApproved   connectorState = precinctcontrol.ConnectorStateApproved
	connectorStateActive     connectorState = precinctcontrol.ConnectorStateActive
	connectorStateRevoked    connectorState = precinctcontrol.ConnectorStateRevoked
)

type connectorManifestSignature = precinctcontrol.ConnectorManifestSignature
type connectorManifest = precinctcontrol.ConnectorManifest
type connectorRecord = precinctcontrol.ConnectorRecord
type connectorConformanceAuthority struct {
	*precinctcontrol.ConnectorConformanceAuthority
}

func newConnectorConformanceAuthority() *connectorConformanceAuthority {
	return &connectorConformanceAuthority{
		ConnectorConformanceAuthority: precinctcontrol.NewConnectorConformanceAuthority(),
	}
}

func validateConnectorManifestSchema(manifest connectorManifest) error {
	return precinctcontrol.ValidateConnectorManifestSchema(manifest)
}

func computeConnectorExpectedSignature(manifest connectorManifest) string {
	return precinctcontrol.ComputeConnectorExpectedSignature(manifest)
}

func (c *connectorConformanceAuthority) register(manifest connectorManifest) (connectorRecord, error) {
	return c.ConnectorConformanceAuthority.Register(manifest)
}

func (c *connectorConformanceAuthority) validate(connectorID string) (connectorRecord, error) {
	return c.ConnectorConformanceAuthority.Validate(connectorID)
}

func (c *connectorConformanceAuthority) approve(connectorID string) (connectorRecord, error) {
	return c.ConnectorConformanceAuthority.Approve(connectorID)
}

func (c *connectorConformanceAuthority) activate(connectorID string) (connectorRecord, error) {
	return c.ConnectorConformanceAuthority.Activate(connectorID)
}

func (c *connectorConformanceAuthority) revoke(connectorID string) (connectorRecord, error) {
	return c.ConnectorConformanceAuthority.Revoke(connectorID)
}

func (c *connectorConformanceAuthority) status(connectorID string) (connectorRecord, bool) {
	return c.ConnectorConformanceAuthority.Status(connectorID)
}

func (c *connectorConformanceAuthority) updateAuditRef(connectorID, decisionID, traceID, reason, operation string) {
	c.ConnectorConformanceAuthority.UpdateAuditRef(connectorID, decisionID, traceID, reason, operation)
}

func (c *connectorConformanceAuthority) runtimeCheck(connectorID, signature string) (bool, string, connectorRecord) {
	return c.ConnectorConformanceAuthority.RuntimeCheck(connectorID, signature)
}

func (c *connectorConformanceAuthority) conformanceReport() map[string]any {
	return c.ConnectorConformanceAuthority.ConformanceReport()
}

type connectorLifecycleRequest struct {
	ConnectorID string            `json:"connector_id"`
	Manifest    connectorManifest `json:"manifest"`
}

func isConnectorMutationPath(path string) bool {
	return precinctcontrol.IsConnectorMutationPath(path)
}

func (g *Gateway) authorizeConnectorMutationRequest(w http.ResponseWriter, r *http.Request) bool {
	principal := g.requestPrincipal(r)
	if principal == "" {
		writeV24GatewayError(
			w,
			r,
			http.StatusUnauthorized,
			middleware.ErrAuthMissingIdentity,
			"connector lifecycle mutation requires SPIFFE identity",
			v24MiddlewareConnectorAuth,
			ReasonContractInvalid,
			map[string]any{"path": r.URL.Path},
		)
		return false
	}
	if !g.isAdminPrincipalAuthorized(principal) {
		writeV24GatewayError(
			w,
			r,
			http.StatusForbidden,
			middleware.ErrAuthzPolicyDenied,
			"connector lifecycle mutation requires admin authorization",
			v24MiddlewareConnectorAuth,
			ReasonContractInvalid,
			map[string]any{
				"path":      r.URL.Path,
				"spiffe_id": principal,
			},
		)
		return false
	}
	return true
}

func (g *Gateway) handleConnectorAuthorityEntry(w http.ResponseWriter, r *http.Request) bool {
	return precinctcontrol.DispatchConnectorAuthorityRoutes(
		w,
		r,
		precinctcontrol.ConnectorAuthorityRouteConfig{
			MiddlewareStep:  v24MiddlewareStep,
			ConnectorAuthMW: v24MiddlewareConnectorAuth,
		},
		precinctcontrol.ConnectorAuthorityRoutes{
			HandleRegister: func(w http.ResponseWriter, r *http.Request) bool {
				if isConnectorMutationPath(r.URL.Path) && !g.authorizeConnectorMutationRequest(w, r) {
					return true
				}
				g.handleConnectorRegister(w, r)
				return true
			},
			HandleValidate: func(w http.ResponseWriter, r *http.Request) bool {
				if isConnectorMutationPath(r.URL.Path) && !g.authorizeConnectorMutationRequest(w, r) {
					return true
				}
				g.handleConnectorValidate(w, r)
				return true
			},
			HandleApprove: func(w http.ResponseWriter, r *http.Request) bool {
				if isConnectorMutationPath(r.URL.Path) && !g.authorizeConnectorMutationRequest(w, r) {
					return true
				}
				g.handleConnectorApprove(w, r)
				return true
			},
			HandleActivate: func(w http.ResponseWriter, r *http.Request) bool {
				if isConnectorMutationPath(r.URL.Path) && !g.authorizeConnectorMutationRequest(w, r) {
					return true
				}
				g.handleConnectorActivate(w, r)
				return true
			},
			HandleRevoke: func(w http.ResponseWriter, r *http.Request) bool {
				if isConnectorMutationPath(r.URL.Path) && !g.authorizeConnectorMutationRequest(w, r) {
					return true
				}
				g.handleConnectorRevoke(w, r)
				return true
			},
			HandleStatus: func(w http.ResponseWriter, r *http.Request) bool {
				g.handleConnectorStatus(w, r)
				return true
			},
			HandleReport: func(w http.ResponseWriter, r *http.Request) bool {
				g.handleConnectorReport(w, r)
				return true
			},
		},
	)
}

func (g *Gateway) decodeConnectorLifecycleRequest(w http.ResponseWriter, r *http.Request) (connectorLifecycleRequest, bool) {
	if r.Method != http.MethodPost {
		g.writeConnectorRequestError(
			w,
			r,
			http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest,
			"method not allowed",
			map[string]any{"expected_method": http.MethodPost},
		)
		return connectorLifecycleRequest{}, false
	}
	var req connectorLifecycleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		g.writeConnectorRequestError(
			w,
			r,
			http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest,
			"invalid json payload",
			nil,
		)
		return connectorLifecycleRequest{}, false
	}
	if req.ConnectorID == "" {
		req.ConnectorID = strings.TrimSpace(req.Manifest.ConnectorID)
	}
	if strings.TrimSpace(req.ConnectorID) == "" {
		g.writeConnectorRequestError(
			w,
			r,
			http.StatusBadRequest,
			middleware.ErrContractValidationFailed,
			"connector_id is required",
			nil,
		)
		return connectorLifecycleRequest{}, false
	}
	return req, true
}

func (g *Gateway) handleConnectorRegister(w http.ResponseWriter, r *http.Request) {
	if !g.authorizeAdminRequest(w, r) {
		return
	}
	req, ok := g.decodeConnectorLifecycleRequest(w, r)
	if !ok {
		return
	}
	req.Manifest.ConnectorID = req.ConnectorID
	rec, err := g.cca.register(req.Manifest)
	if err != nil {
		g.writeConnectorOpError(w, r, req.ConnectorID, "register", err)
		return
	}
	g.writeConnectorOpOK(w, r, req.ConnectorID, "register", rec)
}

func (g *Gateway) handleConnectorValidate(w http.ResponseWriter, r *http.Request) {
	if !g.authorizeAdminRequest(w, r) {
		return
	}
	req, ok := g.decodeConnectorLifecycleRequest(w, r)
	if !ok {
		return
	}
	rec, err := g.cca.validate(req.ConnectorID)
	if err != nil {
		g.writeConnectorOpError(w, r, req.ConnectorID, "validate", err)
		return
	}
	g.writeConnectorOpOK(w, r, req.ConnectorID, "validate", rec)
}

func (g *Gateway) handleConnectorApprove(w http.ResponseWriter, r *http.Request) {
	if !g.authorizeAdminRequest(w, r) {
		return
	}
	req, ok := g.decodeConnectorLifecycleRequest(w, r)
	if !ok {
		return
	}
	rec, err := g.cca.approve(req.ConnectorID)
	if err != nil {
		g.writeConnectorOpError(w, r, req.ConnectorID, "approve", err)
		return
	}
	g.writeConnectorOpOK(w, r, req.ConnectorID, "approve", rec)
}

func (g *Gateway) handleConnectorActivate(w http.ResponseWriter, r *http.Request) {
	if !g.authorizeAdminRequest(w, r) {
		return
	}
	req, ok := g.decodeConnectorLifecycleRequest(w, r)
	if !ok {
		return
	}
	rec, err := g.cca.activate(req.ConnectorID)
	if err != nil {
		g.writeConnectorOpError(w, r, req.ConnectorID, "activate", err)
		return
	}
	g.writeConnectorOpOK(w, r, req.ConnectorID, "activate", rec)
}

func (g *Gateway) handleConnectorRevoke(w http.ResponseWriter, r *http.Request) {
	if !g.authorizeAdminRequest(w, r) {
		return
	}
	req, ok := g.decodeConnectorLifecycleRequest(w, r)
	if !ok {
		return
	}
	rec, err := g.cca.revoke(req.ConnectorID)
	if err != nil {
		g.writeConnectorOpError(w, r, req.ConnectorID, "revoke", err)
		return
	}
	g.writeConnectorOpOK(w, r, req.ConnectorID, "revoke", rec)
}

func (g *Gateway) handleConnectorStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		g.writeConnectorRequestError(
			w,
			r,
			http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest,
			"method not allowed",
			map[string]any{"expected_method": http.MethodGet},
		)
		return
	}
	connectorID := strings.TrimSpace(r.URL.Query().Get("connector_id"))
	if connectorID == "" {
		g.writeConnectorRequestError(
			w,
			r,
			http.StatusBadRequest,
			middleware.ErrContractValidationFailed,
			"connector_id query parameter is required",
			nil,
		)
		return
	}
	rec, ok := g.cca.status(connectorID)
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	if !ok {
		g.logConnectorAuthorityDecision(r, connectorID, "status", "deny", "connector_not_found", decisionID, traceID, http.StatusNotFound)
		writeV24GatewayError(
			w,
			r,
			http.StatusNotFound,
			middleware.ErrContractValidationFailed,
			"connector not found",
			v24MiddlewareConnectorAuth,
			ReasonContractInvalid,
			map[string]any{
				"connector_id": connectorID,
			},
		)
		return
	}
	g.logConnectorAuthorityDecision(r, connectorID, "status", "allow", "connector_found", decisionID, traceID, http.StatusOK)
	g.cca.updateAuditRef(connectorID, decisionID, traceID, "connector_found", "status")
	precinctevidence.WriteJSONResponse(w, http.StatusOK, map[string]any{
		"connector_id": connectorID,
		"status":       "ok",
		"state":        rec.State,
		"record":       rec,
		"decision_id":  decisionID,
		"trace_id":     traceID,
	})
}

func (g *Gateway) handleConnectorReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		g.writeConnectorRequestError(
			w,
			r,
			http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest,
			"method not allowed",
			map[string]any{"expected_method": http.MethodGet},
		)
		return
	}
	report := g.cca.conformanceReport()
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	g.logConnectorAuthorityDecision(r, "all", "report", "allow", "report_generated", decisionID, traceID, http.StatusOK)
	precinctevidence.WriteJSONResponse(w, http.StatusOK, precinctevidence.CloneConnectorConformanceReport(report, traceID, decisionID))
}

func (g *Gateway) writeConnectorOpOK(w http.ResponseWriter, r *http.Request, connectorID, operation string, rec connectorRecord) {
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	g.logConnectorAuthorityDecision(r, connectorID, operation, "allow", "operation_success", decisionID, traceID, http.StatusOK)
	g.cca.updateAuditRef(connectorID, decisionID, traceID, "operation_success", operation)
	precinctevidence.WriteJSONResponse(w, http.StatusOK, map[string]any{
		"connector_id": connectorID,
		"operation":    operation,
		"status":       "ok",
		"state":        rec.State,
		"record":       rec,
		"decision_id":  decisionID,
		"trace_id":     traceID,
	})
}

func (g *Gateway) writeConnectorOpError(w http.ResponseWriter, r *http.Request, connectorID, operation string, err error) {
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	g.logConnectorAuthorityDecision(r, connectorID, operation, "deny", err.Error(), decisionID, traceID, http.StatusBadRequest)
	g.cca.updateAuditRef(connectorID, decisionID, traceID, err.Error(), operation)
	writeV24GatewayError(
		w,
		r,
		http.StatusBadRequest,
		middleware.ErrContractValidationFailed,
		err.Error(),
		v24MiddlewareConnectorAuth,
		ReasonContractInvalid,
		map[string]any{
			"connector_id": connectorID,
			"operation":    operation,
		},
	)
}

func (g *Gateway) writeConnectorRequestError(
	w http.ResponseWriter,
	r *http.Request,
	httpCode int,
	errorCode string,
	message string,
	details map[string]any,
) {
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	g.logConnectorAuthorityDecision(
		r,
		strings.TrimSpace(r.URL.Query().Get("connector_id")),
		"request_validation",
		"deny",
		message,
		decisionID,
		traceID,
		httpCode,
	)
	writeV24GatewayError(
		w,
		r,
		httpCode,
		errorCode,
		message,
		v24MiddlewareConnectorAuth,
		ReasonContractInvalid,
		details,
	)
}

func (g *Gateway) logConnectorAuthorityDecision(r *http.Request, connectorID, operation, decision, reason, decisionID, traceID string, httpStatus int) {
	precinctevidence.LogConnectorAuthorityDecision(g.auditor, r, connectorID, operation, decision, reason, decisionID, traceID, httpStatus)
}

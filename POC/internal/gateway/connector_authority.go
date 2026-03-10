package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
	"github.com/xeipuuv/gojsonschema"
)

const connectorManifestSchemaVersion = "v1"
const connectorSignatureAlgorithm = "sha256-manifest-v1"

// connectorManifestSchemaV1 is the runtime validator contract used by CCA.
// The documented copy is published under contracts/v2.4/schemas.
const connectorManifestSchemaV1 = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Connector Manifest v1",
  "type": "object",
  "required": ["connector_id", "connector_type", "source_principal", "signature"],
  "properties": {
    "connector_id": {"type": "string", "minLength": 1},
    "connector_type": {"type": "string", "minLength": 1},
    "source_principal": {"type": "string", "minLength": 1},
    "version": {"type": "string"},
    "capabilities": {
      "type": "array",
      "items": {"type": "string"}
    },
    "signature": {
      "type": "object",
      "required": ["algorithm", "value"],
      "properties": {
        "algorithm": {"type": "string", "const": "sha256-manifest-v1"},
        "value": {"type": "string", "minLength": 1}
      },
      "additionalProperties": false
    },
    "metadata": {"type": "object"}
  },
  "additionalProperties": true
}`

type connectorState string

const (
	connectorStateRegistered connectorState = "registered"
	connectorStateValidated  connectorState = "validated"
	connectorStateApproved   connectorState = "approved"
	connectorStateActive     connectorState = "active"
	connectorStateRevoked    connectorState = "revoked"
)

type connectorManifestSignature struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type connectorManifest struct {
	ConnectorID     string                     `json:"connector_id"`
	ConnectorType   string                     `json:"connector_type"`
	SourcePrincipal string                     `json:"source_principal"`
	Version         string                     `json:"version,omitempty"`
	Capabilities    []string                   `json:"capabilities,omitempty"`
	Signature       connectorManifestSignature `json:"signature"`
	Metadata        map[string]any             `json:"metadata,omitempty"`
}

type connectorRecord struct {
	ConnectorID     string            `json:"connector_id"`
	State           connectorState    `json:"state"`
	Manifest        connectorManifest `json:"manifest"`
	SchemaVersion   string            `json:"schema_version"`
	ExpectedSig     string            `json:"expected_signature"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	LastDecisionID  string            `json:"last_decision_id,omitempty"`
	LastTraceID     string            `json:"last_trace_id,omitempty"`
	LastReason      string            `json:"last_reason,omitempty"`
	LastOperation   string            `json:"last_operation,omitempty"`
	LastValidatedAt time.Time         `json:"last_validated_at,omitempty"`
}

type connectorConformanceAuthority struct {
	mu         sync.RWMutex
	connectors map[string]*connectorRecord
}

func newConnectorConformanceAuthority() *connectorConformanceAuthority {
	return &connectorConformanceAuthority{connectors: map[string]*connectorRecord{}}
}

func validateConnectorManifestSchema(manifest connectorManifest) error {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	schemaLoader := gojsonschema.NewStringLoader(connectorManifestSchemaV1)
	docLoader := gojsonschema.NewBytesLoader(raw)
	result, err := gojsonschema.Validate(schemaLoader, docLoader)
	if err != nil {
		return fmt.Errorf("schema validate failed: %w", err)
	}
	if result.Valid() {
		return nil
	}
	errParts := make([]string, 0, len(result.Errors()))
	for _, e := range result.Errors() {
		errParts = append(errParts, e.String())
	}
	sort.Strings(errParts)
	return fmt.Errorf("schema invalid: %s", strings.Join(errParts, "; "))
}

func computeConnectorExpectedSignature(manifest connectorManifest) string {
	caps := append([]string(nil), manifest.Capabilities...)
	sort.Strings(caps)
	canon := map[string]any{
		"connector_id":     strings.TrimSpace(manifest.ConnectorID),
		"connector_type":   strings.TrimSpace(manifest.ConnectorType),
		"source_principal": strings.TrimSpace(manifest.SourcePrincipal),
		"version":          strings.TrimSpace(manifest.Version),
		"capabilities":     caps,
	}
	payload, _ := json.Marshal(canon)
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func (c *connectorConformanceAuthority) register(manifest connectorManifest) (connectorRecord, error) {
	if strings.TrimSpace(manifest.ConnectorID) == "" {
		return connectorRecord{}, fmt.Errorf("connector_id is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UTC()
	expected := computeConnectorExpectedSignature(manifest)
	rec, ok := c.connectors[manifest.ConnectorID]
	if !ok {
		rec = &connectorRecord{
			ConnectorID:   manifest.ConnectorID,
			CreatedAt:     now,
			SchemaVersion: connectorManifestSchemaVersion,
		}
		c.connectors[manifest.ConnectorID] = rec
	}
	rec.Manifest = manifest
	rec.ExpectedSig = expected
	rec.State = connectorStateRegistered
	rec.UpdatedAt = now
	rec.LastOperation = "register"
	rec.LastReason = "connector registered"
	return *rec, nil
}

func (c *connectorConformanceAuthority) validate(connectorID string) (connectorRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return connectorRecord{}, fmt.Errorf("connector not found")
	}
	if rec.State != connectorStateRegistered {
		return connectorRecord{}, fmt.Errorf("invalid transition: %s -> validated", rec.State)
	}
	if err := validateConnectorManifestSchema(rec.Manifest); err != nil {
		rec.LastOperation = "validate"
		rec.LastReason = err.Error()
		rec.UpdatedAt = time.Now().UTC()
		return connectorRecord{}, err
	}
	if !strings.EqualFold(strings.TrimSpace(rec.Manifest.Signature.Algorithm), connectorSignatureAlgorithm) {
		rec.LastOperation = "validate"
		rec.LastReason = "invalid signature algorithm"
		rec.UpdatedAt = time.Now().UTC()
		return connectorRecord{}, fmt.Errorf("invalid signature algorithm")
	}
	expected := computeConnectorExpectedSignature(rec.Manifest)
	if rec.Manifest.Signature.Value != expected {
		rec.LastOperation = "validate"
		rec.LastReason = "signature mismatch"
		rec.UpdatedAt = time.Now().UTC()
		return connectorRecord{}, fmt.Errorf("signature mismatch")
	}
	rec.ExpectedSig = expected
	rec.State = connectorStateValidated
	rec.UpdatedAt = time.Now().UTC()
	rec.LastValidatedAt = rec.UpdatedAt
	rec.LastOperation = "validate"
	rec.LastReason = "connector validated"
	return *rec, nil
}

func (c *connectorConformanceAuthority) approve(connectorID string) (connectorRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return connectorRecord{}, fmt.Errorf("connector not found")
	}
	if rec.State != connectorStateValidated {
		return connectorRecord{}, fmt.Errorf("invalid transition: %s -> approved", rec.State)
	}
	rec.State = connectorStateApproved
	rec.UpdatedAt = time.Now().UTC()
	rec.LastOperation = "approve"
	rec.LastReason = "connector approved"
	return *rec, nil
}

func (c *connectorConformanceAuthority) activate(connectorID string) (connectorRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return connectorRecord{}, fmt.Errorf("connector not found")
	}
	if rec.State != connectorStateApproved {
		return connectorRecord{}, fmt.Errorf("invalid transition: %s -> active", rec.State)
	}
	rec.State = connectorStateActive
	rec.UpdatedAt = time.Now().UTC()
	rec.LastOperation = "activate"
	rec.LastReason = "connector active"
	return *rec, nil
}

func (c *connectorConformanceAuthority) revoke(connectorID string) (connectorRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return connectorRecord{}, fmt.Errorf("connector not found")
	}
	switch rec.State {
	case connectorStateRegistered, connectorStateValidated, connectorStateApproved, connectorStateActive:
		rec.State = connectorStateRevoked
		rec.UpdatedAt = time.Now().UTC()
		rec.LastOperation = "revoke"
		rec.LastReason = "connector revoked"
		return *rec, nil
	default:
		return connectorRecord{}, fmt.Errorf("invalid transition: %s -> revoked", rec.State)
	}
}

func (c *connectorConformanceAuthority) status(connectorID string) (connectorRecord, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return connectorRecord{}, false
	}
	return *rec, true
}

func (c *connectorConformanceAuthority) updateAuditRef(connectorID, decisionID, traceID, reason, operation string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return
	}
	rec.LastDecisionID = decisionID
	rec.LastTraceID = traceID
	rec.LastReason = reason
	rec.LastOperation = operation
	rec.UpdatedAt = time.Now().UTC()
}

func (c *connectorConformanceAuthority) runtimeCheck(connectorID, signature string) (bool, string, connectorRecord) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rec, ok := c.connectors[connectorID]
	if !ok {
		return false, "connector_not_registered", connectorRecord{}
	}
	if rec.State != connectorStateActive {
		return false, "connector_not_active", *rec
	}
	if strings.TrimSpace(signature) == "" {
		return false, "connector_signature_missing", *rec
	}
	if signature != rec.ExpectedSig {
		return false, "connector_signature_invalid", *rec
	}
	return true, "connector_active", *rec
}

func (c *connectorConformanceAuthority) conformanceReport() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rows := make([]map[string]any, 0, len(c.connectors))
	for _, rec := range c.connectors {
		rows = append(rows, map[string]any{
			"connector_id":     rec.ConnectorID,
			"state":            rec.State,
			"schema_version":   rec.SchemaVersion,
			"last_operation":   rec.LastOperation,
			"last_reason":      rec.LastReason,
			"last_decision_id": rec.LastDecisionID,
			"last_trace_id":    rec.LastTraceID,
			"updated_at":       rec.UpdatedAt,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i]["connector_id"].(string) < rows[j]["connector_id"].(string)
	})
	return map[string]any{
		"report_type":    "connector_conformance_v1",
		"generated_at":   time.Now().UTC(),
		"schema_version": connectorManifestSchemaVersion,
		"connectors":     rows,
	}
}

type connectorLifecycleRequest struct {
	ConnectorID string            `json:"connector_id"`
	Manifest    connectorManifest `json:"manifest"`
}

func isConnectorMutationPath(path string) bool {
	switch path {
	case "/v1/connectors/register",
		"/v1/connectors/validate",
		"/v1/connectors/approve",
		"/v1/connectors/activate",
		"/v1/connectors/revoke":
		return true
	default:
		return false
	}
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
	if !strings.HasPrefix(r.URL.Path, "/v1/connectors/") {
		return false
	}

	if isConnectorMutationPath(r.URL.Path) && !g.authorizeConnectorMutationRequest(w, r) {
		return true
	}

	switch r.URL.Path {
	case "/v1/connectors/register":
		g.handleConnectorRegister(w, r)
		return true
	case "/v1/connectors/validate":
		g.handleConnectorValidate(w, r)
		return true
	case "/v1/connectors/approve":
		g.handleConnectorApprove(w, r)
		return true
	case "/v1/connectors/activate":
		g.handleConnectorActivate(w, r)
		return true
	case "/v1/connectors/revoke":
		g.handleConnectorRevoke(w, r)
		return true
	case "/v1/connectors/status":
		g.handleConnectorStatus(w, r)
		return true
	case "/v1/connectors/report":
		g.handleConnectorReport(w, r)
		return true
	default:
		return false
	}
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
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
	report["decision_id"] = decisionID
	report["trace_id"] = traceID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(report)
}

func (g *Gateway) writeConnectorOpOK(w http.ResponseWriter, r *http.Request, connectorID, operation string, rec connectorRecord) {
	traceID, decisionID := getDecisionCorrelationIDs(r, RunEnvelope{})
	g.logConnectorAuthorityDecision(r, connectorID, operation, "allow", "operation_success", decisionID, traceID, http.StatusOK)
	g.cca.updateAuditRef(connectorID, decisionID, traceID, "operation_success", operation)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
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
	if g == nil || g.auditor == nil {
		return
	}
	result := fmt.Sprintf("connector_id=%s operation=%s decision=%s reason=%s", connectorID, operation, decision, reason)
	g.auditor.Log(middleware.AuditEvent{
		SessionID:  middleware.GetSessionID(r.Context()),
		DecisionID: decisionID,
		TraceID:    traceID,
		SPIFFEID:   middleware.GetSPIFFEID(r.Context()),
		Action:     "connector_authority." + operation,
		Result:     result,
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: httpStatus,
	})
}

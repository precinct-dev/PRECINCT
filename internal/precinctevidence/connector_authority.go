package precinctevidence

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

// AuditLogger is the minimal subset of an audit logger used by evidence helpers.
type AuditLogger interface {
	Log(middleware.AuditEvent)
}

// DecisionIDResolver maps a request to decision/trace correlation identifiers.
type DecisionIDResolver func(*http.Request) (traceID string, decisionID string)

// LogConnectorAuthorityDecision records a connector conformance decision event.
func LogConnectorAuthorityDecision(
	logger AuditLogger,
	r *http.Request,
	connectorID, operation, decision, reason, decisionID, traceID string,
	httpStatus int,
) {
	if logger == nil || r == nil {
		return
	}
	result := fmt.Sprintf("connector_id=%s operation=%s decision=%s reason=%s", connectorID, operation, decision, reason)
	logger.Log(middleware.AuditEvent{
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

// CloneConnectorConformanceReport returns a copy of report augmented with correlation fields.
func CloneConnectorConformanceReport(report map[string]any, traceID, decisionID string) map[string]any {
	out := make(map[string]any, len(report)+2)
	for k, v := range report {
		out[k] = v
	}
	out["decision_id"] = decisionID
	out["trace_id"] = traceID
	return out
}

// WriteJSONResponse writes a stable JSON response for internal control reporting.
func WriteJSONResponse(w http.ResponseWriter, statusCode int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

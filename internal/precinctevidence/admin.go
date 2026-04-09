// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctevidence

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

// LogLoopAdminDecision records audit data for admin loop operations.
func LogLoopAdminDecision(
	logger AuditLogger,
	r *http.Request,
	action string,
	metadata map[string]any,
	decisionID string,
	traceID string,
	httpStatus int,
) {
	if logger == nil || r == nil {
		return
	}

	result := "action=" + action + " status=" + itoa(httpStatus)
	if metadata != nil {
		if runID, ok := metadata["run_id"]; ok {
			result += " run_id=" + stringify(runID)
		}
		if state, ok := metadata["state"]; ok {
			result += " state=" + stringify(state)
		}
		if reason, ok := metadata["halt_reason"]; ok {
			result += " halt_reason=" + stringify(reason)
		}
		if errMsg, ok := metadata["error"]; ok {
			result += " error=" + stringify(errMsg)
		}
	}

	logger.Log(middleware.AuditEvent{
		SessionID:  middleware.GetSessionID(r.Context()),
		DecisionID: decisionID,
		TraceID:    traceID,
		SPIFFEID:   middleware.GetSPIFFEID(r.Context()),
		Action:     action,
		Result:     result,
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: httpStatus,
	})
}

// LogRuleOpsDecision records audit data for DLP RuleOps operations.
func LogRuleOpsDecision(
	logger AuditLogger,
	r *http.Request,
	rulesetID string,
	operation string,
	decision string,
	reason string,
	decisionID string,
	traceID string,
	httpStatus int,
) {
	if logger == nil || r == nil {
		return
	}
	logger.Log(middleware.AuditEvent{
		SessionID:  middleware.GetSessionID(r.Context()),
		DecisionID: decisionID,
		TraceID:    traceID,
		SPIFFEID:   middleware.GetSPIFFEID(r.Context()),
		Action:     "ruleops." + operation,
		Result:     "ruleset_id=" + rulesetID + " operation=" + operation + " decision=" + decision + " reason=" + reason,
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: httpStatus,
	})
}

func itoa(i int) string {
	return strconv.Itoa(i)
}

func stringify(v any) string {
	return fmt.Sprintf("%v", v)
}

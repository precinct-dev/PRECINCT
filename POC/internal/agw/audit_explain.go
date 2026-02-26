package agw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
)

type auditStepDef struct {
	Step  int
	Layer string
}

var auditStepDefs = []auditStepDef{
	{Step: 1, Layer: "Request Size Limit"},
	{Step: 2, Layer: "Body Capture"},
	{Step: 3, Layer: "SPIFFE Auth"},
	{Step: 4, Layer: "Audit Log"},
	{Step: 5, Layer: "Tool Registry Verify"},
	{Step: 6, Layer: "OPA Policy"},
	{Step: 7, Layer: "DLP Scanner"},
	{Step: 8, Layer: "Session Context"},
	{Step: 9, Layer: "Step-Up Gating"},
	{Step: 10, Layer: "Deep Scan"},
	{Step: 11, Layer: "Rate Limiter"},
	{Step: 12, Layer: "Circuit Breaker"},
	{Step: 13, Layer: "Token Substitution"},
}

var errorCodeToStep = map[string]int{
	middleware.ErrRequestTooLarge: 1,

	middleware.ErrAuthMissingIdentity: 3,
	middleware.ErrAuthInvalidIdentity: 3,

	middleware.ErrRegistryHashMismatch: 5,
	middleware.ErrRegistryToolUnknown:  5,
	middleware.ErrMCPInvalidRequest:    5,
	middleware.ErrUICapabilityDenied:   5,

	middleware.ErrAuthzPolicyDenied:    6,
	middleware.ErrAuthzNoMatchingGrant: 6,
	middleware.ErrAuthzToolNotFound:    6,

	middleware.ErrDLPCredentialsDetected: 7,
	middleware.ErrDLPInjectionBlocked:    7,
	middleware.ErrDLPPIIBlocked:          7,

	middleware.ErrExfiltrationDetected: 8,

	middleware.ErrStepUpDenied:             9,
	middleware.ErrStepUpApprovalRequired:   9,
	middleware.ErrStepUpGuardBlocked:       9,
	middleware.ErrStepUpDestinationBlocked: 9,

	middleware.ErrDeepScanBlocked:               10,
	middleware.ErrDeepScanUnavailableFailClosed: 10,
	middleware.ErrUIResourceBlocked:             10,

	middleware.ErrRateLimitExceeded: 11,

	middleware.ErrCircuitOpen: 12,

	middleware.ErrMCPTransportFailed: 13,
	middleware.ErrMCPRequestFailed:   13,
	middleware.ErrMCPInvalidResponse: 13,
}

type AuditExplainLayer struct {
	Step   int    `json:"step"`
	Layer  string `json:"layer"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type AuditExplainOutput struct {
	DecisionID string              `json:"decision_id"`
	Timestamp  string              `json:"timestamp"`
	SPIFFEID   string              `json:"spiffe_id"`
	Tool       string              `json:"tool"`
	Result     string              `json:"result"`
	StatusCode int                 `json:"status_code"`
	TraceID    string              `json:"trace_id"`
	ErrorCode  string              `json:"error_code,omitempty"`
	Layers     []AuditExplainLayer `json:"layers"`
}

// ErrorCodeToStep maps a gateway error code to the middleware step.
func ErrorCodeToStep(code string) (int, bool) {
	step, ok := errorCodeToStep[strings.TrimSpace(code)]
	return step, ok
}

// BuildAuditExplain reconstructs a layer-by-layer trace for a decision.
func BuildAuditExplain(entries []map[string]any, decisionID string) (AuditExplainOutput, error) {
	if strings.TrimSpace(decisionID) == "" {
		return AuditExplainOutput{}, fmt.Errorf("decision-id is required")
	}
	if len(entries) == 0 {
		return AuditExplainOutput{}, fmt.Errorf("no audit entries found for decision-id %q", decisionID)
	}

	mainEntry := pickMainAuditEntry(entries, decisionID)
	if mainEntry == nil {
		return AuditExplainOutput{}, fmt.Errorf("no mcp_request entry found for decision-id %q", decisionID)
	}

	statusCode, _ := getInt(mainEntry, "status_code")
	out := AuditExplainOutput{
		DecisionID: decisionID,
		Timestamp:  getString(mainEntry, "timestamp"),
		SPIFFEID:   getString(mainEntry, "spiffe_id"),
		Tool:       getString(mainEntry, "tool"),
		StatusCode: statusCode,
		TraceID:    getString(mainEntry, "trace_id"),
	}

	if statusCode >= 400 {
		out.Result = fmt.Sprintf("denied (HTTP %d)", statusCode)
	} else {
		out.Result = "allowed"
	}

	errorCode := extractErrorCode(mainEntry)
	failedStep, detail := 0, ""
	if statusCode >= 400 {
		if step, ok := getInt(mainEntry, "middleware_step"); ok {
			failedStep = step
		}
		if failedStep == 0 && errorCode != "" {
			if step, ok := ErrorCodeToStep(errorCode); ok {
				failedStep = step
			}
		}

		if errorCode == "" {
			errorCode = inferErrorCode(mainEntry, entries)
		}
		if failedStep == 0 {
			if step, ok := ErrorCodeToStep(errorCode); ok {
				failedStep = step
			}
		}
		if failedStep == 0 {
			failedStep = inferStepWithoutErrorCode(mainEntry, entries)
		}
		if failedStep < 1 || failedStep > 13 {
			failedStep = 13
		}

		detail = inferFailureDetail(mainEntry, entries, errorCode, failedStep)
	}

	out.ErrorCode = errorCode
	out.Layers = buildLayerTrace(mainEntry, decisionID, failedStep, detail)
	return out, nil
}

func RenderAuditExplainJSON(out AuditExplainOutput) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderAuditExplainTable(out AuditExplainOutput) (string, error) {
	var buf bytes.Buffer
	_, _ = fmt.Fprintf(&buf, "DECISION: %s\n", out.DecisionID)
	_, _ = fmt.Fprintf(&buf, "TIMESTAMP: %s\n", out.Timestamp)
	_, _ = fmt.Fprintf(&buf, "SPIFFE ID: %s\n", out.SPIFFEID)
	_, _ = fmt.Fprintf(&buf, "TOOL: %s\n", out.Tool)
	_, _ = fmt.Fprintf(&buf, "RESULT: %s\n", out.Result)
	if out.ErrorCode != "" {
		_, _ = fmt.Fprintf(&buf, "ERROR CODE: %s\n", out.ErrorCode)
	}
	_, _ = fmt.Fprintln(&buf)

	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "STEP\tLAYER\tSTATUS\tDETAIL")
	for _, layer := range out.Layers {
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", layer.Step, layer.Layer, layer.Status, layer.Detail)
	}
	_ = tw.Flush()
	return buf.String(), nil
}

func pickMainAuditEntry(entries []map[string]any, decisionID string) map[string]any {
	var candidates []map[string]any
	for _, e := range entries {
		if getString(e, "decision_id") == decisionID {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	// Prefer the terminal mcp_request event for the decision.
	for _, e := range candidates {
		if getString(e, "action") == "mcp_request" {
			return e
		}
	}

	// Fall back to the most recent timestamp.
	sort.SliceStable(candidates, func(i, j int) bool {
		return getString(candidates[i], "timestamp") > getString(candidates[j], "timestamp")
	})
	return candidates[0]
}

func extractErrorCode(entry map[string]any) string {
	if v := getString(entry, "error_code"); v != "" {
		return v
	}
	if v := getString(entry, "code"); v != "" {
		return v
	}
	if raw, ok := entry["error"].(map[string]any); ok {
		if v := getString(raw, "code"); v != "" {
			return v
		}
	}
	return ""
}

func inferErrorCode(mainEntry map[string]any, entries []map[string]any) string {
	statusCode, _ := getInt(mainEntry, "status_code")
	switch statusCode {
	case 401:
		return middleware.ErrAuthMissingIdentity
	case 413:
		return middleware.ErrRequestTooLarge
	case 429:
		return middleware.ErrRateLimitExceeded
	case 503:
		if hasActionEntry(entries, "deep_scan", "blocked=true") {
			return middleware.ErrDeepScanBlocked
		}
		return middleware.ErrCircuitOpen
	case 403:
		if hasActionEntry(entries, "step_up_gating", "allowed=false") {
			return middleware.ErrStepUpDenied
		}
		if hasActionEntry(entries, "deep_scan", "blocked=true") {
			return middleware.ErrDeepScanBlocked
		}
		if authz, ok := mainEntry["authorization"].(map[string]any); ok {
			if allowed, ok := authz["allowed"].(bool); ok && !allowed {
				return middleware.ErrAuthzPolicyDenied
			}
		}
		return middleware.ErrRegistryToolUnknown
	default:
		return ""
	}
}

func inferStepWithoutErrorCode(mainEntry map[string]any, entries []map[string]any) int {
	statusCode, _ := getInt(mainEntry, "status_code")
	switch statusCode {
	case 401:
		return 3
	case 413:
		return 1
	case 429:
		return 11
	case 503:
		if hasActionEntry(entries, "deep_scan", "blocked=true") {
			return 10
		}
		return 12
	case 403:
		if hasActionEntry(entries, "step_up_gating", "allowed=false") {
			return 9
		}
		if hasActionEntry(entries, "deep_scan", "blocked=true") {
			return 10
		}
		if authz, ok := mainEntry["authorization"].(map[string]any); ok {
			if allowed, ok := authz["allowed"].(bool); ok && !allowed {
				return 6
			}
		}
		return 5
	default:
		return 0
	}
}

func inferFailureDetail(mainEntry map[string]any, entries []map[string]any, errorCode string, failedStep int) string {
	if msg := getString(mainEntry, "message"); msg != "" {
		return msg
	}
	if action, result := findCorrelatedAction(entries); action != "" {
		return fmt.Sprintf("%s: %s", action, result)
	}
	if errorCode != "" {
		return fmt.Sprintf("error_code=%s", errorCode)
	}
	statusCode, _ := getInt(mainEntry, "status_code")
	return fmt.Sprintf("request denied at step %d (status=%d)", failedStep, statusCode)
}

func findCorrelatedAction(entries []map[string]any) (string, string) {
	for _, e := range entries {
		action := getString(e, "action")
		switch action {
		case "step_up_gating", "deep_scan":
			return action, getString(e, "result")
		}
	}
	return "", ""
}

func hasActionEntry(entries []map[string]any, action, contains string) bool {
	for _, e := range entries {
		if getString(e, "action") != action {
			continue
		}
		if contains == "" || strings.Contains(getString(e, "result"), contains) {
			return true
		}
	}
	return false
}

func buildLayerTrace(mainEntry map[string]any, decisionID string, failedStep int, failureDetail string) []AuditExplainLayer {
	out := make([]AuditExplainLayer, 0, len(auditStepDefs))
	for _, def := range auditStepDefs {
		layer := AuditExplainLayer{
			Step:   def.Step,
			Layer:  def.Layer,
			Status: "PASS",
			Detail: defaultPassDetail(def.Step, mainEntry, decisionID),
		}

		if failedStep > 0 {
			switch {
			case def.Step == failedStep:
				layer.Status = "FAIL"
				layer.Detail = failureDetail
			case def.Step > failedStep:
				layer.Status = "SKIPPED"
				layer.Detail = fmt.Sprintf("request denied at step %d", failedStep)
			}
		}

		out = append(out, layer)
	}
	return out
}

func defaultPassDetail(step int, mainEntry map[string]any, decisionID string) string {
	switch step {
	case 3:
		if spiffe := getString(mainEntry, "spiffe_id"); spiffe != "" {
			return fmt.Sprintf("spiffe_id=%s", spiffe)
		}
	case 4:
		return fmt.Sprintf("decision_id=%s", decisionID)
	case 5:
		if sec, ok := mainEntry["security"].(map[string]any); ok {
			if verified, ok := sec["tool_hash_verified"]; ok {
				return fmt.Sprintf("tool_hash_verified=%v", verified)
			}
		}
	}
	return "--"
}

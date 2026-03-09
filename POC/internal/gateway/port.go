package gateway

import (
	"context"
	"net/http"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
)

// PortAdapter is the extension point for third-party agent integrations.
// Each adapter claims a set of URL paths and handles matching requests.
type PortAdapter interface {
	// Name returns a short, unique identifier for the port.
	Name() string

	// TryServeHTTP inspects the request and, if the path belongs to this port,
	// serves it and returns true. Returns false if the request is not handled.
	TryServeHTTP(w http.ResponseWriter, r *http.Request) bool
}

// PortGatewayServices is the narrow facade that port adapters use to access
// gateway internals. It exposes only the operations needed by adapters,
// keeping the coupling surface small and explicit.
type PortGatewayServices interface {
	// Model plane
	BuildModelPlaneRequest(r *http.Request, payload map[string]any) PlaneRequestV2
	EvaluateModelPlaneDecision(r *http.Request, req PlaneRequestV2) (Decision, ReasonCode, int, map[string]any)
	ExecuteModelEgress(ctx context.Context, attrs map[string]any, payload map[string]any, authHeader string) (*ModelEgressResult, error)
	ShouldApplyPolicyIntentProjection() bool

	// Tool plane
	EvaluateToolRequest(req PlaneRequestV2) ToolPlaneEvalResult

	// Messaging egress
	ExecuteMessagingEgress(ctx context.Context, attrs map[string]string, payload []byte, authHeader string) (*MessagingEgressResult, error)
	RedeemSPIKESecret(ctx context.Context, tokenStr string) (string, error)

	// Audit / logging
	LogPlaneDecision(r *http.Request, decision PlaneDecisionV2, httpStatus int)
	AuditLog(event middleware.AuditEvent)

	// Error writing
	WriteGatewayError(w http.ResponseWriter, r *http.Request, httpCode int, errorCode string, message string, middlewareName string, reason ReasonCode, details map[string]any)

	// Approval capabilities
	ValidateAndConsumeApproval(token string, scope middleware.ApprovalScope) (*middleware.ApprovalCapabilityClaims, error)
	HasApprovalService() bool

	// Connector conformance
	ValidateConnector(connectorID, signature string) (bool, string)

	// Content scanning (OC-di1n: exposes DLP scanner to port adapters)
	ScanContent(content string) middleware.ScanResult
}

// ModelEgressResult is the exported version of modelEgressResult for use by port adapters.
type ModelEgressResult struct {
	StatusCode       int
	ResponseBody     []byte
	ResponseHeaders  http.Header
	Reason           ReasonCode
	ProviderUsed     string
	UpstreamStatus   int
	FallbackAttempted bool
}

// ToolPlaneEvalResult is the exported version of toolPlaneEvalResult for use by port adapters.
type ToolPlaneEvalResult struct {
	Decision      Decision
	Reason        ReasonCode
	HTTPStatus    int
	RequireStepUp bool
	Metadata      map[string]any
}

// --- Exported helpers for port adapters ---

// GetDecisionCorrelationIDs returns (traceID, decisionID) for the request.
func GetDecisionCorrelationIDs(r *http.Request, env RunEnvelope) (string, string) {
	return getDecisionCorrelationIDs(r, env)
}

// MergeMetadata merges extra metadata into base, returning a new map.
func MergeMetadata(base, extra map[string]any) map[string]any {
	return mergeMetadata(base, extra)
}

// GetStringAttr returns a string attribute from a map with a fallback.
func GetStringAttr(attrs map[string]any, key, fallback string) string {
	return getStringAttr(attrs, key, fallback)
}

// DefaultString returns v if non-empty, otherwise fallback.
func DefaultString(v, fallback string) string {
	return defaultString(v, fallback)
}

// BuildModelPolicyIntentProjection builds the policy-intent projection XML.
func BuildModelPolicyIntentProjection(attrs map[string]any, envelope RunEnvelope) string {
	return buildModelPolicyIntentProjection(attrs, envelope)
}

// PrependSystemPolicyIntentMessage prepends a system message to the payload.
func PrependSystemPolicyIntentMessage(payload map[string]any, projection string) bool {
	return prependSystemPolicyIntentMessage(payload, projection)
}

// ProjectionHeaderValue returns the header value for policy-intent projection.
func ProjectionHeaderValue(enabled, applied bool) string {
	return projectionHeaderValue(enabled, applied)
}

// CopyHeaderIfPresent copies a header from src to dst if present.
func CopyHeaderIfPresent(dst http.Header, src http.Header, key string) {
	copyHeaderIfPresent(dst, src, key)
}

// StatusForToolReason maps a tool reason code to an HTTP status.
func StatusForToolReason(reason ReasonCode) int {
	return statusForToolReason(reason)
}

// OpenAICompatChatCompletionsPath is the path for OpenAI-compatible model egress.
const OpenAICompatChatCompletionsPath = "/openai/v1/chat/completions"

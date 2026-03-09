// Package mcpgateway provides a Go SDK for agent-gateway integration.
//
// GatewayError mirrors the unified JSON error envelope from the gateway
// middleware (RFA-tj9.1). Every denial from the gateway is parsed into
// this type so callers have a single, structured error to handle.
package mcpgateway

import "fmt"

// GatewayError represents a structured error returned by the security gateway.
// It mirrors the unified JSON envelope defined in internal/gateway/middleware/errors.go.
//
// Agent code should type-assert errors from [GatewayClient.Call] to *GatewayError
// to inspect denial details:
//
//	result, err := client.Call(ctx, "tool", params)
//	var ge *mcpgateway.GatewayError
//	if errors.As(err, &ge) {
//	    log.Printf("denied by %s (step %d): %s", ge.Middleware, ge.Step, ge.Code)
//	}
type GatewayError struct {
	// Code is the machine-readable error code (e.g. "authz_policy_denied").
	Code string `json:"code"`

	// Message is the human-readable error description.
	Message string `json:"message"`

	// Middleware identifies which middleware layer rejected the request.
	Middleware string `json:"middleware"`

	// Step is the middleware step number in the chain.
	Step int `json:"middleware_step"`

	// DecisionID is the audit decision ID for cross-referencing with audit logs.
	DecisionID string `json:"decision_id"`

	// TraceID is the OpenTelemetry trace ID for distributed tracing correlation.
	TraceID string `json:"trace_id"`

	// Details contains optional structured data (risk scores, etc.).
	Details map[string]any `json:"details,omitempty"`

	// Remediation provides optional guidance on how to resolve the error.
	Remediation string `json:"remediation,omitempty"`

	// DocsURL is an optional link to relevant documentation.
	DocsURL string `json:"docs_url,omitempty"`

	// HTTPStatus is the HTTP status code from the gateway response.
	// Not serialized to JSON -- it comes from the HTTP layer, not the body.
	HTTPStatus int `json:"-"`

	// ResponseMeta contains gateway advisory headers from the response.
	// Only populated when using [GatewayClient.CallWithMetadata].
	ResponseMeta ResponseMeta `json:"-"`
}

// Error implements the error interface.
func (e *GatewayError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("gateway error %s: %s", e.Code, e.Message)
	}
	if e.Code != "" {
		return fmt.Sprintf("gateway error %s", e.Code)
	}
	return fmt.Sprintf("gateway error (HTTP %d)", e.HTTPStatus)
}

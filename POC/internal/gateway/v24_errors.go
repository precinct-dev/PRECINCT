package gateway

import (
	"net/http"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

const (
	v24MiddlewareStep                = 16
	v24MiddlewarePhase3Plane         = "v24_phase3_plane"
	v24MiddlewareConnectorAuth       = "v24_connector_authority"
	v24MiddlewareRuleOpsAdmin        = "v24_ruleops_admin"
	v24MiddlewareApprovalAdmin       = "v24_approval_admin"
	v24MiddlewareBreakGlassAdmin     = "v24_breakglass_admin"
	v24MiddlewareProfileAdmin        = "v24_profile_admin"
	v24MiddlewareLoopAdmin           = "v24_loop_admin"
	v24MiddlewareCircuitBreakerAdmin = "v24_circuit_breaker_admin"
	v24MiddlewarePolicyReloadAdmin   = "v24_policy_reload_admin"
	v24MiddlewareAdminAuthz          = "v24_admin_authz"
	v24MiddlewareModelCompat         = "v24_model_compat"
	v24ReasonPolicyHookRejected      = ReasonContractInvalid
)

func writeV24GatewayError(
	w http.ResponseWriter,
	r *http.Request,
	httpCode int,
	errorCode string,
	message string,
	middlewareName string,
	reason ReasonCode,
	details map[string]any,
) {
	ge := middleware.GatewayError{
		Code:           errorCode,
		Message:        message,
		Middleware:     middlewareName,
		MiddlewareStep: v24MiddlewareStep,
		Details:        details,
	}
	if reason != "" {
		ge.ReasonCode = string(reason)
	}
	middleware.WriteGatewayError(w, r, httpCode, ge)
}

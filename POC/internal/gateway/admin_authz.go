package gateway

import (
	"net/http"
	"strings"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
)

func isAdminPath(path string) bool {
	return path == "/admin" || strings.HasPrefix(path, "/admin/")
}

func normalizeAdminAuthzAllowlist(ids []string) map[string]struct{} {
	normalized := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		normalized[id] = struct{}{}
	}
	return normalized
}

func (g *Gateway) isAdminPrincipalAuthorized(spiffeID string) bool {
	if g == nil {
		return false
	}
	if len(g.adminAuthzAllowedSPIFFEIDs) == 0 {
		return false
	}
	_, ok := g.adminAuthzAllowedSPIFFEIDs[strings.TrimSpace(spiffeID)]
	return ok
}

func adminMiddlewareForPath(path string) string {
	switch {
	case strings.HasPrefix(path, dlpRulesetAdminPath):
		return v24MiddlewareRuleOpsAdmin
	case strings.HasPrefix(path, approvalAdminPath):
		return v24MiddlewareApprovalAdmin
	case strings.HasPrefix(path, breakGlassAdminPath):
		return v24MiddlewareBreakGlassAdmin
	case strings.HasPrefix(path, profileAdminPath):
		return v24MiddlewareProfileAdmin
	case strings.HasPrefix(path, "/admin/loop/runs"):
		return v24MiddlewareLoopAdmin
	case strings.HasPrefix(path, "/admin/circuit-breakers"):
		return v24MiddlewareCircuitBreakerAdmin
	case strings.HasPrefix(path, "/admin/policy/reload"):
		return v24MiddlewarePolicyReloadAdmin
	case path == "/v1/connectors/register",
		path == "/v1/connectors/validate",
		path == "/v1/connectors/approve",
		path == "/v1/connectors/activate",
		path == "/v1/connectors/revoke":
		return v24MiddlewareConnectorAuth
	default:
		return v24MiddlewareAdminAuthz
	}
}

func (g *Gateway) authorizeAdminRequest(w http.ResponseWriter, r *http.Request) bool {
	principal := strings.TrimSpace(middleware.GetSPIFFEID(r.Context()))
	if principal == "" && g != nil && g.config != nil && strings.EqualFold(strings.TrimSpace(g.config.SPIFFEMode), "dev") {
		// Allow direct-dispatch dev/test flows where SPIFFEAuth middleware is not
		// part of the call path (for example unit tests invoking handlers directly).
		principal = strings.TrimSpace(r.Header.Get("X-SPIFFE-ID"))
	}
	adminMiddleware := adminMiddlewareForPath(r.URL.Path)

	if principal == "" {
		writeV24GatewayError(
			w,
			r,
			http.StatusUnauthorized,
			middleware.ErrAuthMissingIdentity,
			"admin endpoint requires SPIFFE identity",
			adminMiddleware,
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
			"admin access denied for principal",
			adminMiddleware,
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

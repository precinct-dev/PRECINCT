package gateway

import (
	"net/http"
	"strings"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"github.com/precinct-dev/precinct/internal/precinctcontrol"
)

func isAdminPath(path string) bool {
	return precinctcontrol.IsAdminPath(path)
}

func normalizeAdminAuthzAllowlist(ids []string) map[string]struct{} {
	return precinctcontrol.NormalizeAdminAuthzAllowlist(ids)
}

func (g *Gateway) isAdminPrincipalAuthorized(spiffeID string) bool {
	if g == nil {
		return false
	}
	return precinctcontrol.IsAdminPrincipalAuthorized(g.adminAuthzAllowedSPIFFEIDs, spiffeID)
}

func adminMiddlewareForPath(path string) string {
	names := precinctcontrol.AdminMiddlewareNames{
		ConnectorAuth: v24MiddlewareConnectorAuth,
		RuleOps:       v24MiddlewareRuleOpsAdmin,
		Approval:      v24MiddlewareApprovalAdmin,
		BreakGlass:    v24MiddlewareBreakGlassAdmin,
		Profile:       v24MiddlewareProfileAdmin,
		LoopRuns:      v24MiddlewareLoopAdmin,
		Circuit:       v24MiddlewareCircuitBreakerAdmin,
		PolicyReload:  v24MiddlewarePolicyReloadAdmin,
		Default:       v24MiddlewareAdminAuthz,
	}
	return precinctcontrol.ResolveAdminMiddlewareForPath(path, names)
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

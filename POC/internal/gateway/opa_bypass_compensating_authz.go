package gateway

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
)

func supportedBypassCheckIDs() map[string]struct{} {
	return map[string]struct{}{
		middleware.BypassCheckSPIFFEIdentity: {},
		middleware.BypassCheckAdminAllowlist: {},
		middleware.BypassCheckDemoModeGate:   {},
	}
}

func validateOPABypassCompensatingContracts() error {
	if err := middleware.ValidateOPABypassContracts(); err != nil {
		return err
	}

	supportedChecks := supportedBypassCheckIDs()
	var violations []string
	for _, contract := range middleware.ListOPABypassContracts() {
		for _, check := range contract.RequiredChecks {
			if _, ok := supportedChecks[strings.TrimSpace(check)]; !ok {
				violations = append(violations, fmt.Sprintf("contract %q requires unsupported check %q", contract.ID, check))
			}
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("opa bypass contract validation failed: %s", strings.Join(violations, "; "))
	}
	return nil
}

func (g *Gateway) requestPrincipal(r *http.Request) string {
	principal := strings.TrimSpace(middleware.GetSPIFFEID(r.Context()))
	if principal == "" && g != nil && g.config != nil && strings.EqualFold(strings.TrimSpace(g.config.SPIFFEMode), "dev") {
		// Preserve direct-dispatch dev tests that call handler functions without
		// going through the full middleware chain.
		principal = strings.TrimSpace(r.Header.Get("X-SPIFFE-ID"))
	}
	return principal
}

func (g *Gateway) demoBypassEnabled() bool {
	if g == nil || g.config == nil {
		return false
	}
	return g.config.DemoRugpullAdminEnabled && strings.EqualFold(strings.TrimSpace(g.config.SPIFFEMode), "dev")
}

// enforceOPABypassCompensatingChecks enforces explicit route-level controls for
// every OPA-bypassed route class.
func (g *Gateway) enforceOPABypassCompensatingChecks(w http.ResponseWriter, r *http.Request) (bool, string) {
	contract, ok := middleware.MatchOPABypassContract(r)
	if !ok {
		return true, ""
	}

	principal := g.requestPrincipal(r)
	for _, check := range contract.RequiredChecks {
		switch strings.TrimSpace(check) {
		case middleware.BypassCheckSPIFFEIdentity:
			if principal == "" {
				writeV24GatewayError(
					w,
					r,
					http.StatusUnauthorized,
					middleware.ErrAuthMissingIdentity,
					"bypass route requires SPIFFE identity",
					v24MiddlewareBypassContract,
					ReasonContractInvalid,
					map[string]any{
						"contract_id": contract.ID,
						"path":        r.URL.Path,
					},
				)
				return false, contract.ID
			}
			if !strings.HasPrefix(principal, "spiffe://") {
				writeV24GatewayError(
					w,
					r,
					http.StatusUnauthorized,
					middleware.ErrAuthInvalidIdentity,
					"bypass route requires valid SPIFFE identity",
					v24MiddlewareBypassContract,
					ReasonContractInvalid,
					map[string]any{
						"contract_id": contract.ID,
						"path":        r.URL.Path,
						"spiffe_id":   principal,
					},
				)
				return false, contract.ID
			}
		case middleware.BypassCheckAdminAllowlist:
			if !g.isAdminPrincipalAuthorized(principal) {
				writeV24GatewayError(
					w,
					r,
					http.StatusForbidden,
					middleware.ErrAuthzPolicyDenied,
					"bypass route admin authorization denied",
					v24MiddlewareBypassContract,
					ReasonContractInvalid,
					map[string]any{
						"contract_id": contract.ID,
						"path":        r.URL.Path,
						"spiffe_id":   principal,
					},
				)
				return false, contract.ID
			}
		case middleware.BypassCheckDemoModeGate:
			if !g.demoBypassEnabled() {
				http.NotFound(w, r)
				return false, contract.ID
			}
		default:
			writeV24GatewayError(
				w,
				r,
				http.StatusInternalServerError,
				middleware.ErrContractValidationFailed,
				"unsupported bypass compensating check",
				v24MiddlewareBypassContract,
				ReasonContractInvalid,
				map[string]any{
					"contract_id": contract.ID,
					"check_id":    check,
				},
			)
			return false, contract.ID
		}
	}

	return true, contract.ID
}

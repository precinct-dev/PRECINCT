package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// principalHeaderNames is the set of gateway-computed principal metadata headers.
// These are stripped from inbound requests (anti-forgery) and injected by the
// gateway after SPIFFE identity resolution.
var principalHeaderNames = []string{
	"X-Precinct-Principal-Level",
	"X-Precinct-Principal-Role",
	"X-Precinct-Principal-Capabilities",
	"X-Precinct-Auth-Method",
}

// PrincipalHeaders middleware strips client-provided principal headers
// (anti-forgery), resolves the PrincipalRole from the SPIFFE identity
// established by the upstream SPIFFE auth middleware, injects structured
// authority headers into the proxied request, and stores the PrincipalRole
// in the request context for downstream middleware (e.g., audit).
//
// This middleware MUST run immediately after SPIFFEAuth (step 3) so that the
// SPIFFE ID is available in the context.
//
// Parameters:
//   - trustDomain: the expected SPIFFE trust domain (e.g., "poc.local")
//   - spiffeMode: "dev" or "prod", used to determine the auth method
func PrincipalHeaders(next http.Handler, trustDomain string, spiffeMode string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tracer.Start(r.Context(), "gateway.principal_headers",
			trace.WithAttributes(
				attribute.String("mcp.gateway.middleware", "principal_headers"),
			),
		)
		defer span.End()

		// Step 1: Strip any client-provided principal headers (anti-forgery).
		// These headers are gateway-internal and must never be trusted from
		// external sources.
		for _, h := range principalHeaderNames {
			r.Header.Del(h)
		}

		// Step 2: Determine auth method from context when present (for
		// non-SPIFFE auth sources such as token exchange), falling back to
		// legacy SPIFFE mode derivation to preserve existing behavior.
		authMethod := GetAuthMethod(ctx)
		if authMethod == "" {
			authMethod = "header_declared"
			if spiffeMode == "prod" {
				authMethod = "mtls_svid"
			}
		}

		// Step 3: Resolve principal role from SPIFFE ID in context.
		spiffeID := GetSPIFFEID(ctx)
		role := ResolvePrincipalRole(spiffeID, trustDomain, authMethod)

		// Step 4: Inject gateway-computed principal headers.
		r.Header.Set("X-Precinct-Principal-Level", strconv.Itoa(role.Level))
		r.Header.Set("X-Precinct-Principal-Role", role.Role)
		r.Header.Set("X-Precinct-Principal-Capabilities", strings.Join(role.Capabilities, ","))
		r.Header.Set("X-Precinct-Auth-Method", role.AuthMethod)

		// Step 5: Store PrincipalRole in context for downstream middleware.
		ctx = WithPrincipalRole(ctx, role)

		// Record resolved role on the OTel span.
		span.SetAttributes(
			attribute.Int("mcp.principal.level", role.Level),
			attribute.String("mcp.principal.role", role.Role),
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

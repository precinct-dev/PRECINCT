package middleware

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type SPIFFEAuthOption func(*spiffeAuthConfig)

type spiffeAuthConfig struct {
	oauthJWT    *OAuthJWTConfig
	trustDomain string
}

func WithOAuthJWTConfig(cfg *OAuthJWTConfig, trustDomain string) SPIFFEAuthOption {
	return func(runtime *spiffeAuthConfig) {
		runtime.oauthJWT = cfg
		runtime.trustDomain = trustDomain
	}
}

// SPIFFEAuth validates SPIFFE identity.
// In dev mode: reads from X-SPIFFE-ID header (Phase 1 behavior).
// In prod mode: extracts SPIFFE ID from the client's mTLS certificate URI SAN.
//
// RFA-8z8.1: prod mode now reads the SPIFFE ID from the verified TLS client
// certificate presented during the mTLS handshake. The TLS stack (configured
// by SPIFFETLSConfig) already validated the cert against the SPIRE trust bundle;
// this middleware extracts the identity for downstream authorization.
func SPIFFEAuth(next http.Handler, mode string, opts ...SPIFFEAuthOption) http.Handler {
	runtime := spiffeAuthConfig{}
	for _, opt := range opts {
		opt(&runtime)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.1: Create OTel span for step 3
		ctx, span := tracer.Start(r.Context(), "gateway.spiffe_auth",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 3),
				attribute.String("mcp.gateway.middleware", "spiffe_auth"),
			),
		)
		defer span.End()

		spiffeID, bearerUsed, bearerErr := resolveOAuthBearerIdentity(ctx, r, &runtime)
		if bearerErr != nil {
			WriteGatewayError(w, r.WithContext(ctx), http.StatusUnauthorized, GatewayError{
				Code:           ErrAuthInvalidBearerToken,
				Message:        "Invalid OAuth bearer token",
				Middleware:     "spiffe_auth",
				MiddlewareStep: 3,
				Remediation:    "Present a valid bearer token issued by the configured OAuth authorization server.",
			})
			return
		}
		ctx = r.Context()

		if mode == "dev" {
			// Dev mode: read from header (Phase 1 behavior preserved)
			if spiffeID == "" {
				spiffeID = r.Header.Get("X-SPIFFE-ID")
			}
			if spiffeID == "" {
				WriteGatewayError(w, r.WithContext(ctx), http.StatusUnauthorized, GatewayError{
					Code:           ErrAuthMissingIdentity,
					Message:        "Missing X-SPIFFE-ID header",
					Middleware:     "spiffe_auth",
					MiddlewareStep: 3,
					Remediation:    "Include a valid X-SPIFFE-ID header in the request.",
				})
				return
			}

			// Basic validation: must start with spiffe://
			if !strings.HasPrefix(spiffeID, "spiffe://") {
				WriteGatewayError(w, r.WithContext(ctx), http.StatusUnauthorized, GatewayError{
					Code:           ErrAuthInvalidIdentity,
					Message:        "Invalid SPIFFE ID format",
					Middleware:     "spiffe_auth",
					MiddlewareStep: 3,
					Remediation:    "SPIFFE ID must start with spiffe:// scheme.",
				})
				return
			}

			if GetAuthMethod(ctx) == "" {
				ctx = WithAuthMethod(ctx, "header_declared")
			}
		} else {
			// Prod mode: extract SPIFFE ID from verified mTLS client certificate.
			// The TLS handshake already validated the cert chain against SPIRE's
			// trust bundle (via go-spiffe tlsconfig). We extract the SPIFFE ID
			// from the URI SAN (Subject Alternative Name) of the peer certificate.
			if spiffeID == "" {
				spiffeID = ExtractSPIFFEIDFromTLS(r)
			}
			if spiffeID == "" {
				message := "No valid SPIFFE ID in client certificate"
				remediation := "Present a valid client certificate with a spiffe:// URI SAN."
				if strings.TrimSpace(r.Header.Get("X-SPIFFE-ID")) != "" {
					message = "No valid SPIFFE ID in client certificate (X-SPIFFE-ID header is ignored in prod mode)"
					remediation = "SPIFFE_MODE=prod does not trust X-SPIFFE-ID headers. Present a valid client certificate with a spiffe:// URI SAN."
				}
				WriteGatewayError(w, r.WithContext(ctx), http.StatusUnauthorized, GatewayError{
					Code:           ErrAuthMissingIdentity,
					Message:        message,
					Middleware:     "spiffe_auth",
					MiddlewareStep: 3,
					Remediation:    remediation,
				})
				return
			}

			if GetAuthMethod(ctx) == "" {
				ctx = WithAuthMethod(ctx, "mtls_svid")
			}
		}

		// Record the SPIFFE ID as a span attribute
		span.SetAttributes(attribute.String("mcp.spiffe_id", spiffeID))

		// Add SPIFFE ID to context
		ctx = WithSPIFFEID(ctx, spiffeID)
		if bearerUsed {
			r.Header.Del("Authorization")
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func resolveOAuthBearerIdentity(ctx context.Context, r *http.Request, runtime *spiffeAuthConfig) (string, bool, error) {
	if runtime == nil || runtime.oauthJWT == nil {
		return "", false, nil
	}

	bearerToken, ok := extractBearerToken(r.Header.Get("Authorization"))
	if !ok {
		return "", false, nil
	}

	// SPIKE reference tokens are handled downstream (TokenSubstitution at
	// step 13 or model proxy SPIKE resolution), not by OAuth JWT validation.
	// Skip them here so the token reaches the correct handler intact.
	// Formats: $SPIKE{ref:...,exp:...} and spike:ref:<name>
	if len(FindSPIKETokens(bearerToken)) > 0 || strings.HasPrefix(bearerToken, "spike:ref:") {
		return "", false, nil
	}

	claims, err := ValidateOAuthJWT(ctx, bearerToken, *runtime.oauthJWT)
	if err != nil {
		// Distinguish "not a JWT at all" from "JWT but invalid".
		// Only fall back to introspection when the token structurally
		// cannot be parsed as a JWT (opaque token). If it IS a JWT but
		// fails validation (wrong issuer, expired, bad signature), fail
		// immediately without trying introspection.
		introCfg := runtime.oauthJWT.IntrospectionConfig()
		if isNotJWTError(err) && introCfg != nil && introCfg.IsConfigured() {
			introClaims, introErr := IntrospectToken(ctx, bearerToken, *introCfg)
			if introErr != nil {
				return "", true, introErr
			}
			ctxWithClaims := WithAuthMethod(ctx, "oauth_introspection")
			ctxWithClaims = WithOAuthIssuer(ctxWithClaims, introClaims.Issuer)
			ctxWithClaims = WithOAuthScopes(ctxWithClaims, introClaims.Scopes)
			*r = *r.WithContext(ctxWithClaims)
			return mapOAuthSubjectToSPIFFEID(runtime.trustDomain, introClaims.Subject), true, nil
		}
		return "", true, err
	}

	ctxWithClaims := WithAuthMethod(ctx, "oauth_jwt")
	ctxWithClaims = WithOAuthIssuer(ctxWithClaims, claims.Issuer)
	ctxWithClaims = WithOAuthScopes(ctxWithClaims, claims.Scopes)
	*r = *r.WithContext(ctxWithClaims)

	return mapOAuthSubjectToSPIFFEID(runtime.trustDomain, claims.Subject), true, nil
}

func extractBearerToken(headerValue string) (string, bool) {
	trimmed := strings.TrimSpace(headerValue)
	if !strings.HasPrefix(trimmed, "Bearer ") {
		return "", false
	}

	token := strings.TrimSpace(strings.TrimPrefix(trimmed, "Bearer "))
	if token == "" {
		return "", false
	}
	return token, true
}

func mapOAuthSubjectToSPIFFEID(trustDomain, subject string) string {
	subject = strings.Trim(strings.TrimSpace(subject), "/")
	if subject == "" {
		subject = "anonymous"
	}
	return "spiffe://" + trustDomain + "/external/" + url.PathEscape(subject)
}

// ExtractSPIFFEIDFromTLS extracts the SPIFFE ID from the verified TLS client
// certificate's URI SAN. Returns empty string if no valid SPIFFE ID is found.
//
// SPIFFE IDs are encoded as URI SANs in X.509 certificates per the SPIFFE
// specification (https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md).
// A valid SPIFFE ID has the form: spiffe://<trust-domain>/<workload-path>
func ExtractSPIFFEIDFromTLS(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}

	// The first peer certificate is the client's leaf certificate.
	// Search its URI SANs for a spiffe:// URI.
	cert := r.TLS.PeerCertificates[0]
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			return uri.String()
		}
	}

	return ""
}

// ParseSPIFFEIDFromURI parses a SPIFFE ID string into a *url.URL.
// Returns nil if the string is not a valid spiffe:// URI.
func ParseSPIFFEIDFromURI(raw string) *url.URL {
	if !strings.HasPrefix(raw, "spiffe://") {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	if u.Scheme != "spiffe" {
		return nil
	}
	return u
}

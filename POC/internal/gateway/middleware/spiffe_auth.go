package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// SPIFFEAuth validates SPIFFE identity.
// In dev mode: reads from X-SPIFFE-ID header (Phase 1 behavior).
// In prod mode: extracts SPIFFE ID from the client's mTLS certificate URI SAN.
//
// RFA-8z8.1: prod mode now reads the SPIFFE ID from the verified TLS client
// certificate presented during the mTLS handshake. The TLS stack (configured
// by SPIFFETLSConfig) already validated the cert against the SPIRE trust bundle;
// this middleware extracts the identity for downstream authorization.
func SPIFFEAuth(next http.Handler, mode string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.1: Create OTel span for step 3
		ctx, span := tracer.Start(r.Context(), "gateway.spiffe_auth",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 3),
				attribute.String("mcp.gateway.middleware", "spiffe_auth"),
			),
		)
		defer span.End()

		var spiffeID string

		if mode == "dev" {
			// Dev mode: read from header (Phase 1 behavior preserved)
			spiffeID = r.Header.Get("X-SPIFFE-ID")
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
		} else {
			// Prod mode: extract SPIFFE ID from verified mTLS client certificate.
			// The TLS handshake already validated the cert chain against SPIRE's
			// trust bundle (via go-spiffe tlsconfig). We extract the SPIFFE ID
			// from the URI SAN (Subject Alternative Name) of the peer certificate.
			spiffeID = ExtractSPIFFEIDFromTLS(r)
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
		}

		// Record the SPIFFE ID as a span attribute
		span.SetAttributes(attribute.String("mcp.spiffe_id", spiffeID))

		// Add SPIFFE ID to context
		ctx = WithSPIFFEID(ctx, spiffeID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
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

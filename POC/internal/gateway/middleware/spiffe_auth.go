package middleware

import (
	"net/http"
	"strings"
)

// SPIFFEAuth validates SPIFFE identity
// In dev mode: reads from X-SPIFFE-ID header (placeholder)
// In prod mode: would extract from mTLS cert (not implemented in skeleton)
func SPIFFEAuth(next http.Handler, mode string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var spiffeID string

		if mode == "dev" {
			// Dev mode: read from header
			spiffeID = r.Header.Get("X-SPIFFE-ID")
			if spiffeID == "" {
				http.Error(w, "Missing X-SPIFFE-ID header", http.StatusUnauthorized)
				return
			}

			// Basic validation: must start with spiffe://
			if !strings.HasPrefix(spiffeID, "spiffe://") {
				http.Error(w, "Invalid SPIFFE ID format", http.StatusUnauthorized)
				return
			}
		} else {
			// Prod mode: would extract from mTLS cert
			// For skeleton, this is a no-op pass-through
			spiffeID = "spiffe://poc.local/unknown/prod"
		}

		// Add SPIFFE ID to context
		ctx := WithSPIFFEID(r.Context(), spiffeID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

package middleware

import (
	"context"
	"net/http"
	"strings"
)

const (
	runtimeProfileProdStandard       = "prod_standard"
	runtimeProfileProdRegulatedHIPAA = "prod_regulated_hipaa"
)

// RuntimeProfile injects runtime mode/profile metadata into request context.
func RuntimeProfile(next http.Handler, spiffeMode, enforcementProfile string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithRuntimeProfile(r.Context(), spiffeMode, enforcementProfile)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// IsStrictRuntimeProfile returns true for prod/strict runtime requests.
func IsStrictRuntimeProfile(ctx context.Context) bool {
	mode := strings.ToLower(strings.TrimSpace(GetRuntimeSPIFFEMode(ctx)))
	if mode == "prod" {
		return true
	}
	profile := strings.ToLower(strings.TrimSpace(GetRuntimeEnforcementProfile(ctx)))
	return profile == runtimeProfileProdStandard || profile == runtimeProfileProdRegulatedHIPAA
}

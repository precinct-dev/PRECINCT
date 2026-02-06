package middleware

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// TokenSubstitution is the middleware that substitutes SPIKE tokens with actual secrets.
// The redeemer parameter controls how tokens are resolved to secret values:
// - SPIKENexusRedeemer: calls SPIKE Nexus via mTLS (production)
// - POCSecretRedeemer: returns deterministic mock secrets (dev/test)
func TokenSubstitution(next http.Handler, redeemer SecretRedeemer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.2: Create OTel span for step 13
		ctx, span := tracer.Start(r.Context(), "gateway.token_substitution",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 13),
				attribute.String("mcp.gateway.middleware", "token_substitution"),
			),
		)
		defer span.End()

		// Get SPIFFE ID from context
		spiffeID := GetSPIFFEID(ctx)
		if spiffeID == "" {
			http.Error(w, "Missing SPIFFE ID for token substitution", http.StatusUnauthorized)
			return
		}

		// Get request body from context (already captured by BodyCapture middleware)
		bodyBytes := GetRequestBody(ctx)
		if bodyBytes == nil {
			// No body, nothing to substitute
			span.SetAttributes(
				attribute.Int("tokens_substituted", 0),
				attribute.Int("spike_ref_count", 0),
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "no body"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		bodyStr := string(bodyBytes)

		// Find all SPIKE tokens in the body
		tokenStrings := FindSPIKETokens(bodyStr)
		if len(tokenStrings) == 0 {
			// No tokens found, proceed without substitution
			span.SetAttributes(
				attribute.Int("tokens_substituted", 0),
				attribute.Int("spike_ref_count", 0),
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "no tokens found"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		span.SetAttributes(attribute.Int("spike_ref_count", len(tokenStrings)))

		// Process each token
		tokenMap := make(map[string]string)

		for _, tokenStr := range tokenStrings {
			// Parse token
			token, err := ParseSPIKEToken(tokenStr)
			if err != nil {
				// Log to stdout for POC (audit logging happens at higher middleware layer)
				fmt.Printf("Token substitution failed: ref=%s, spiffe=%s, error=%v\n", tokenStr, spiffeID, err)
				span.SetAttributes(
					attribute.Int("tokens_substituted", len(tokenMap)),
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "invalid SPIKE token"),
				)
				http.Error(w, fmt.Sprintf("Invalid SPIKE token: %v", err), http.StatusBadRequest)
				return
			}

			// Validate token ownership
			if err := ValidateTokenOwnership(token, spiffeID); err != nil {
				fmt.Printf("Token ownership validation failed: ref=%s, spiffe=%s, error=%v\n", token.Ref, spiffeID, err)
				span.SetAttributes(
					attribute.Int("tokens_substituted", len(tokenMap)),
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "token ownership failed"),
				)
				http.Error(w, fmt.Sprintf("Token ownership validation failed: %v", err), http.StatusForbidden)
				return
			}

			// Validate token expiry
			if err := ValidateTokenExpiry(token); err != nil {
				fmt.Printf("Token expired: ref=%s, spiffe=%s, error=%v\n", token.Ref, spiffeID, err)
				span.SetAttributes(
					attribute.Int("tokens_substituted", len(tokenMap)),
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "token expired"),
				)
				http.Error(w, fmt.Sprintf("Token expired: %v", err), http.StatusUnauthorized)
				return
			}

			// Validate token scope (for POC, we use a default scope)
			// In production, scope would come from the request context or tool registry
			if err := ValidateTokenScope(token, "tools", "docker", "read"); err != nil {
				fmt.Printf("Token scope validation failed: ref=%s, spiffe=%s, error=%v\n", token.Ref, spiffeID, err)
				span.SetAttributes(
					attribute.Int("tokens_substituted", len(tokenMap)),
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "token scope failed"),
				)
				http.Error(w, fmt.Sprintf("Token scope validation failed: %v", err), http.StatusForbidden)
				return
			}

			// Redeem token for actual secret
			secret, err := redeemer.RedeemSecret(ctx, token)
			if err != nil {
				fmt.Printf("Token redemption failed: ref=%s, spiffe=%s, error=%v\n", token.Ref, spiffeID, err)
				span.SetAttributes(
					attribute.Int("tokens_substituted", len(tokenMap)),
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "token redemption failed"),
				)
				http.Error(w, fmt.Sprintf("Token redemption failed: %v", err), http.StatusInternalServerError)
				return
			}

			// Store token->secret mapping
			tokenMap[tokenStr] = secret.Value

			// Log successful substitution (without the secret value)
			fmt.Printf("Token substitution succeeded: ref=%s, spiffe=%s\n", token.Ref, spiffeID)
		}

		span.SetAttributes(
			attribute.Int("tokens_substituted", len(tokenMap)),
			attribute.String("mcp.result", "allowed"),
			attribute.String("mcp.reason", "tokens substituted"),
		)

		// Perform substitution
		substitutedBody := SubstituteTokens(bodyStr, tokenMap)

		// Update request body with substituted content
		r.Body = io.NopCloser(bytes.NewBufferString(substitutedBody))
		r.ContentLength = int64(len(substitutedBody))

		// Continue to next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// POCSecretRedeemer is a POC implementation of SecretRedeemer
// In production, this would make mTLS calls to SPIKE Nexus
type POCSecretRedeemer struct{}

// NewPOCSecretRedeemer creates a new POC secret redeemer
func NewPOCSecretRedeemer() *POCSecretRedeemer {
	return &POCSecretRedeemer{}
}

// RedeemSecret redeems a SPIKE token for the actual secret value
// POC implementation: returns a mock secret
// Production: would make mTLS call to SPIKE Nexus at https://spike-nexus:8443/api/v1/redeem
func (p *POCSecretRedeemer) RedeemSecret(ctx context.Context, token *SPIKEToken) (*SPIKESecret, error) {
	// For POC, return a deterministic mock secret based on token ref
	// In production, this would:
	// 1. Make mTLS connection to SPIKE Nexus
	// 2. POST to /api/v1/redeem with token ref
	// 3. Verify mTLS certificate chain
	// 4. Parse response and return secret

	// Set IssuedAt if not already set (for validation)
	if token.IssuedAt == 0 {
		token.IssuedAt = time.Now().Unix()
	}

	// Return mock secret
	secret := &SPIKESecret{
		Value:     fmt.Sprintf("secret-value-for-%s", token.Ref),
		ExpiresAt: time.Now().Unix() + 3600,
	}

	return secret, nil
}

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

// logTokenEvent emits a structured audit event for token substitution.
// If auditor is nil, the call is a no-op (safe for tests that don't
// need audit infrastructure).
func logTokenEvent(auditor *Auditor, ctx context.Context, r *http.Request, action, result string) {
	if auditor == nil {
		return
	}
	auditor.Log(AuditEvent{
		SessionID:  GetSessionID(ctx),
		DecisionID: GetDecisionID(ctx),
		TraceID:    GetTraceID(ctx),
		SPIFFEID:   GetSPIFFEID(ctx),
		Action:     action,
		Result:     result,
		Method:     r.Method,
		Path:       r.URL.Path,
	})
}

// TokenSubstitution is the middleware that substitutes SPIKE tokens with actual secrets.
// The redeemer parameter controls how tokens are resolved to secret values:
// - SPIKENexusRedeemer: calls SPIKE Nexus via mTLS (production)
// - POCSecretRedeemer: returns deterministic mock secrets (dev/test)
// The auditor parameter enables structured audit logging; pass nil to disable
// (safe for unit tests that don't need audit infrastructure).
func TokenSubstitution(next http.Handler, redeemer SecretRedeemer, auditor *Auditor) http.Handler {
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
			WriteGatewayError(w, r.WithContext(ctx), http.StatusUnauthorized, GatewayError{
				Code:           ErrAuthMissingIdentity,
				Message:        "Missing SPIFFE ID for token substitution",
				Middleware:     "token_substitution",
				MiddlewareStep: 13,
			})
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
				logTokenEvent(auditor, ctx, r, "token_substitution",
					fmt.Sprintf("parse_failed ref=%s spiffe=%s error=%v", tokenStr, spiffeID, err))
				span.SetAttributes(
					attribute.Int("tokens_substituted", len(tokenMap)),
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "invalid SPIKE token"),
				)
				WriteGatewayError(w, r.WithContext(ctx), http.StatusBadRequest, GatewayError{
					Code:           "invalid_spike_token",
					Message:        fmt.Sprintf("Invalid SPIKE token: %v", err),
					Middleware:     "token_substitution",
					MiddlewareStep: 13,
				})
				return
			}

			// Validate token expiry
			if err := ValidateTokenExpiry(token); err != nil {
				logTokenEvent(auditor, ctx, r, "token_substitution",
					fmt.Sprintf("token_expired ref=%s spiffe=%s error=%v", token.Ref, spiffeID, err))
				span.SetAttributes(
					attribute.Int("tokens_substituted", len(tokenMap)),
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "token expired"),
				)
				WriteGatewayError(w, r.WithContext(ctx), http.StatusUnauthorized, GatewayError{
					Code:           "token_expired",
					Message:        fmt.Sprintf("Token expired: %v", err),
					Middleware:     "token_substitution",
					MiddlewareStep: 13,
				})
				return
			}

			// Validate token scope (for POC, we use a default scope)
			// In production, scope would come from the request context or tool registry
			if err := ValidateTokenScope(token, "tools", "docker", "read"); err != nil {
				logTokenEvent(auditor, ctx, r, "token_substitution",
					fmt.Sprintf("scope_failed ref=%s spiffe=%s error=%v", token.Ref, spiffeID, err))
				span.SetAttributes(
					attribute.Int("tokens_substituted", len(tokenMap)),
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "token scope failed"),
				)
				WriteGatewayError(w, r.WithContext(ctx), http.StatusForbidden, GatewayError{
					Code:           "token_scope_failed",
					Message:        fmt.Sprintf("Token scope validation failed: %v", err),
					Middleware:     "token_substitution",
					MiddlewareStep: 13,
				})
				return
			}

			// Redeem token for actual secret.
			// The redeemer populates token.OwnerID from SPIKE Nexus metadata
			// (or from POC simulation). This must happen BEFORE ownership
			// validation so the gateway can verify the caller matches the
			// server-assigned owner. See RFA-7ct.
			secret, err := redeemer.RedeemSecret(ctx, token)
			if err != nil {
				logTokenEvent(auditor, ctx, r, "token_substitution",
					fmt.Sprintf("redemption_failed ref=%s spiffe=%s error=%v", token.Ref, spiffeID, err))
				span.SetAttributes(
					attribute.Int("tokens_substituted", len(tokenMap)),
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "token redemption failed"),
				)
				WriteGatewayError(w, r.WithContext(ctx), http.StatusInternalServerError, GatewayError{
					Code:           "token_redemption_failed",
					Message:        fmt.Sprintf("Token redemption failed: %v", err),
					Middleware:     "token_substitution",
					MiddlewareStep: 13,
				})
				return
			}

			// Validate token ownership (defense-in-depth).
			// After redemption, token.OwnerID is populated by the redeemer.
			// Reject if OwnerID is empty (SPIKE Nexus must pre-set it) or
			// if it doesn't match the requesting agent's SPIFFE ID. See RFA-7ct.
			if err := ValidateTokenOwnership(token, spiffeID); err != nil {
				logTokenEvent(auditor, ctx, r, "token_substitution",
					fmt.Sprintf("ownership_failed ref=%s spiffe=%s error=%v", token.Ref, spiffeID, err))
				span.SetAttributes(
					attribute.Int("tokens_substituted", len(tokenMap)),
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "token ownership failed"),
				)
				WriteGatewayError(w, r.WithContext(ctx), http.StatusForbidden, GatewayError{
					Code:           "token_ownership_failed",
					Message:        fmt.Sprintf("Token ownership validation failed: %v", err),
					Middleware:     "token_substitution",
					MiddlewareStep: 13,
				})
				return
			}

			// Store token->secret mapping
			tokenMap[tokenStr] = secret.Value

			// Log successful substitution (without the secret value)
			logTokenEvent(auditor, ctx, r, "token_substitution",
				fmt.Sprintf("substituted ref=%s spiffe=%s", token.Ref, spiffeID))
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

// POCSecretRedeemer is a POC implementation of SecretRedeemer.
// In production, this would make mTLS calls to SPIKE Nexus.
// The POC redeemer simulates Nexus behavior by setting OwnerID
// on the token from a configured owner SPIFFE ID (see RFA-7ct).
type POCSecretRedeemer struct {
	// ownerSPIFFEID is the SPIFFE ID that owns all tokens in POC mode.
	// Simulates SPIKE Nexus returning the owner metadata at redemption.
	// If empty, OwnerID is NOT set (reproducing the pre-RFA-7ct bug for testing).
	ownerSPIFFEID string
}

// NewPOCSecretRedeemer creates a new POC secret redeemer that simulates
// SPIKE Nexus returning owner metadata. The ownerSPIFFEID is set on
// every redeemed token, matching production behavior where Nexus
// populates OwnerID from its token issuance records.
func NewPOCSecretRedeemer() *POCSecretRedeemer {
	return &POCSecretRedeemer{}
}

// NewPOCSecretRedeemerWithOwner creates a POC redeemer with a configured
// owner SPIFFE ID. This simulates SPIKE Nexus behavior where every
// token has a pre-assigned owner from issuance time.
func NewPOCSecretRedeemerWithOwner(ownerSPIFFEID string) *POCSecretRedeemer {
	return &POCSecretRedeemer{ownerSPIFFEID: ownerSPIFFEID}
}

// RedeemSecret redeems a SPIKE token for the actual secret value.
// POC implementation: returns a mock secret and populates OwnerID.
// Production: would make mTLS call to SPIKE Nexus at https://spike-nexus:8443/api/v1/redeem
func (p *POCSecretRedeemer) RedeemSecret(ctx context.Context, token *SPIKEToken) (*SPIKESecret, error) {
	// For POC, return a deterministic mock secret based on token ref
	// In production, this would:
	// 1. Make mTLS connection to SPIKE Nexus
	// 2. POST to /api/v1/redeem with token ref
	// 3. Verify mTLS certificate chain
	// 4. Parse response and return secret + owner metadata

	// Set IssuedAt if not already set (for validation)
	if token.IssuedAt == 0 {
		token.IssuedAt = time.Now().Unix()
	}

	// Populate OwnerID from configured owner, simulating SPIKE Nexus
	// returning the owner SPIFFE ID as part of token metadata (RFA-7ct).
	if p.ownerSPIFFEID != "" {
		token.OwnerID = p.ownerSPIFFEID
	}

	// Return mock secret
	secret := &SPIKESecret{
		Value:     fmt.Sprintf("secret-value-for-%s", token.Ref),
		ExpiresAt: time.Now().Unix() + 3600,
	}

	return secret, nil
}

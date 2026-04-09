// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SPIKEToken represents a parsed SPIKE token
type SPIKEToken struct {
	Ref      string // Hex reference to the secret
	Exp      int64  // Expiry in seconds (relative to IssuedAt)
	Scope    string // Scope (location.operation.destination format)
	OwnerID  string // SPIFFE ID of the token owner (populated during validation)
	IssuedAt int64  // Unix timestamp when token was issued (populated during validation)
}

// SPIKESecret represents the redeemed secret value
type SPIKESecret struct {
	Value     string // The actual secret value
	ExpiresAt int64  // Unix timestamp when secret expires
}

// TokenSubstitutionEvent represents an audit event for token substitution
type TokenSubstitutionEvent struct {
	TokenRef    string // Token reference (hex)
	SpiffeID    string // Requesting agent's SPIFFE ID
	Scope       string // Token scope
	Destination string // Destination service
	Success     bool   // Whether substitution succeeded
	Timestamp   int64  // Unix timestamp
	SecretValue string // NEVER populated - secrets must not be logged
}

// SecretRedeemer is the interface for redeeming SPIKE tokens into actual secrets
type SecretRedeemer interface {
	RedeemSecret(ctx context.Context, token *SPIKEToken) (*SPIKESecret, error)
}

var (
	// Token format: $SPIKE{ref:<hex>,exp:<seconds>,scope:<scope>}
	// Token regex: \$SPIKE\{ref:([a-f0-9]+)(?:,exp:(\d+))?(?:,scope:(\w+))?\}
	tokenRegex = regexp.MustCompile(`\$SPIKE\{ref:([a-f0-9]+)(?:,exp:(\d+))?(?:,scope:([\w.]+))?\}`)

	// ErrInvalidToken indicates the token format is invalid
	ErrInvalidToken = errors.New("invalid SPIKE token format")
	// ErrOwnershipMismatch indicates the token owner does not match the requesting agent
	ErrOwnershipMismatch = errors.New("token ownership validation failed")
	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token has expired")
	// ErrScopeMismatch indicates the token scope does not match the request
	ErrScopeMismatch = errors.New("token scope validation failed")
	// ErrMissingSPIFFEID indicates the SPIFFE ID is missing from context
	ErrMissingSPIFFEID = errors.New("missing SPIFFE ID in context")
	// ErrEmptyOwnerID indicates the token has no OwnerID set (must be pre-populated by SPIKE Nexus)
	ErrEmptyOwnerID = errors.New("token has empty OwnerID: SPIKE Nexus must pre-populate OwnerID at issuance")
)

// ParseSPIKEToken parses a SPIKE token string into a SPIKEToken struct
func ParseSPIKEToken(tokenStr string) (*SPIKEToken, error) {
	matches := tokenRegex.FindStringSubmatch(tokenStr)
	if matches == nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidToken, tokenStr)
	}

	token := &SPIKEToken{
		Ref: matches[1],
	}

	// Parse expiry if present
	if matches[2] != "" {
		exp, err := strconv.ParseInt(matches[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid expiry value", ErrInvalidToken)
		}
		token.Exp = exp
	}

	// Parse scope if present
	if matches[3] != "" {
		token.Scope = matches[3]
	}

	return token, nil
}

// FindSPIKETokens finds all SPIKE tokens in a string
func FindSPIKETokens(input string) []string {
	matches := tokenRegex.FindAllString(input, -1)
	return matches
}

// ValidateTokenOwnership validates that the token owner matches the requesting agent
func ValidateTokenOwnership(token *SPIKEToken, spiffeID string) error {
	if spiffeID == "" {
		return ErrMissingSPIFFEID
	}

	// OwnerID must be pre-populated by SPIKE Nexus at token issuance time.
	// Reject tokens with empty OwnerID to prevent unauthorized token claiming
	// in multi-agent scenarios (see RFA-7ct).
	if token.OwnerID == "" {
		return ErrEmptyOwnerID
	}

	if token.OwnerID != spiffeID {
		return fmt.Errorf("%w: token owner %s does not match requesting agent %s",
			ErrOwnershipMismatch, token.OwnerID, spiffeID)
	}

	return nil
}

// ValidateTokenExpiry validates that the token has not expired
func ValidateTokenExpiry(token *SPIKEToken) error {
	// If no expiry is set, token never expires
	if token.Exp == 0 {
		return nil
	}

	// Fail closed: tokens with a relative expiry MUST have IssuedAt set
	// (populated by the SecretRedeemer during redemption). A zero IssuedAt
	// with non-zero Exp would make the token effectively immortal.
	if token.IssuedAt == 0 {
		return fmt.Errorf("%w: token has expiry (%d) but no IssuedAt timestamp", ErrTokenExpired, token.Exp)
	}

	expiryTime := token.IssuedAt + token.Exp
	currentTime := time.Now().Unix()

	if currentTime > expiryTime {
		return fmt.Errorf("%w: token expired at %d, current time %d",
			ErrTokenExpired, expiryTime, currentTime)
	}

	return nil
}

// ValidateTokenScope validates that the token scope matches the request context
// Scope format: location.operation.destination (e.g., "tools.docker.read")
func ValidateTokenScope(token *SPIKEToken, location, operation, destination string) error {
	// If no scope is set, allow any usage (for POC flexibility)
	if token.Scope == "" {
		return nil
	}

	expectedScope := fmt.Sprintf("%s.%s.%s", location, operation, destination)
	if token.Scope != expectedScope {
		return fmt.Errorf("%w: expected scope %s, got %s",
			ErrScopeMismatch, expectedScope, token.Scope)
	}

	return nil
}

// SubstituteTokens replaces SPIKE tokens in a string with their actual secret values
func SubstituteTokens(input string, tokenMap map[string]string) string {
	result := input
	for token, secret := range tokenMap {
		result = strings.ReplaceAll(result, token, secret)
	}
	return result
}

package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// OAuthIntrospectionConfig holds the optional RFC 7662 introspection settings.
// When configured, opaque (non-JWT) bearer tokens are validated by calling
// the authorization server's introspection endpoint.
type OAuthIntrospectionConfig struct {
	IntrospectionURL          string `yaml:"introspection_url"`
	IntrospectionClientIDEnv  string `yaml:"introspection_client_id_env"`
	IntrospectionClientSecEnv string `yaml:"introspection_client_secret_env"`
	RequiredAudience          string `yaml:"introspection_required_audience"`

	// HTTPClient is used for introspection requests. If nil, a default client
	// with a 5-second timeout is created on first use.
	HTTPClient *http.Client `yaml:"-"`
	// Now is an injectable clock for testing.
	Now func() time.Time `yaml:"-"`
}

// OAuthIntrospectionClaims represents the validated claims extracted from
// an introspection response.
type OAuthIntrospectionClaims struct {
	Subject   string
	Issuer    string
	Audience  string
	Scopes    []string
	ClientID  string
	ExpiresAt time.Time
}

// introspectionResponse models the JSON body returned by an RFC 7662
// introspection endpoint.
type introspectionResponse struct {
	Active    bool   `json:"active"`
	TokenType string `json:"token_type,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iss       string `json:"iss,omitempty"`
}

// IsConfigured returns true when introspection has been configured with at
// least an introspection URL.
func (c *OAuthIntrospectionConfig) IsConfigured() bool {
	return c != nil && strings.TrimSpace(c.IntrospectionURL) != ""
}

func (c *OAuthIntrospectionConfig) normalize() {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// clientCredentials resolves the client ID and client secret from the
// environment variables named by the config. Returns empty strings when
// the env vars are not set (introspection may still work if the server
// does not require client authentication).
func (c *OAuthIntrospectionConfig) clientCredentials() (clientID, clientSecret string) {
	if env := strings.TrimSpace(c.IntrospectionClientIDEnv); env != "" {
		clientID = os.Getenv(env)
	}
	if env := strings.TrimSpace(c.IntrospectionClientSecEnv); env != "" {
		clientSecret = os.Getenv(env)
	}
	return clientID, clientSecret
}

// IntrospectToken validates an opaque bearer token by calling the configured
// RFC 7662 introspection endpoint. It returns the validated claims on success
// or an error when the token is inactive, expired, or the introspection
// request fails.
func IntrospectToken(ctx context.Context, rawToken string, cfg OAuthIntrospectionConfig) (OAuthIntrospectionClaims, error) {
	cfg.normalize()

	if strings.TrimSpace(cfg.IntrospectionURL) == "" {
		return OAuthIntrospectionClaims{}, fmt.Errorf("introspection_url is required")
	}

	form := url.Values{}
	form.Set("token", rawToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.IntrospectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return OAuthIntrospectionClaims{}, fmt.Errorf("build introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Attach client credentials via HTTP Basic Auth if both are configured.
	clientID, clientSecret := cfg.clientCredentials()
	if clientID != "" && clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return OAuthIntrospectionClaims{}, fmt.Errorf("introspection request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return OAuthIntrospectionClaims{}, fmt.Errorf("introspection endpoint returned status %d", resp.StatusCode)
	}

	var ir introspectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		return OAuthIntrospectionClaims{}, fmt.Errorf("decode introspection response: %w", err)
	}

	if !ir.Active {
		return OAuthIntrospectionClaims{}, fmt.Errorf("introspection: token is not active")
	}

	// Validate required audience if configured.
	if requiredAud := strings.TrimSpace(cfg.RequiredAudience); requiredAud != "" {
		if ir.Aud != requiredAud {
			return OAuthIntrospectionClaims{}, fmt.Errorf("introspection: unexpected audience %q, want %q", ir.Aud, requiredAud)
		}
	}

	// Validate expiry.
	now := cfg.Now()
	if ir.Exp > 0 {
		expiresAt := time.Unix(ir.Exp, 0)
		if now.After(expiresAt) {
			return OAuthIntrospectionClaims{}, fmt.Errorf("introspection: token expired at %s", expiresAt.UTC().Format(time.RFC3339))
		}
	}

	// Require a subject claim.
	sub := strings.TrimSpace(ir.Sub)
	if sub == "" {
		return OAuthIntrospectionClaims{}, fmt.Errorf("introspection: sub claim is required")
	}

	scopes := normalizeOAuthScopes(ir.Scope, nil)

	return OAuthIntrospectionClaims{
		Subject:   sub,
		Issuer:    ir.Iss,
		Audience:  ir.Aud,
		Scopes:    scopes,
		ClientID:  ir.ClientID,
		ExpiresAt: time.Unix(ir.Exp, 0),
	}, nil
}

// isNotJWTError returns true when the error from ValidateOAuthJWT indicates
// the token could not be parsed as a JWT at all (as opposed to being a JWT
// that failed validation). This classification drives the introspection
// fallback: only tokens that are structurally not JWTs should be sent to
// the introspection endpoint.
func isNotJWTError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// The go-jose library returns "go-jose/go-jose: compact JWS format must
	// have three parts" (or similar) when the input is not a valid JWS at all.
	// Our own ValidateOAuthJWT wraps this as "parse signed jwt: <...>".
	return strings.Contains(msg, "parse signed jwt:")
}

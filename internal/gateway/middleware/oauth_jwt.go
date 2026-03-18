package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"gopkg.in/yaml.v3"
)

const (
	defaultOAuthClockSkew = 30 * time.Second
	defaultOAuthCacheTTL  = 5 * time.Minute
)

type OAuthJWTConfig struct {
	Issuer           string           `yaml:"issuer"`
	Audience         string           `yaml:"audience"`
	JWKSURL          string           `yaml:"jwks_url"`
	RequiredScopes   []string         `yaml:"required_scopes"`
	ClockSkewSeconds int              `yaml:"clock_skew_seconds"`
	CacheTTLSeconds  int              `yaml:"cache_ttl_seconds"`
	HTTPClient       *http.Client     `yaml:"-"`
	Now              func() time.Time `yaml:"-"`
	cache            *oauthJWKCache   `yaml:"-"`

	// Optional RFC 7662 introspection fields. When IntrospectionURL is set,
	// opaque (non-JWT) bearer tokens are validated via introspection instead
	// of being rejected outright.
	IntrospectionURL          string `yaml:"introspection_url"`
	IntrospectionClientIDEnv  string `yaml:"introspection_client_id_env"`
	IntrospectionClientSecEnv string `yaml:"introspection_client_secret_env"`
	IntrospectionRequiredAud  string `yaml:"introspection_required_audience"`
}

type OAuthJWTClaims struct {
	Subject   string
	Issuer    string
	Audience  []string
	Scopes    []string
	ExpiresAt time.Time
}

type oauthJWKCache struct {
	mu        sync.RWMutex
	set       jose.JSONWebKeySet
	expiresAt time.Time
}

type oauthJWTFile struct {
	OAuth OAuthJWTConfig `yaml:"oauth_resource_server"`
}

type oauthTokenClaims struct {
	Iss   string        `json:"iss"`
	Sub   string        `json:"sub"`
	Aud   oauthAudience `json:"aud"`
	Exp   int64         `json:"exp"`
	Nbf   int64         `json:"nbf,omitempty"`
	Iat   int64         `json:"iat,omitempty"`
	Scope string        `json:"scope,omitempty"`
	Scp   []string      `json:"scp,omitempty"`
}

type oauthAudience []string

func (a *oauthAudience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}

	var multi []string
	if err := json.Unmarshal(data, &multi); err == nil {
		*a = multi
		return nil
	}

	return fmt.Errorf("invalid aud claim")
}

func LoadOAuthJWTConfig(path string) (*OAuthJWTConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read oauth resource server config: %w", err)
	}

	wrapper := oauthJWTFile{}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse oauth resource server config: %w", err)
	}

	cfg := wrapper.OAuth
	cfg.normalize()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (cfg *OAuthJWTConfig) normalize() {
	if cfg.cache == nil {
		cfg.cache = &oauthJWKCache{}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
}

func (cfg *OAuthJWTConfig) validate() error {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return fmt.Errorf("oauth resource server issuer is required")
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		return fmt.Errorf("oauth resource server audience is required")
	}
	if strings.TrimSpace(cfg.JWKSURL) == "" {
		return fmt.Errorf("oauth resource server jwks_url is required")
	}
	return nil
}

func (cfg OAuthJWTConfig) clockSkew() time.Duration {
	if cfg.ClockSkewSeconds <= 0 {
		return defaultOAuthClockSkew
	}
	return time.Duration(cfg.ClockSkewSeconds) * time.Second
}

func (cfg OAuthJWTConfig) cacheTTL() time.Duration {
	if cfg.CacheTTLSeconds <= 0 {
		return defaultOAuthCacheTTL
	}
	return time.Duration(cfg.CacheTTLSeconds) * time.Second
}

// IntrospectionConfig returns a configured OAuthIntrospectionConfig when
// introspection is enabled (i.e., IntrospectionURL is set). Returns nil
// when introspection is not configured.
func (cfg OAuthJWTConfig) IntrospectionConfig() *OAuthIntrospectionConfig {
	if strings.TrimSpace(cfg.IntrospectionURL) == "" {
		return nil
	}
	return &OAuthIntrospectionConfig{
		IntrospectionURL:          cfg.IntrospectionURL,
		IntrospectionClientIDEnv:  cfg.IntrospectionClientIDEnv,
		IntrospectionClientSecEnv: cfg.IntrospectionClientSecEnv,
		RequiredAudience:          cfg.IntrospectionRequiredAud,
		HTTPClient:                cfg.HTTPClient,
		Now:                       cfg.Now,
	}
}

func ValidateOAuthJWT(ctx context.Context, rawToken string, cfg OAuthJWTConfig) (OAuthJWTClaims, error) {
	cfg.normalize()
	if err := cfg.validate(); err != nil {
		return OAuthJWTClaims{}, err
	}

	token, err := jwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{
		jose.HS256, jose.HS384, jose.HS512,
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA,
	})
	if err != nil {
		return OAuthJWTClaims{}, fmt.Errorf("parse signed jwt: %w", err)
	}

	jwks, err := cfg.fetchJWKS(ctx)
	if err != nil {
		return OAuthJWTClaims{}, err
	}
	if len(jwks.Keys) == 0 {
		return OAuthJWTClaims{}, fmt.Errorf("jwks contains no keys")
	}

	kid := ""
	if len(token.Headers) > 0 {
		kid = strings.TrimSpace(token.Headers[0].KeyID)
	}

	keys := jwks.Keys
	if kid != "" {
		keys = jwks.Key(kid)
		if len(keys) == 0 {
			return OAuthJWTClaims{}, fmt.Errorf("no jwk found for kid %q", kid)
		}
	}

	var claims oauthTokenClaims
	var verified bool
	for _, key := range keys {
		if err := token.Claims(key.Key, &claims); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return OAuthJWTClaims{}, fmt.Errorf("jwt signature verification failed")
	}

	now := cfg.Now()
	skew := cfg.clockSkew()
	if claims.Iss != cfg.Issuer {
		return OAuthJWTClaims{}, fmt.Errorf("unexpected issuer %q", claims.Iss)
	}
	if !slices.Contains([]string(claims.Aud), cfg.Audience) {
		return OAuthJWTClaims{}, fmt.Errorf("unexpected audience %v", []string(claims.Aud))
	}
	if claims.Exp == 0 {
		return OAuthJWTClaims{}, fmt.Errorf("exp claim is required")
	}

	expiry := time.Unix(claims.Exp, 0)
	if now.After(expiry.Add(skew)) {
		return OAuthJWTClaims{}, fmt.Errorf("token expired at %s", expiry.UTC().Format(time.RFC3339))
	}
	if claims.Nbf != 0 && now.Add(skew).Before(time.Unix(claims.Nbf, 0)) {
		return OAuthJWTClaims{}, fmt.Errorf("token not valid before %s", time.Unix(claims.Nbf, 0).UTC().Format(time.RFC3339))
	}
	if claims.Iat != 0 && now.Add(skew).Before(time.Unix(claims.Iat, 0)) {
		return OAuthJWTClaims{}, fmt.Errorf("token issued in the future")
	}

	scopes := normalizeOAuthScopes(claims.Scope, claims.Scp)
	if len(cfg.RequiredScopes) > 0 {
		for _, required := range cfg.RequiredScopes {
			if !slices.Contains(scopes, required) {
				return OAuthJWTClaims{}, fmt.Errorf("missing required scope %q", required)
			}
		}
	}
	if strings.TrimSpace(claims.Sub) == "" {
		return OAuthJWTClaims{}, fmt.Errorf("sub claim is required")
	}

	return OAuthJWTClaims{
		Subject:   claims.Sub,
		Issuer:    claims.Iss,
		Audience:  []string(claims.Aud),
		Scopes:    scopes,
		ExpiresAt: expiry,
	}, nil
}

func normalizeOAuthScopes(scope string, scp []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(scp)+1)
	for _, entry := range strings.Fields(scope) {
		if _, ok := seen[entry]; ok || entry == "" {
			continue
		}
		seen[entry] = struct{}{}
		out = append(out, entry)
	}
	for _, entry := range scp {
		entry = strings.TrimSpace(entry)
		if _, ok := seen[entry]; ok || entry == "" {
			continue
		}
		seen[entry] = struct{}{}
		out = append(out, entry)
	}
	return out
}

func (cfg OAuthJWTConfig) fetchJWKS(ctx context.Context) (jose.JSONWebKeySet, error) {
	cfg.normalize()

	cfg.cache.mu.RLock()
	if time.Now().Before(cfg.cache.expiresAt) && len(cfg.cache.set.Keys) > 0 {
		cached := cfg.cache.set
		cfg.cache.mu.RUnlock()
		return cached, nil
	}
	cfg.cache.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.JWKSURL, nil)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("build jwks request: %w", err)
	}
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}

	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("decode jwks: %w", err)
	}

	cfg.cache.mu.Lock()
	cfg.cache.set = set
	cfg.cache.expiresAt = time.Now().Add(cfg.cacheTTL())
	cfg.cache.mu.Unlock()

	return set, nil
}

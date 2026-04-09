// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/precinct-dev/precinct/internal/testutil"
)

func TestConfigFromEnv_OAuthResourceServerConfigPath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "oauth-resource-server.yaml")
	if err := os.WriteFile(configPath, []byte("oauth_resource_server:\n  issuer: http://issuer\n  audience: gateway\n  jwks_url: http://issuer/jwks.json\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Setenv("OAUTH_RESOURCE_SERVER_CONFIG_PATH", configPath)
	cfg := ConfigFromEnv()
	if cfg.OAuthResourceServerConfigPath != configPath {
		t.Fatalf("OAuthResourceServerConfigPath = %q, want %q", cfg.OAuthResourceServerConfigPath, configPath)
	}
}

func TestGatewayOAuthBearerProxyMode(t *testing.T) {
	issuer := newGatewayTestOAuthIssuer(t)
	configPath := writeGatewayOAuthConfig(t, issuer.URL)

	var upstreamAuthorization string
	var upstreamAuthMethod string
	var upstreamPrincipalRole string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuthorization = r.Header.Get("Authorization")
		upstreamAuthMethod = r.Header.Get("X-Precinct-Auth-Method")
		upstreamPrincipalRole = r.Header.Get("X-Precinct-Principal-Role")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	t.Cleanup(upstream.Close)

	cfg := &Config{
		UpstreamURL:                   upstream.URL,
		OPAPolicyDir:                  testutil.OPAPolicyDir(),
		ToolRegistryConfigPath:        testutil.ToolRegistryConfigPath(),
		AuditLogPath:                  "",
		OPAPolicyPath:                 testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:           1024 * 1024,
		SPIFFEMode:                    "dev",
		SPIFFETrustDomain:             "poc.local",
		MCPTransportMode:              "proxy",
		OAuthResourceServerConfigPath: configPath,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+issuer.MustMintToken(t, map[string]any{
		"iss":   issuer.URL,
		"sub":   "external-agent",
		"aud":   "gateway",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"scope": "mcp:tools",
	}))
	rec := httptest.NewRecorder()

	gw.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if upstreamAuthorization != "" {
		t.Fatalf("Authorization header leaked upstream: %q", upstreamAuthorization)
	}
	if upstreamAuthMethod != "oauth_jwt" {
		t.Fatalf("X-Precinct-Auth-Method = %q, want oauth_jwt", upstreamAuthMethod)
	}
	if upstreamPrincipalRole != "external_user" {
		t.Fatalf("X-Precinct-Principal-Role = %q, want external_user", upstreamPrincipalRole)
	}
}

// TestGatewayOAuthBearerIntrospection validates that opaque (non-JWT) bearer
// tokens are authenticated via RFC 7662 introspection when configured. This
// is an integration test: no mocks -- a real httptest gateway + issuer.
func TestGatewayOAuthBearerIntrospection(t *testing.T) {
	issuer := newGatewayTestOAuthIssuerWithIntrospection(t)
	configPath := writeGatewayOAuthConfigWithIntrospection(t, issuer.URL)

	var upstreamAuthMethod string
	var upstreamPrincipalRole string
	var upstreamAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuthorization = r.Header.Get("Authorization")
		upstreamAuthMethod = r.Header.Get("X-Precinct-Auth-Method")
		upstreamPrincipalRole = r.Header.Get("X-Precinct-Principal-Role")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	t.Cleanup(upstream.Close)

	cfg := &Config{
		UpstreamURL:                   upstream.URL,
		OPAPolicyDir:                  testutil.OPAPolicyDir(),
		ToolRegistryConfigPath:        testutil.ToolRegistryConfigPath(),
		AuditLogPath:                  "",
		OPAPolicyPath:                 testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:           1024 * 1024,
		SPIFFEMode:                    "dev",
		SPIFFETrustDomain:             "poc.local",
		MCPTransportMode:              "proxy",
		OAuthResourceServerConfigPath: configPath,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	t.Run("OpaqueTokenAuthenticatedViaIntrospection", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer opaque-gateway-test-token")
		rec := httptest.NewRecorder()

		gw.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if upstreamAuthorization != "" {
			t.Fatalf("Authorization header leaked upstream: %q", upstreamAuthorization)
		}
		if upstreamAuthMethod != "oauth_introspection" {
			t.Fatalf("X-Precinct-Auth-Method = %q, want oauth_introspection", upstreamAuthMethod)
		}
		if upstreamPrincipalRole != "external_user" {
			t.Fatalf("X-Precinct-Principal-Role = %q, want external_user", upstreamPrincipalRole)
		}
	})

	t.Run("InactiveOpaqueTokenFailsClosed", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer inactive-opaque-token")
		rec := httptest.NewRecorder()

		gw.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("JWTStillWorksWhenIntrospectionConfigured", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+issuer.MustMintToken(t, map[string]any{
			"iss":   issuer.URL,
			"sub":   "jwt-user",
			"aud":   "gateway",
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"scope": "mcp:tools",
		}))
		rec := httptest.NewRecorder()

		gw.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if upstreamAuthMethod != "oauth_jwt" {
			t.Fatalf("X-Precinct-Auth-Method = %q, want oauth_jwt", upstreamAuthMethod)
		}
	})
}

type gatewayTestOAuthIssuer struct {
	*httptest.Server
	kid     string
	privKey *rsa.PrivateKey
}

func newGatewayTestOAuthIssuer(t *testing.T) *gatewayTestOAuthIssuer {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	issuer := &gatewayTestOAuthIssuer{
		kid:     "gateway-test-kid",
		privKey: privKey,
	}

	pubJWK := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		KeyID:     issuer.kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
		_ = json.NewEncoder(w).Encode(jwks)
	})
	issuer.Server = httptest.NewServer(mux)
	t.Cleanup(issuer.Close)
	return issuer
}

// newGatewayTestOAuthIssuerWithIntrospection creates a test OAuth issuer
// that serves JWKS (for JWT validation) and /introspect (for opaque tokens).
func newGatewayTestOAuthIssuerWithIntrospection(t *testing.T) *gatewayTestOAuthIssuer {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	issuer := &gatewayTestOAuthIssuer{
		kid:     "gateway-test-kid",
		privKey: privKey,
	}

	pubJWK := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		KeyID:     issuer.kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
		_ = json.NewEncoder(w).Encode(jwks)
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		token := r.FormValue("token")

		w.Header().Set("Content-Type", "application/json")

		// Only "opaque-gateway-test-token" is active; everything else is inactive.
		if token == "opaque-gateway-test-token" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active":    true,
				"sub":       "opaque-integration-user",
				"aud":       "gateway",
				"scope":     "mcp:tools",
				"client_id": "integration-client",
				"exp":       time.Now().Add(5 * time.Minute).Unix(),
				"iss":       "", // issuer URL filled in after server starts
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
		}
	})

	issuer.Server = httptest.NewServer(mux)
	t.Cleanup(issuer.Close)
	return issuer
}

func (i *gatewayTestOAuthIssuer) MustMintToken(t *testing.T, claims map[string]any) string {
	t.Helper()

	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{
		Key:       i.privKey,
		KeyID:     i.kid,
		Algorithm: string(jose.RS256),
	}}
	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}

	builder := josejwt.Signed(signer)
	builder = builder.Claims(claims)

	token, err := builder.Serialize()
	if err != nil {
		t.Fatalf("jwt.Serialize: %v", err)
	}
	return token
}

func writeGatewayOAuthConfig(t *testing.T, issuerURL string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "oauth-resource-server.yaml")
	content := []byte("oauth_resource_server:\n" +
		"  issuer: " + issuerURL + "\n" +
		"  audience: gateway\n" +
		"  jwks_url: " + issuerURL + "/jwks.json\n" +
		"  required_scopes:\n" +
		"    - mcp:tools\n" +
		"  clock_skew_seconds: 30\n" +
		"  cache_ttl_seconds: 60\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return path
}

func writeGatewayOAuthConfigWithIntrospection(t *testing.T, issuerURL string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "oauth-resource-server.yaml")
	content := []byte("oauth_resource_server:\n" +
		"  issuer: " + issuerURL + "\n" +
		"  audience: gateway\n" +
		"  jwks_url: " + issuerURL + "/jwks.json\n" +
		"  required_scopes:\n" +
		"    - mcp:tools\n" +
		"  clock_skew_seconds: 30\n" +
		"  cache_ttl_seconds: 60\n" +
		"  introspection_url: " + issuerURL + "/introspect\n" +
		"  introspection_required_audience: gateway\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return path
}

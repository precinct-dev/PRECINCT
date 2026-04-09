// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"github.com/precinct-dev/precinct/internal/testutil"
)

// --- Unit tests: handler response shape and config-to-JSON mapping ---

func TestOAuthProtectedResourceHandler_ReturnsMetadata(t *testing.T) {
	cfg := &middleware.OAuthJWTConfig{
		Issuer:         "http://mock-oauth-issuer:8088",
		Audience:       "gateway",
		JWKSURL:        "http://mock-oauth-issuer:8088/jwks.json",
		RequiredScopes: []string{"mcp:tools"},
	}

	handler := oauthProtectedResourceHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	var meta OAuthProtectedResourceMetadata
	if err := json.NewDecoder(rec.Body).Decode(&meta); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if meta.Resource != "gateway" {
		t.Errorf("resource = %q, want %q", meta.Resource, "gateway")
	}
	if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != "http://mock-oauth-issuer:8088" {
		t.Errorf("authorization_servers = %v, want [http://mock-oauth-issuer:8088]", meta.AuthorizationServers)
	}
	if len(meta.ScopesSupported) != 1 || meta.ScopesSupported[0] != "mcp:tools" {
		t.Errorf("scopes_supported = %v, want [mcp:tools]", meta.ScopesSupported)
	}
	if meta.MCPEndpoint != "/" {
		t.Errorf("mcp_endpoint = %q, want %q", meta.MCPEndpoint, "/")
	}
}

func TestOAuthProtectedResourceHandler_NilConfig_Returns404(t *testing.T) {
	handler := oauthProtectedResourceHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestOAuthProtectedResourceHandler_PostMethod_Returns405(t *testing.T) {
	cfg := &middleware.OAuthJWTConfig{
		Issuer:   "http://issuer",
		Audience: "gateway",
		JWKSURL:  "http://issuer/jwks.json",
	}

	handler := oauthProtectedResourceHandler(cfg)
	req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}

	allow := rec.Header().Get("Allow")
	if allow != http.MethodGet {
		t.Errorf("Allow header = %q, want %q", allow, http.MethodGet)
	}
}

func TestOAuthProtectedResourceHandler_NoScopes_OmitsField(t *testing.T) {
	cfg := &middleware.OAuthJWTConfig{
		Issuer:   "http://issuer",
		Audience: "aud",
		JWKSURL:  "http://issuer/jwks.json",
	}

	handler := oauthProtectedResourceHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Decode into raw map to verify the scopes_supported key is absent
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := raw["scopes_supported"]; present {
		t.Error("scopes_supported should be omitted when no scopes are configured")
	}
}

func TestOAuthProtectedResourceHandler_CacheControlSet(t *testing.T) {
	cfg := &middleware.OAuthJWTConfig{
		Issuer:   "http://issuer",
		Audience: "gateway",
		JWKSURL:  "http://issuer/jwks.json",
	}

	handler := oauthProtectedResourceHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	cc := rec.Header().Get("Cache-Control")
	if cc != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q, want %q", cc, "public, max-age=3600")
	}
}

func TestOAuthProtectedResourceHandler_MultipleScopes(t *testing.T) {
	cfg := &middleware.OAuthJWTConfig{
		Issuer:         "http://issuer",
		Audience:       "gateway",
		JWKSURL:        "http://issuer/jwks.json",
		RequiredScopes: []string{"mcp:tools", "mcp:read", "admin"},
	}

	handler := oauthProtectedResourceHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var meta OAuthProtectedResourceMetadata
	if err := json.NewDecoder(rec.Body).Decode(&meta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(meta.ScopesSupported) != 3 {
		t.Errorf("scopes_supported length = %d, want 3", len(meta.ScopesSupported))
	}
}

// --- Integration test: start gateway, fetch endpoint, verify HTTP 200 + JSON ---

func TestOAuthProtectedResource_IntegrationViaGateway(t *testing.T) {
	issuer := newGatewayTestOAuthIssuer(t)
	configPath := writeGatewayOAuthConfig(t, issuer.URL)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
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

	ts := httptest.NewServer(gw.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var meta OAuthProtectedResourceMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if meta.Resource != "gateway" {
		t.Errorf("resource = %q, want %q", meta.Resource, "gateway")
	}
	if len(meta.AuthorizationServers) == 0 {
		t.Fatal("authorization_servers is empty")
	}
	if meta.AuthorizationServers[0] != issuer.URL {
		t.Errorf("authorization_servers[0] = %q, want %q", meta.AuthorizationServers[0], issuer.URL)
	}
	if meta.MCPEndpoint != "/" {
		t.Errorf("mcp_endpoint = %q, want %q", meta.MCPEndpoint, "/")
	}
	if len(meta.ScopesSupported) != 1 || meta.ScopesSupported[0] != "mcp:tools" {
		t.Errorf("scopes_supported = %v, want [mcp:tools]", meta.ScopesSupported)
	}
}

func TestOAuthProtectedResource_IntegrationNoAuth(t *testing.T) {
	// Verify the endpoint does not require authentication by checking that
	// a request without any Authorization header still succeeds.
	issuer := newGatewayTestOAuthIssuer(t)
	configPath := writeGatewayOAuthConfig(t, issuer.URL)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
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

	// Use httptest.NewRequest (no real auth headers) against the handler directly
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	gw.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unauthenticated request: status = %d, want %d; body = %s",
			rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestOAuthProtectedResource_PublicHandler(t *testing.T) {
	// Verify the endpoint is also available on the public handler
	configPath := filepath.Join(t.TempDir(), "oauth-resource-server.yaml")
	content := []byte("oauth_resource_server:\n" +
		"  issuer: http://test-issuer\n" +
		"  audience: gateway\n" +
		"  jwks_url: http://test-issuer/jwks.json\n" +
		"  required_scopes:\n" +
		"    - mcp:tools\n")
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
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
		PublicListenPort:              defaultPublicListenPort,
		PublicListenHost:              defaultPublicListenHost,
		PublicRouteAllowlist:          defaultPublicRouteAllowlist,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	gw.PublicHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("public handler: status = %d, want %d; body = %s",
			rec.Code, http.StatusOK, rec.Body.String())
	}

	var meta OAuthProtectedResourceMetadata
	if err := json.NewDecoder(rec.Body).Decode(&meta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if meta.Resource != "gateway" {
		t.Errorf("resource = %q, want %q", meta.Resource, "gateway")
	}
	if meta.AuthorizationServers[0] != "http://test-issuer" {
		t.Errorf("authorization_servers[0] = %q, want %q", meta.AuthorizationServers[0], "http://test-issuer")
	}
}

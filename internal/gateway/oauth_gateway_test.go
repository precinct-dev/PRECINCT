package gateway

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

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

type gatewayTestOAuthIssuer struct {
	*httptest.Server
	kid string
	key []byte
}

func newGatewayTestOAuthIssuer(t *testing.T) *gatewayTestOAuthIssuer {
	t.Helper()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	issuer := &gatewayTestOAuthIssuer{
		kid: "gateway-test-kid",
		key: key,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "oct",
					"alg": "HS256",
					"use": "sig",
					"kid": issuer.kid,
					"k":   base64.RawURLEncoding.EncodeToString(issuer.key),
				},
			},
		})
	})
	issuer.Server = httptest.NewServer(mux)
	t.Cleanup(issuer.Close)
	return issuer
}

func (i *gatewayTestOAuthIssuer) MustMintToken(t *testing.T, claims map[string]any) string {
	t.Helper()

	headerJSON, err := json.Marshal(map[string]any{
		"alg": "HS256",
		"typ": "JWT",
		"kid": i.kid,
	})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerEncoded + "." + payloadEncoded

	mac := hmac.New(sha256.New, i.key)
	_, _ = mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + signature
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

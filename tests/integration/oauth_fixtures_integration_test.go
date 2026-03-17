//go:build integration
// +build integration

package integration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type mockOAuthJWKS struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		K   string `json:"k"`
	} `json:"keys"`
}

type mockOAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
}

type mockOAuthIntrospectResponse struct {
	Active bool  `json:"active"`
	Exp    int64 `json:"exp"`
}

func TestOAuthExternalMockIssuerContract(t *testing.T) {
	t.Parallel()
	baseURL := getEnvOrDefault("MOCK_OAUTH_ISSUER_URL", "http://localhost:18083")

	if err := waitForService(baseURL+"/health", 15*time.Second); err != nil {
		if os.Getenv("MOCK_OAUTH_STRICT") == "" {
			t.Skipf("mock-oauth-issuer not reachable at %s/health; set MOCK_OAUTH_STRICT=1 to fail when fixture is missing", baseURL)
		}
		t.Fatalf("mock-oauth-issuer not reachable: %v", err)
	}

	jwksReq, err := http.Get(baseURL + "/jwks.json")
	if err != nil {
		t.Fatalf("GET /jwks.json failed: %v", err)
	}
	defer func() { _ = jwksReq.Body.Close() }()
	if jwksReq.StatusCode != http.StatusOK {
		t.Fatalf("GET /jwks.json status=%d", jwksReq.StatusCode)
	}

	var jwks mockOAuthJWKS
	if err := json.NewDecoder(jwksReq.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks response: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected one jwk, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kty != "oct" {
		t.Fatalf("expected oct key, got %q", jwks.Keys[0].Kty)
	}
	if jwks.Keys[0].Alg != "HS256" {
		t.Fatalf("expected alg HS256, got %q", jwks.Keys[0].Alg)
	}
	if strings.TrimSpace(jwks.Keys[0].K) == "" {
		t.Fatal("expected jwk k value")
	}

	tokenPayload := `{"client_id":"acct", "subject":"integration", "scope":"mcp:tools", "audience":"gateway", "ttl_seconds": 180}`
	tokenReq, err := http.NewRequest(http.MethodPost, baseURL+"/token", strings.NewReader(tokenPayload))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /token failed: %v", err)
	}
	defer func() { _ = tokenResp.Body.Close() }()
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /token status=%d", tokenResp.StatusCode)
	}

	var token mockOAuthTokenResponse
	if err := json.NewDecoder(tokenResp.Body).Decode(&token); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		t.Fatal("missing access_token in token response")
	}
	if token.TokenType != "Bearer" {
		t.Fatalf("expected token_type Bearer, got %q", token.TokenType)
	}
	parts := strings.Split(token.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not jwt: parts=%d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode jwt header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal jwt header: %v", err)
	}
	gotKid, ok := header["kid"].(string)
	if !ok || strings.TrimSpace(gotKid) != strings.TrimSpace(jwks.Keys[0].Kid) {
		t.Fatalf("expected kid %q, got %q (ok=%v)", strings.TrimSpace(jwks.Keys[0].Kid), gotKid, ok)
	}

	opaquePayload := `{"client_id":"acct", "token_type":"opaque", "scope":"opaque-scope", "audience":"gateway", "ttl_seconds": 180}`
	opaqueReq, err := http.NewRequest(http.MethodPost, baseURL+"/token", strings.NewReader(opaquePayload))
	if err != nil {
		t.Fatalf("build opaque token request: %v", err)
	}
	opaqueReq.Header.Set("Content-Type", "application/json")
	opaqueResp, err := http.DefaultClient.Do(opaqueReq)
	if err != nil {
		t.Fatalf("POST /token (opaque) failed: %v", err)
	}
	defer func() { _ = opaqueResp.Body.Close() }()
	if opaqueResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /token (opaque) status=%d", opaqueResp.StatusCode)
	}
	var opaqueToken mockOAuthTokenResponse
	if err := json.NewDecoder(opaqueResp.Body).Decode(&opaqueToken); err != nil {
		t.Fatalf("decode opaque token response: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(opaqueToken.AccessToken), "opaque-") {
		t.Fatalf("expected opaque token prefix, got %q", opaqueToken.AccessToken)
	}

	introspectReqPayload := `{"token":"` + opaqueToken.AccessToken + `"}`
	introspectReq, err := http.NewRequest(http.MethodPost, baseURL+"/introspect", strings.NewReader(introspectReqPayload))
	if err != nil {
		t.Fatalf("build introspect request: %v", err)
	}
	introspectReq.Header.Set("Content-Type", "application/json")
	introspectResp, err := http.DefaultClient.Do(introspectReq)
	if err != nil {
		t.Fatalf("POST /introspect failed: %v", err)
	}
	defer func() { _ = introspectResp.Body.Close() }()
	var introspect mockOAuthIntrospectResponse
	if err := json.NewDecoder(introspectResp.Body).Decode(&introspect); err != nil {
		t.Fatalf("decode introspect response: %v", err)
	}
	if !introspect.Active {
		t.Fatal("expected active=true for minted opaque token")
	}
	if introspect.Exp <= 0 {
		t.Fatal("expected introspection exp > 0")
	}

	unknownReqPayload := `{"token":"opaque-` + "does-not-exist" + `"}`
	unknownReq, err := http.NewRequest(http.MethodPost, baseURL+"/introspect", strings.NewReader(unknownReqPayload))
	if err != nil {
		t.Fatalf("build unknown introspect request: %v", err)
	}
	unknownReq.Header.Set("Content-Type", "application/json")
	unknownResp, err := http.DefaultClient.Do(unknownReq)
	if err != nil {
		t.Fatalf("POST /introspect (unknown token) failed: %v", err)
	}
	defer func() { _ = unknownResp.Body.Close() }()
	var unknown mockOAuthIntrospectResponse
	if err := json.NewDecoder(unknownResp.Body).Decode(&unknown); err != nil {
		t.Fatalf("decode unknown introspect response: %v", err)
	}
	if unknown.Active {
		t.Fatal("expected active=false for unknown token")
	}
}

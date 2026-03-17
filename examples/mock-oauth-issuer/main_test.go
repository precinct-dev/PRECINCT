package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T, issuer string) *httptest.Server {
	t.Helper()
	instance := newIssuer(issuer, "test-key")
	mux := http.NewServeMux()
	mux.HandleFunc("/health", instance.handleHealth)
	mux.HandleFunc("/jwks.json", instance.handleJWKS)
	mux.HandleFunc("/token", instance.handleToken)
	mux.HandleFunc("/introspect", instance.handleIntrospect)
	return httptest.NewServer(mux)
}

func TestMockOAuthIssuerJWKSAndJWT(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, "http://mock-oauth-issuer")
	defer server.Close()

	respJWKS, err := http.Get(server.URL + "/jwks.json")
	if err != nil {
		t.Fatalf("GET /jwks.json failed: %v", err)
	}
	defer func() { _ = respJWKS.Body.Close() }()
	if respJWKS.StatusCode != http.StatusOK {
		t.Fatalf("GET /jwks.json status=%d", respJWKS.StatusCode)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.NewDecoder(respJWKS.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected one jwk, got %d", len(jwks.Keys))
	}
	if got := strings.TrimSpace(jwks.Keys[0]["kid"]); got != "test-key" {
		t.Fatalf("expected key id %q, got %q", "test-key", got)
	}

	body := strings.NewReader(`{
		"client_id": "acme-client",
		"subject": "alice",
		"audience": "gateway",
		"scope": "mcp:tools",
		"ttl_seconds": 600
	}`)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/token", body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	respToken, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token failed: %v", err)
	}
	defer func() { _ = respToken.Body.Close() }()
	var tokenResp tokenResponse
	if err := json.NewDecoder(respToken.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenResp.AccessToken == "" {
		t.Fatal("expected signed token")
	}

	parts := strings.Split(tokenResp.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT format (3 segments), got %d", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode jwt header: %v", err)
	}
	var headerPayload map[string]any
	if err := json.Unmarshal(header, &headerPayload); err != nil {
		t.Fatalf("decode header json: %v", err)
	}
	kidRaw, ok := headerPayload["kid"]
	if !ok {
		t.Fatal("jwt header missing kid")
	}
	kid, ok := kidRaw.(string)
	if !ok {
		t.Fatalf("jwt header kid wrong type %T", kidRaw)
	}
	if got := strings.TrimSpace(kid); got != "test-key" {
		t.Fatalf("expected token kid %q got %q", "test-key", got)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode jwt payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("decode jwt payload json: %v", err)
	}
	if got := payload["sub"]; got != "alice" {
		t.Fatalf("expected sub=alice, got %#v", got)
	}
	if expRaw, ok := payload["exp"].(float64); !ok || int64(expRaw) <= time.Now().Unix() {
		t.Fatalf("expected exp > now, got %#v", payload["exp"])
	}
}

func TestMockOAuthIssuerOpaqueIntrospection(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, "http://mock-oauth-issuer")
	defer server.Close()

	reqBody := strings.NewReader(`{
		"client_id": "acme-client",
		"token_type": "opaque",
		"audience": "gateway",
		"scope": "mcp:tools"
	}`)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/token", reqBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	respToken, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token failed: %v", err)
	}
	defer func() { _ = respToken.Body.Close() }()
	var tokenResp tokenResponse
	if err := json.NewDecoder(respToken.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	if tokenResp.AccessToken == "" {
		t.Fatal("expected opaque token")
	}

	introReqBody := strings.NewReader(`{"token":"` + tokenResp.AccessToken + `"}`)
	introReq, err := http.NewRequest(http.MethodPost, server.URL+"/introspect", introReqBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	introReq.Header.Set("Content-Type", "application/json")
	introResp, err := http.DefaultClient.Do(introReq)
	if err != nil {
		t.Fatalf("POST /introspect failed: %v", err)
	}
	defer func() { _ = introResp.Body.Close() }()

	var intro introspectResponse
	if err := json.NewDecoder(introResp.Body).Decode(&intro); err != nil {
		t.Fatalf("decode introspect response: %v", err)
	}
	if !intro.Active {
		t.Fatal("expected active=true for minted token")
	}

	unknownReq := strings.NewReader(`{"token":"opaque-missing-token"}`)
	unknownReqObj, err := http.NewRequest(http.MethodPost, server.URL+"/introspect", unknownReq)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	unknownReqObj.Header.Set("Content-Type", "application/json")
	unknownResp, err := http.DefaultClient.Do(unknownReqObj)
	if err != nil {
		t.Fatalf("POST /introspect failed: %v", err)
	}
	defer func() { _ = unknownResp.Body.Close() }()
	var unknown introspectResponse
	if err := json.NewDecoder(unknownResp.Body).Decode(&unknown); err != nil {
		t.Fatalf("decode introspect response: %v", err)
	}
	if unknown.Active {
		t.Fatal("expected active=false for missing token")
	}
}

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

const testSigningKey = "test-signing-key-for-token-exchange-32b"

func testTokenExchangeConfig() *TokenExchangeConfig {
	return LoadTokenExchangeConfigForTest(
		[]TokenExchangeCredential{
			{
				CredentialType: "api_key",
				Credential:     "test-tool-key-001",
				SPIFFEID:       "spiffe://poc.local/external/test-tool",
			},
			{
				CredentialType: "api_key",
				Credential:     "monitoring-key-001",
				SPIFFEID:       "spiffe://poc.local/external/monitoring-agent",
			},
		},
		testSigningKey,
		15*time.Minute,
		1*time.Hour,
	)
}

// --- Unit Tests ---

func TestLoadTokenExchangeConfig(t *testing.T) {
	t.Run("loads valid config from file", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "token-exchange.yaml")
		configYAML := `
credentials:
  - credential_type: "api_key"
    credential: "key-abc"
    spiffe_id: "spiffe://test.local/external/abc"
default_ttl: "10m"
max_ttl: "30m"
`
		if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("TOKEN_EXCHANGE_SIGNING_KEY", "test-key-123")

		cfg, err := LoadTokenExchangeConfig(configPath)
		if err != nil {
			t.Fatalf("LoadTokenExchangeConfig failed: %v", err)
		}

		if len(cfg.Credentials) != 1 {
			t.Fatalf("expected 1 credential, got %d", len(cfg.Credentials))
		}
		if cfg.defaultTTL != 10*time.Minute {
			t.Errorf("default_ttl = %v, want 10m", cfg.defaultTTL)
		}
		if cfg.maxTTL != 30*time.Minute {
			t.Errorf("max_ttl = %v, want 30m", cfg.maxTTL)
		}
	})

	t.Run("fails without signing key env", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "token-exchange.yaml")
		configYAML := `
credentials:
  - credential_type: "api_key"
    credential: "key-abc"
    spiffe_id: "spiffe://test.local/external/abc"
`
		if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("TOKEN_EXCHANGE_SIGNING_KEY", "")

		_, err := LoadTokenExchangeConfig(configPath)
		if err == nil {
			t.Fatal("expected error for missing signing key")
		}
		if !strings.Contains(err.Error(), "TOKEN_EXCHANGE_SIGNING_KEY") {
			t.Errorf("error should mention TOKEN_EXCHANGE_SIGNING_KEY, got: %v", err)
		}
	})

	t.Run("fails with missing file", func(t *testing.T) {
		_, err := LoadTokenExchangeConfig("/nonexistent/path.yaml")
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}

func TestCredentialLookup(t *testing.T) {
	cfg := testTokenExchangeConfig()

	t.Run("known credential returns SPIFFE ID", func(t *testing.T) {
		spiffeID, ok := cfg.LookupCredential("api_key", "test-tool-key-001")
		if !ok {
			t.Fatal("expected credential to be found")
		}
		if spiffeID != "spiffe://poc.local/external/test-tool" {
			t.Errorf("spiffe_id = %q, want spiffe://poc.local/external/test-tool", spiffeID)
		}
	})

	t.Run("unknown credential returns false", func(t *testing.T) {
		_, ok := cfg.LookupCredential("api_key", "unknown-key")
		if ok {
			t.Fatal("expected credential to not be found")
		}
	})

	t.Run("wrong credential type returns false", func(t *testing.T) {
		_, ok := cfg.LookupCredential("bearer", "test-tool-key-001")
		if ok {
			t.Fatal("expected credential to not be found with wrong type")
		}
	})
}

func TestResolveTTL(t *testing.T) {
	cfg := testTokenExchangeConfig()

	t.Run("empty requested uses default", func(t *testing.T) {
		ttl, err := cfg.ResolveTTL("")
		if err != nil {
			t.Fatal(err)
		}
		if ttl != 15*time.Minute {
			t.Errorf("ttl = %v, want 15m", ttl)
		}
	})

	t.Run("valid requested TTL is honored", func(t *testing.T) {
		ttl, err := cfg.ResolveTTL("5m")
		if err != nil {
			t.Fatal(err)
		}
		if ttl != 5*time.Minute {
			t.Errorf("ttl = %v, want 5m", ttl)
		}
	})

	t.Run("TTL exceeding max is clamped", func(t *testing.T) {
		ttl, err := cfg.ResolveTTL("2h")
		if err != nil {
			t.Fatal(err)
		}
		if ttl != 1*time.Hour {
			t.Errorf("ttl = %v, want 1h (clamped to max)", ttl)
		}
	})

	t.Run("negative TTL is rejected", func(t *testing.T) {
		_, err := cfg.ResolveTTL("-5m")
		if err == nil {
			t.Fatal("expected error for negative TTL")
		}
	})

	t.Run("invalid TTL format is rejected", func(t *testing.T) {
		_, err := cfg.ResolveTTL("notaduration")
		if err == nil {
			t.Fatal("expected error for invalid TTL")
		}
	})
}

func TestMintAndValidateToken(t *testing.T) {
	cfg := testTokenExchangeConfig()
	spiffeID := "spiffe://poc.local/external/test-tool"

	t.Run("mint and validate round-trip", func(t *testing.T) {
		token, err := cfg.MintToken(spiffeID, 15*time.Minute)
		if err != nil {
			t.Fatal(err)
		}

		// Token should have 3 parts (JWT format).
		parts := strings.SplitN(token, ".", 3)
		if len(parts) != 3 {
			t.Fatalf("expected 3 JWT parts, got %d", len(parts))
		}

		// Validate the token.
		claims, err := ValidateExchangeToken(token, []byte(testSigningKey))
		if err != nil {
			t.Fatalf("ValidateExchangeToken failed: %v", err)
		}

		if claims.Sub != spiffeID {
			t.Errorf("sub = %q, want %q", claims.Sub, spiffeID)
		}
		if claims.Iss != "precinct-gateway" {
			t.Errorf("iss = %q, want precinct-gateway", claims.Iss)
		}
		if claims.Aud != "precinct-gateway" {
			t.Errorf("aud = %q, want precinct-gateway", claims.Aud)
		}
		if claims.PrecinctAuthMethod != "token_exchange" {
			t.Errorf("precinct_auth_method = %q, want token_exchange", claims.PrecinctAuthMethod)
		}
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		// Mint with a time function that returns a time in the past.
		token, err := mintExchangeToken(spiffeID, 1*time.Second, []byte(testSigningKey), func() time.Time {
			return time.Now().Add(-2 * time.Hour)
		})
		if err != nil {
			t.Fatal(err)
		}

		_, err = ValidateExchangeToken(token, []byte(testSigningKey))
		if err == nil {
			t.Fatal("expected error for expired token")
		}
		if !strings.Contains(err.Error(), "expired") {
			t.Errorf("error should mention expiry, got: %v", err)
		}
	})

	t.Run("wrong signing key is rejected", func(t *testing.T) {
		token, err := cfg.MintToken(spiffeID, 15*time.Minute)
		if err != nil {
			t.Fatal(err)
		}

		_, err = ValidateExchangeToken(token, []byte("wrong-key"))
		if err == nil {
			t.Fatal("expected error for wrong signing key")
		}
		if !strings.Contains(err.Error(), "signature") {
			t.Errorf("error should mention signature, got: %v", err)
		}
	})

	t.Run("tampered token is rejected", func(t *testing.T) {
		token, err := cfg.MintToken(spiffeID, 15*time.Minute)
		if err != nil {
			t.Fatal(err)
		}

		// Tamper with the payload by changing a character.
		parts := strings.SplitN(token, ".", 3)
		// Flip a character in the payload.
		payload := []byte(parts[1])
		if len(payload) > 5 {
			payload[5] = 'X'
		}
		tampered := parts[0] + "." + string(payload) + "." + parts[2]

		_, err = ValidateExchangeToken(tampered, []byte(testSigningKey))
		if err == nil {
			t.Fatal("expected error for tampered token")
		}
	})

	t.Run("malformed JWT is rejected", func(t *testing.T) {
		_, err := ValidateExchangeToken("not.a.jwt-at-all", []byte(testSigningKey))
		if err == nil {
			t.Fatal("expected error for malformed JWT")
		}
	})

	t.Run("two-part string is rejected", func(t *testing.T) {
		_, err := ValidateExchangeToken("only.twoparts", []byte(testSigningKey))
		if err == nil {
			t.Fatal("expected error for two-part string")
		}
		if !strings.Contains(err.Error(), "expected 3 parts") {
			t.Errorf("error should mention part count, got: %v", err)
		}
	})
}

// --- HTTP Handler Tests ---

func TestTokenExchangeHandler(t *testing.T) {
	cfg := testTokenExchangeConfig()
	handler := tokenExchangeHandler(cfg)

	t.Run("valid credential returns token", func(t *testing.T) {
		body := TokenExchangeRequest{
			CredentialType: "api_key",
			Credential:     "test-tool-key-001",
		}
		b, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
		}

		var resp TokenExchangeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if resp.Token == "" {
			t.Fatal("expected non-empty token")
		}
		if resp.TokenType != "Bearer" {
			t.Errorf("token_type = %q, want Bearer", resp.TokenType)
		}
		if resp.ExpiresIn != 900 {
			t.Errorf("expires_in = %d, want 900 (15 minutes)", resp.ExpiresIn)
		}

		// Validate the returned token.
		claims, err := ValidateExchangeToken(resp.Token, []byte(testSigningKey))
		if err != nil {
			t.Fatalf("returned token is invalid: %v", err)
		}
		if claims.Sub != "spiffe://poc.local/external/test-tool" {
			t.Errorf("sub = %q, want spiffe://poc.local/external/test-tool", claims.Sub)
		}
	})

	t.Run("valid credential with custom TTL", func(t *testing.T) {
		body := TokenExchangeRequest{
			CredentialType: "api_key",
			Credential:     "test-tool-key-001",
			RequestedTTL:   "5m",
		}
		b, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange", bytes.NewReader(b))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}

		var resp TokenExchangeResponse
		json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp.ExpiresIn != 300 {
			t.Errorf("expires_in = %d, want 300 (5 minutes)", resp.ExpiresIn)
		}
	})

	t.Run("invalid credential returns 401", func(t *testing.T) {
		body := TokenExchangeRequest{
			CredentialType: "api_key",
			Credential:     "invalid-key",
		}
		b, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange", bytes.NewReader(b))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}

		var errResp tokenExchangeErrorResponse
		json.Unmarshal(rec.Body.Bytes(), &errResp)
		if errResp.Error != "invalid_credential" {
			t.Errorf("error = %q, want invalid_credential", errResp.Error)
		}
	})

	t.Run("missing fields returns 400", func(t *testing.T) {
		body := TokenExchangeRequest{
			CredentialType: "api_key",
			// Missing Credential
		}
		b, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange", bytes.NewReader(b))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("invalid JSON returns 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange", strings.NewReader("{bad json"))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("GET method returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/token-exchange", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rec.Code)
		}
	})

	t.Run("invalid TTL format returns 400", func(t *testing.T) {
		body := TokenExchangeRequest{
			CredentialType: "api_key",
			Credential:     "test-tool-key-001",
			RequestedTTL:   "notaduration",
		}
		b, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange", bytes.NewReader(b))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("TTL exceeding max is clamped", func(t *testing.T) {
		body := TokenExchangeRequest{
			CredentialType: "api_key",
			Credential:     "test-tool-key-001",
			RequestedTTL:   "2h",
		}
		b, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange", bytes.NewReader(b))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}

		var resp TokenExchangeResponse
		json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp.ExpiresIn != 3600 {
			t.Errorf("expires_in = %d, want 3600 (1h, clamped to max)", resp.ExpiresIn)
		}
	})
}

// --- Integration Test: Exchange -> Use Token -> Middleware Chain ---

func TestTokenExchangeIntegration(t *testing.T) {
	cfg := testTokenExchangeConfig()

	t.Run("exchanged token is accepted by SPIFFEAuth middleware", func(t *testing.T) {
		// Step 1: Exchange credential for token.
		exchangeHandler := tokenExchangeHandler(cfg)
		body := TokenExchangeRequest{
			CredentialType: "api_key",
			Credential:     "test-tool-key-001",
		}
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange", bytes.NewReader(b))
		rec := httptest.NewRecorder()
		exchangeHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("exchange status = %d, want 200", rec.Code)
		}

		var resp TokenExchangeResponse
		json.Unmarshal(rec.Body.Bytes(), &resp)
		token := resp.Token

		// Step 2: Use token as Bearer in a request through SPIFFEAuth middleware.
		signingKey := []byte(testSigningKey)
		validator := func(tokenStr string) (*middleware.ExchangeTokenClaims, error) {
			claims, err := ValidateExchangeToken(tokenStr, signingKey)
			if err != nil {
				return nil, err
			}
			return &middleware.ExchangeTokenClaims{
				Sub:        claims.Sub,
				AuthMethod: claims.PrecinctAuthMethod,
			}, nil
		}

		var capturedSPIFFEID string
		var capturedAuthMethod string
		innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedSPIFFEID = middleware.GetSPIFFEID(r.Context())
			capturedAuthMethod = middleware.GetAuthMethod(r.Context())
			w.WriteHeader(http.StatusOK)
		})

		spiffeAuth := middleware.SPIFFEAuth(
			innerHandler,
			"dev",
			middleware.WithExchangeTokenValidator(validator),
		)

		mcpReq := httptest.NewRequest(http.MethodPost, "/", nil)
		mcpReq.Header.Set("Authorization", "Bearer "+token)
		mcpRec := httptest.NewRecorder()
		spiffeAuth.ServeHTTP(mcpRec, mcpReq)

		if mcpRec.Code != http.StatusOK {
			t.Fatalf("MCP request status = %d, want 200; body = %s", mcpRec.Code, mcpRec.Body.String())
		}
		if capturedSPIFFEID != "spiffe://poc.local/external/test-tool" {
			t.Errorf("SPIFFE ID = %q, want spiffe://poc.local/external/test-tool", capturedSPIFFEID)
		}
		if capturedAuthMethod != "token_exchange" {
			t.Errorf("auth_method = %q, want token_exchange", capturedAuthMethod)
		}
	})

	t.Run("expired exchange token is rejected by SPIFFEAuth", func(t *testing.T) {
		// Mint an already-expired token.
		spiffeID := "spiffe://poc.local/external/test-tool"
		token, err := mintExchangeToken(spiffeID, 1*time.Second, []byte(testSigningKey), func() time.Time {
			return time.Now().Add(-2 * time.Hour)
		})
		if err != nil {
			t.Fatal(err)
		}

		signingKey := []byte(testSigningKey)
		validator := func(tokenStr string) (*middleware.ExchangeTokenClaims, error) {
			claims, err := ValidateExchangeToken(tokenStr, signingKey)
			if err != nil {
				return nil, err
			}
			return &middleware.ExchangeTokenClaims{
				Sub:        claims.Sub,
				AuthMethod: claims.PrecinctAuthMethod,
			}, nil
		}

		innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("inner handler should not be called for expired token")
		})

		spiffeAuth := middleware.SPIFFEAuth(
			innerHandler,
			"dev",
			middleware.WithExchangeTokenValidator(validator),
		)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		spiffeAuth.ServeHTTP(rec, req)

		// With an expired token, the exchange validator returns an error,
		// so it falls through. Without OAuth or X-SPIFFE-ID, dev mode returns 401.
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body = %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("full flow: exchange -> use token -> endpoint", func(t *testing.T) {
		// This test simulates the complete user journey:
		// 1. External tool calls POST /v1/auth/token-exchange with credential
		// 2. Gets back a JWT
		// 3. Uses that JWT as Bearer token to call an MCP endpoint
		// 4. The gateway middleware chain accepts the token and routes the request

		// Build a mini server with both the exchange endpoint and a protected endpoint.
		exchangeHandler := tokenExchangeHandler(cfg)
		signingKey := []byte(testSigningKey)

		var capturedSPIFFEID string
		var capturedAuthMethod string
		protectedEndpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedSPIFFEID = middleware.GetSPIFFEID(r.Context())
			capturedAuthMethod = middleware.GetAuthMethod(r.Context())
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":[]},"id":1}`))
		})

		validator := func(tokenStr string) (*middleware.ExchangeTokenClaims, error) {
			claims, err := ValidateExchangeToken(tokenStr, signingKey)
			if err != nil {
				return nil, err
			}
			return &middleware.ExchangeTokenClaims{
				Sub:        claims.Sub,
				AuthMethod: claims.PrecinctAuthMethod,
			}, nil
		}

		protectedWithAuth := middleware.SPIFFEAuth(
			protectedEndpoint,
			"dev",
			middleware.WithExchangeTokenValidator(validator),
		)

		mux := http.NewServeMux()
		mux.Handle("/v1/auth/token-exchange", exchangeHandler)
		mux.Handle("/", protectedWithAuth)

		server := httptest.NewServer(mux)
		defer server.Close()

		// Step 1: Exchange credential.
		exchangeBody, _ := json.Marshal(TokenExchangeRequest{
			CredentialType: "api_key",
			Credential:     "monitoring-key-001",
		})
		exchangeResp, err := http.Post(server.URL+"/v1/auth/token-exchange", "application/json", bytes.NewReader(exchangeBody))
		if err != nil {
			t.Fatalf("exchange request failed: %v", err)
		}
		defer exchangeResp.Body.Close()

		if exchangeResp.StatusCode != http.StatusOK {
			t.Fatalf("exchange status = %d, want 200", exchangeResp.StatusCode)
		}

		var tokenResp TokenExchangeResponse
		json.NewDecoder(exchangeResp.Body).Decode(&tokenResp)

		// Step 2: Use token to call protected endpoint (simulating tools/list).
		mcpReq, _ := http.NewRequest(http.MethodPost, server.URL+"/", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
		mcpReq.Header.Set("Authorization", "Bearer "+tokenResp.Token)
		mcpReq.Header.Set("Content-Type", "application/json")

		mcpResp, err := http.DefaultClient.Do(mcpReq)
		if err != nil {
			t.Fatalf("MCP request failed: %v", err)
		}
		defer mcpResp.Body.Close()

		if mcpResp.StatusCode != http.StatusOK {
			t.Fatalf("MCP status = %d, want 200", mcpResp.StatusCode)
		}

		if capturedSPIFFEID != "spiffe://poc.local/external/monitoring-agent" {
			t.Errorf("SPIFFE ID = %q, want spiffe://poc.local/external/monitoring-agent", capturedSPIFFEID)
		}
		if capturedAuthMethod != "token_exchange" {
			t.Errorf("auth_method = %q, want token_exchange", capturedAuthMethod)
		}
	})
}

func TestDefaultPublicRouteAllowlistIncludesTokenExchange(t *testing.T) {
	// Verify that the default public route allowlist includes the token exchange endpoint.
	allowlist := parsePublicRouteAllowlist(defaultPublicRouteAllowlist)
	if _, ok := allowlist["/v1/auth/token-exchange"]; !ok {
		t.Fatal("defaultPublicRouteAllowlist should include /v1/auth/token-exchange")
	}
}

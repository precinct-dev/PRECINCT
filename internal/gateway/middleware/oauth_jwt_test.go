package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateOAuthJWT(t *testing.T) {
	issuer := newTestOAuthIssuer(t)
	cfg := issuer.Config()

	t.Run("ValidToken", func(t *testing.T) {
		token := issuer.MustMintToken(t, map[string]any{
			"iss":   issuer.URL,
			"sub":   "integration-user",
			"aud":   "gateway",
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"iat":   time.Now().Add(-1 * time.Minute).Unix(),
			"scope": "mcp:tools extra",
		})

		claims, err := ValidateOAuthJWT(context.Background(), token, cfg)
		if err != nil {
			t.Fatalf("ValidateOAuthJWT() error = %v", err)
		}
		if claims.Subject != "integration-user" {
			t.Fatalf("Subject = %q, want integration-user", claims.Subject)
		}
		if claims.Issuer != issuer.URL {
			t.Fatalf("Issuer = %q, want %q", claims.Issuer, issuer.URL)
		}
		if !strings.Contains(strings.Join(claims.Scopes, " "), "mcp:tools") {
			t.Fatalf("Scopes = %v, want mcp:tools", claims.Scopes)
		}
	})

	t.Run("RejectsWrongIssuer", func(t *testing.T) {
		token := issuer.MustMintToken(t, map[string]any{
			"iss":   "https://evil.example",
			"sub":   "integration-user",
			"aud":   "gateway",
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"scope": "mcp:tools",
		})

		if _, err := ValidateOAuthJWT(context.Background(), token, cfg); err == nil {
			t.Fatal("expected issuer validation failure")
		}
	})

	t.Run("RejectsWrongAudience", func(t *testing.T) {
		token := issuer.MustMintToken(t, map[string]any{
			"iss":   issuer.URL,
			"sub":   "integration-user",
			"aud":   "other-audience",
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"scope": "mcp:tools",
		})

		if _, err := ValidateOAuthJWT(context.Background(), token, cfg); err == nil {
			t.Fatal("expected audience validation failure")
		}
	})

	t.Run("RejectsExpiredBeyondSkew", func(t *testing.T) {
		token := issuer.MustMintToken(t, map[string]any{
			"iss":   issuer.URL,
			"sub":   "integration-user",
			"aud":   "gateway",
			"exp":   time.Now().Add(-2 * time.Minute).Unix(),
			"scope": "mcp:tools",
		})

		if _, err := ValidateOAuthJWT(context.Background(), token, cfg); err == nil {
			t.Fatal("expected expiry validation failure")
		}
	})

	t.Run("AllowsClockSkewWindow", func(t *testing.T) {
		token := issuer.MustMintToken(t, map[string]any{
			"iss":   issuer.URL,
			"sub":   "integration-user",
			"aud":   "gateway",
			"exp":   time.Now().Add(-10 * time.Second).Unix(),
			"scope": "mcp:tools",
		})

		if _, err := ValidateOAuthJWT(context.Background(), token, cfg); err != nil {
			t.Fatalf("expected token within skew window to validate, got %v", err)
		}
	})

	t.Run("RejectsInvalidSignature", func(t *testing.T) {
		token := issuer.MustMintToken(t, map[string]any{
			"iss":   issuer.URL,
			"sub":   "integration-user",
			"aud":   "gateway",
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"scope": "mcp:tools",
		})
		token = tamperJWTClaimsWithoutResigning(t, token, map[string]any{
			"sub": "tampered-user",
		})

		if _, err := ValidateOAuthJWT(context.Background(), token, cfg); err == nil {
			t.Fatal("expected signature validation failure")
		}
	})
}

func TestSPIFFEAuthBearerJWT(t *testing.T) {
	issuer := newTestOAuthIssuer(t)
	cfg := issuer.Config()

	mustMint := func(subject string) string {
		return issuer.MustMintToken(t, map[string]any{
			"iss":   issuer.URL,
			"sub":   subject,
			"aud":   "gateway",
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"scope": "mcp:tools",
		})
	}

	t.Run("DevModeAcceptsBearerWithoutSPIFFEHeader", func(t *testing.T) {
		var gotSPIFFEID string
		var gotAuthMethod string
		var gotIssuer string
		var gotScopes []string
		var authHeader string

		handler := SPIFFEAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotSPIFFEID = GetSPIFFEID(r.Context())
			gotAuthMethod = GetAuthMethod(r.Context())
			gotIssuer = GetOAuthIssuer(r.Context())
			gotScopes = GetOAuthScopes(r.Context())
			authHeader = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		}), "dev", WithOAuthJWTConfig(&cfg, "poc.local"))

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer "+mustMint("external-user"))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if gotSPIFFEID != "spiffe://poc.local/external/external-user" {
			t.Fatalf("SPIFFE ID = %q", gotSPIFFEID)
		}
		if gotAuthMethod != "oauth_jwt" {
			t.Fatalf("AuthMethod = %q, want oauth_jwt", gotAuthMethod)
		}
		if gotIssuer != issuer.URL {
			t.Fatalf("Issuer = %q, want %q", gotIssuer, issuer.URL)
		}
		if authHeader != "" {
			t.Fatalf("Authorization header was not stripped, got %q", authHeader)
		}
		if len(gotScopes) != 1 || gotScopes[0] != "mcp:tools" {
			t.Fatalf("Scopes = %v, want [mcp:tools]", gotScopes)
		}
	})

	t.Run("ProdModeAllowsBearerWithoutTLSClientCert", func(t *testing.T) {
		var gotSPIFFEID string
		handler := SPIFFEAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotSPIFFEID = GetSPIFFEID(r.Context())
			w.WriteHeader(http.StatusOK)
		}), "prod", WithOAuthJWTConfig(&cfg, "poc.local"))

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer "+mustMint("prod-external"))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if gotSPIFFEID != "spiffe://poc.local/external/prod-external" {
			t.Fatalf("SPIFFE ID = %q", gotSPIFFEID)
		}
	})

	t.Run("InvalidBearerFailsClosed", func(t *testing.T) {
		handler := SPIFFEAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), "dev", WithOAuthJWTConfig(&cfg, "poc.local"))

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer not-a-jwt")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		var ge GatewayError
		if err := json.Unmarshal(rec.Body.Bytes(), &ge); err != nil {
			t.Fatalf("decode GatewayError: %v", err)
		}
		if ge.Code != ErrAuthInvalidBearerToken {
			t.Fatalf("error code = %q, want %q", ge.Code, ErrAuthInvalidBearerToken)
		}
	})
}

type testOAuthIssuer struct {
	*httptest.Server
	kid string
	key []byte
}

func tamperJWTClaimsWithoutResigning(t *testing.T, token string, overrides map[string]any) string {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT with 3 segments, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	for key, value := range overrides {
		claims[key] = value
	}

	modifiedPayload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal modified payload: %v", err)
	}

	parts[1] = base64.RawURLEncoding.EncodeToString(modifiedPayload)
	return strings.Join(parts, ".")
}

func newTestOAuthIssuer(t *testing.T) *testOAuthIssuer {
	t.Helper()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	issuer := &testOAuthIssuer{
		kid: "test-kid",
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

func (i *testOAuthIssuer) Config() OAuthJWTConfig {
	return OAuthJWTConfig{
		Issuer:           i.URL,
		Audience:         "gateway",
		JWKSURL:          i.URL + "/jwks.json",
		RequiredScopes:   []string{"mcp:tools"},
		ClockSkewSeconds: 30,
		CacheTTLSeconds:  60,
		HTTPClient:       i.Client(),
	}
}

func (i *testOAuthIssuer) MustMintToken(t *testing.T, claims map[string]any) string {
	t.Helper()

	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
		"kid": i.kid,
	}

	headerJSON, err := json.Marshal(header)
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

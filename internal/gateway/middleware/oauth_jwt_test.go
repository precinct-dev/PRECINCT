// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
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

	// CVE-2015-9235 algorithm-confusion tests: an attacker who knows the
	// JWKS public key (which is public by design) forges a JWT using HMAC
	// with the public key bytes as the symmetric secret.
	t.Run("RejectsHS256WithPublicKeyAsHMACSecret", func(t *testing.T) {
		pubDER, err := x509.MarshalPKIXPublicKey(&issuer.privKey.PublicKey)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		forged := mintForgedHMACToken(t, "HS256", pubDER, issuer.kid, map[string]any{
			"iss":   issuer.URL,
			"sub":   "attacker",
			"aud":   "gateway",
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"scope": "mcp:tools",
		})

		_, err = ValidateOAuthJWT(context.Background(), forged, cfg)
		if err == nil {
			t.Fatal("expected HS256 algorithm-confusion token to be rejected")
		}
		if !strings.Contains(err.Error(), "parse signed jwt") {
			t.Fatalf("expected parse-time rejection, got: %v", err)
		}
	})

	t.Run("RejectsHS384Token", func(t *testing.T) {
		pubDER, err := x509.MarshalPKIXPublicKey(&issuer.privKey.PublicKey)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		forged := mintForgedHMACToken(t, "HS384", pubDER, issuer.kid, map[string]any{
			"iss":   issuer.URL,
			"sub":   "attacker",
			"aud":   "gateway",
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"scope": "mcp:tools",
		})

		_, err = ValidateOAuthJWT(context.Background(), forged, cfg)
		if err == nil {
			t.Fatal("expected HS384 token to be rejected")
		}
		if !strings.Contains(err.Error(), "parse signed jwt") {
			t.Fatalf("expected parse-time rejection, got: %v", err)
		}
	})

	t.Run("RejectsHS512Token", func(t *testing.T) {
		pubDER, err := x509.MarshalPKIXPublicKey(&issuer.privKey.PublicKey)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		forged := mintForgedHMACToken(t, "HS512", pubDER, issuer.kid, map[string]any{
			"iss":   issuer.URL,
			"sub":   "attacker",
			"aud":   "gateway",
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"scope": "mcp:tools",
		})

		_, err = ValidateOAuthJWT(context.Background(), forged, cfg)
		if err == nil {
			t.Fatal("expected HS512 token to be rejected")
		}
		if !strings.Contains(err.Error(), "parse signed jwt") {
			t.Fatalf("expected parse-time rejection, got: %v", err)
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
	kid     string
	privKey *rsa.PrivateKey
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

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	issuer := &testOAuthIssuer{
		kid:     "test-kid",
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

// mintForgedHMACToken creates a JWT signed with an HMAC algorithm using the
// given secret bytes. This is used to test algorithm-confusion rejection
// (CVE-2015-9235): the attacker uses the JWKS public key as the HMAC secret.
func mintForgedHMACToken(t *testing.T, alg string, secret []byte, kid string, claims map[string]any) string {
	t.Helper()

	header := map[string]any{
		"alg": alg,
		"typ": "JWT",
		"kid": kid,
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

	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + signature
}

package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIntrospectToken_ActiveToken(t *testing.T) {
	srv := newTestIntrospectionServer(t, introspectionResponse{
		Active:   true,
		Sub:      "opaque-user",
		Aud:      "gateway",
		Scope:    "mcp:tools admin",
		ClientID: "test-client",
		Exp:      time.Now().Add(5 * time.Minute).Unix(),
		Iss:      "http://issuer.local",
	})

	cfg := OAuthIntrospectionConfig{
		IntrospectionURL: srv.URL + "/introspect",
		RequiredAudience: "gateway",
		HTTPClient:       srv.Client(),
	}

	claims, err := IntrospectToken(context.Background(), "opaque-test-token", cfg)
	if err != nil {
		t.Fatalf("IntrospectToken() error = %v", err)
	}
	if claims.Subject != "opaque-user" {
		t.Fatalf("Subject = %q, want opaque-user", claims.Subject)
	}
	if claims.Issuer != "http://issuer.local" {
		t.Fatalf("Issuer = %q, want http://issuer.local", claims.Issuer)
	}
	if claims.Audience != "gateway" {
		t.Fatalf("Audience = %q, want gateway", claims.Audience)
	}
	if claims.ClientID != "test-client" {
		t.Fatalf("ClientID = %q, want test-client", claims.ClientID)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "mcp:tools" || claims.Scopes[1] != "admin" {
		t.Fatalf("Scopes = %v, want [mcp:tools admin]", claims.Scopes)
	}
}

func TestIntrospectToken_InactiveToken(t *testing.T) {
	srv := newTestIntrospectionServer(t, introspectionResponse{
		Active: false,
	})

	cfg := OAuthIntrospectionConfig{
		IntrospectionURL: srv.URL + "/introspect",
		HTTPClient:       srv.Client(),
	}

	_, err := IntrospectToken(context.Background(), "inactive-token", cfg)
	if err == nil {
		t.Fatal("expected error for inactive token")
	}
	if got := err.Error(); got != "introspection: token is not active" {
		t.Fatalf("error = %q, want 'introspection: token is not active'", got)
	}
}

func TestIntrospectToken_ExpiredToken(t *testing.T) {
	srv := newTestIntrospectionServer(t, introspectionResponse{
		Active: true,
		Sub:    "user",
		Aud:    "gateway",
		Exp:    time.Now().Add(-10 * time.Minute).Unix(),
	})

	cfg := OAuthIntrospectionConfig{
		IntrospectionURL: srv.URL + "/introspect",
		HTTPClient:       srv.Client(),
	}

	_, err := IntrospectToken(context.Background(), "expired-token", cfg)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if got := err.Error(); !strings.Contains(got, "token expired") {
		t.Fatalf("error = %q, want token expired", got)
	}
}

func TestIntrospectToken_WrongAudience(t *testing.T) {
	srv := newTestIntrospectionServer(t, introspectionResponse{
		Active: true,
		Sub:    "user",
		Aud:    "wrong-audience",
		Exp:    time.Now().Add(5 * time.Minute).Unix(),
	})

	cfg := OAuthIntrospectionConfig{
		IntrospectionURL: srv.URL + "/introspect",
		RequiredAudience: "gateway",
		HTTPClient:       srv.Client(),
	}

	_, err := IntrospectToken(context.Background(), "wrong-aud-token", cfg)
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
	if got := err.Error(); !strings.Contains(got, "unexpected audience") {
		t.Fatalf("error = %q, want 'unexpected audience'", got)
	}
}

func TestIntrospectToken_MissingSubject(t *testing.T) {
	srv := newTestIntrospectionServer(t, introspectionResponse{
		Active: true,
		Sub:    "",
		Aud:    "gateway",
		Exp:    time.Now().Add(5 * time.Minute).Unix(),
	})

	cfg := OAuthIntrospectionConfig{
		IntrospectionURL: srv.URL + "/introspect",
		HTTPClient:       srv.Client(),
	}

	_, err := IntrospectToken(context.Background(), "no-sub-token", cfg)
	if err == nil {
		t.Fatal("expected error for missing sub claim")
	}
	if got := err.Error(); !strings.Contains(got, "sub claim is required") {
		t.Fatalf("error = %q, want 'sub claim is required'", got)
	}
}

func TestIntrospectToken_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	cfg := OAuthIntrospectionConfig{
		IntrospectionURL: srv.URL + "/introspect",
		HTTPClient:       srv.Client(),
	}

	_, err := IntrospectToken(context.Background(), "some-token", cfg)
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if got := err.Error(); !strings.Contains(got, "status 500") {
		t.Fatalf("error = %q, want 'status 500'", got)
	}
}

func TestIntrospectToken_MissingURL(t *testing.T) {
	cfg := OAuthIntrospectionConfig{}
	_, err := IntrospectToken(context.Background(), "token", cfg)
	if err == nil {
		t.Fatal("expected error for missing introspection URL")
	}
}

func TestIntrospectToken_ClientCredentials(t *testing.T) {
	var gotAuthHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(introspectionResponse{
			Active: true,
			Sub:    "user",
			Aud:    "gateway",
			Exp:    time.Now().Add(5 * time.Minute).Unix(),
		})
	}))
	t.Cleanup(srv.Close)

	t.Setenv("TEST_INTRO_CLIENT_ID", "my-client")
	t.Setenv("TEST_INTRO_CLIENT_SECRET", "my-secret")

	cfg := OAuthIntrospectionConfig{
		IntrospectionURL:          srv.URL + "/introspect",
		IntrospectionClientIDEnv:  "TEST_INTRO_CLIENT_ID",
		IntrospectionClientSecEnv: "TEST_INTRO_CLIENT_SECRET",
		HTTPClient:                srv.Client(),
	}

	_, err := IntrospectToken(context.Background(), "some-token", cfg)
	if err != nil {
		t.Fatalf("IntrospectToken() error = %v", err)
	}
	if gotAuthHeader == "" {
		t.Fatal("expected Authorization header with Basic auth credentials")
	}
	if !strings.Contains(gotAuthHeader, "Basic") {
		t.Fatalf("Authorization = %q, want Basic auth", gotAuthHeader)
	}
}

func TestIntrospectToken_NoCredentialsNoAuth(t *testing.T) {
	var gotAuthHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(introspectionResponse{
			Active: true,
			Sub:    "user",
			Aud:    "gateway",
			Exp:    time.Now().Add(5 * time.Minute).Unix(),
		})
	}))
	t.Cleanup(srv.Close)

	cfg := OAuthIntrospectionConfig{
		IntrospectionURL: srv.URL + "/introspect",
		HTTPClient:       srv.Client(),
	}

	_, err := IntrospectToken(context.Background(), "some-token", cfg)
	if err != nil {
		t.Fatalf("IntrospectToken() error = %v", err)
	}
	if gotAuthHeader != "" {
		t.Fatalf("expected no Authorization header, got %q", gotAuthHeader)
	}
}

func TestIsNotJWTError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		expect bool
	}{
		{
			name:   "NilError",
			err:    nil,
			expect: false,
		},
		{
			name: "NotAJWT",
			err: func() error {
				_, err := ValidateOAuthJWT(context.Background(), "opaque-token-not-jwt", OAuthJWTConfig{
					Issuer:   "http://test",
					Audience: "test",
					JWKSURL:  "http://test/jwks",
				})
				return err
			}(),
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNotJWTError(tt.err); got != tt.expect {
				t.Fatalf("isNotJWTError() = %v, want %v (err = %v)", got, tt.expect, tt.err)
			}
		})
	}
}

func TestOAuthIntrospectionConfig_IsConfigured(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		var cfg *OAuthIntrospectionConfig
		if cfg.IsConfigured() {
			t.Fatal("expected false for nil config")
		}
	})
	t.Run("EmptyURL", func(t *testing.T) {
		cfg := &OAuthIntrospectionConfig{}
		if cfg.IsConfigured() {
			t.Fatal("expected false for empty URL")
		}
	})
	t.Run("Configured", func(t *testing.T) {
		cfg := &OAuthIntrospectionConfig{IntrospectionURL: "http://example/introspect"}
		if !cfg.IsConfigured() {
			t.Fatal("expected true for configured URL")
		}
	})
}

func TestSPIFFEAuthBearerIntrospection(t *testing.T) {
	issuer := newTestOAuthIssuer(t)
	jwtCfg := issuer.Config()

	// Add introspection endpoint to the test issuer's server.
	introSrv := newTestIntrospectionServer(t, introspectionResponse{
		Active:   true,
		Sub:      "opaque-subject",
		Aud:      "gateway",
		Scope:    "mcp:tools",
		ClientID: "test-client",
		Exp:      time.Now().Add(5 * time.Minute).Unix(),
		Iss:      issuer.URL,
	})

	jwtCfg.IntrospectionURL = introSrv.URL + "/introspect"
	jwtCfg.IntrospectionRequiredAud = "gateway"

	t.Run("OpaqueTokenFallsBackToIntrospection", func(t *testing.T) {
		var gotSPIFFEID string
		var gotAuthMethod string
		var gotIssuer string
		var gotScopes []string

		handler := SPIFFEAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotSPIFFEID = GetSPIFFEID(r.Context())
			gotAuthMethod = GetAuthMethod(r.Context())
			gotIssuer = GetOAuthIssuer(r.Context())
			gotScopes = GetOAuthScopes(r.Context())
			w.WriteHeader(http.StatusOK)
		}), "dev", WithOAuthJWTConfig(&jwtCfg, "poc.local"))

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer opaque-not-a-jwt-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		if gotSPIFFEID != "spiffe://poc.local/external/opaque-subject" {
			t.Fatalf("SPIFFE ID = %q, want spiffe://poc.local/external/opaque-subject", gotSPIFFEID)
		}
		if gotAuthMethod != "oauth_introspection" {
			t.Fatalf("AuthMethod = %q, want oauth_introspection", gotAuthMethod)
		}
		if gotIssuer != issuer.URL {
			t.Fatalf("Issuer = %q, want %q", gotIssuer, issuer.URL)
		}
		if len(gotScopes) != 1 || gotScopes[0] != "mcp:tools" {
			t.Fatalf("Scopes = %v, want [mcp:tools]", gotScopes)
		}
	})

	t.Run("ValidJWTDoesNotTriggerIntrospection", func(t *testing.T) {
		var gotAuthMethod string

		handler := SPIFFEAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuthMethod = GetAuthMethod(r.Context())
			w.WriteHeader(http.StatusOK)
		}), "dev", WithOAuthJWTConfig(&jwtCfg, "poc.local"))

		jwt := issuer.MustMintToken(t, map[string]any{
			"iss":   issuer.URL,
			"sub":   "jwt-user",
			"aud":   "gateway",
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"scope": "mcp:tools",
		})

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if gotAuthMethod != "oauth_jwt" {
			t.Fatalf("AuthMethod = %q, want oauth_jwt (not introspection)", gotAuthMethod)
		}
	})

	t.Run("InvalidJWTDoesNotFallbackToIntrospection", func(t *testing.T) {
		// A token that IS a valid JWT structure but has wrong issuer
		// should fail immediately without trying introspection.
		handler := SPIFFEAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), "dev", WithOAuthJWTConfig(&jwtCfg, "poc.local"))

		jwt := issuer.MustMintToken(t, map[string]any{
			"iss":   "https://evil.example",
			"sub":   "evil-user",
			"aud":   "gateway",
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"scope": "mcp:tools",
		})

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (JWT with wrong issuer should fail, not fallback)", rec.Code)
		}
	})

	t.Run("OpaqueTokenIntrospectionFailsClosedWith401", func(t *testing.T) {
		inactiveIntroSrv := newTestIntrospectionServer(t, introspectionResponse{
			Active: false,
		})
		cfgWithInactive := jwtCfg
		cfgWithInactive.IntrospectionURL = inactiveIntroSrv.URL + "/introspect"

		handler := SPIFFEAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), "dev", WithOAuthJWTConfig(&cfgWithInactive, "poc.local"))

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer opaque-inactive-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("NoIntrospectionConfiguredOpaqueTokenFails", func(t *testing.T) {
		cfgNoIntro := issuer.Config()
		// No introspection URL set

		handler := SPIFFEAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), "dev", WithOAuthJWTConfig(&cfgNoIntro, "poc.local"))

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "Bearer opaque-no-introspection")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (no introspection configured)", rec.Code)
		}
	})
}

func newTestIntrospectionServer(t *testing.T, response introspectionResponse) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(srv.Close)
	return srv
}

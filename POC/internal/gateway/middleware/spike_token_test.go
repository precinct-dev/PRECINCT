package middleware

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseSPIKEToken(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      *SPIKEToken
		wantError bool
	}{
		{
			name:  "valid token with all fields",
			input: "$SPIKE{ref:abc123,exp:3600,scope:read}",
			want: &SPIKEToken{
				Ref:   "abc123",
				Exp:   3600,
				Scope: "read",
			},
			wantError: false,
		},
		{
			name:  "valid token with only ref",
			input: "$SPIKE{ref:deadbeef}",
			want: &SPIKEToken{
				Ref:   "deadbeef",
				Exp:   0,
				Scope: "",
			},
			wantError: false,
		},
		{
			name:  "valid token with ref and exp",
			input: "$SPIKE{ref:1a2b3c,exp:7200}",
			want: &SPIKEToken{
				Ref:   "1a2b3c",
				Exp:   7200,
				Scope: "",
			},
			wantError: false,
		},
		{
			name:      "invalid - missing ref",
			input:     "$SPIKE{exp:3600,scope:read}",
			want:      nil,
			wantError: true,
		},
		{
			name:      "invalid - wrong prefix",
			input:     "$TOKEN{ref:abc123,exp:3600}",
			want:      nil,
			wantError: true,
		},
		{
			name:      "invalid - malformed",
			input:     "$SPIKE{invalid}",
			want:      nil,
			wantError: true,
		},
		{
			name:      "invalid - non-hex ref",
			input:     "$SPIKE{ref:xyz123,exp:3600}",
			want:      nil,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSPIKEToken(tt.input)
			if tt.wantError {
				if err == nil {
					t.Errorf("ParseSPIKEToken() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Errorf("ParseSPIKEToken() error = %v, want nil", err)
				return
			}
			if got.Ref != tt.want.Ref || got.Exp != tt.want.Exp || got.Scope != tt.want.Scope {
				t.Errorf("ParseSPIKEToken() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestValidateTokenOwnership(t *testing.T) {
	token := &SPIKEToken{
		Ref:      "abc123",
		Exp:      3600,
		Scope:    "read",
		OwnerID:  "spiffe://poc.local/agent/test-agent",
		IssuedAt: time.Now().Unix(),
	}

	tests := []struct {
		name      string
		spiffeID  string
		wantError bool
	}{
		{
			name:      "valid - owner matches",
			spiffeID:  "spiffe://poc.local/agent/test-agent",
			wantError: false,
		},
		{
			name:      "invalid - owner mismatch",
			spiffeID:  "spiffe://poc.local/agent/other-agent",
			wantError: true,
		},
		{
			name:      "invalid - empty spiffe ID",
			spiffeID:  "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTokenOwnership(token, tt.spiffeID)
			if tt.wantError && err == nil {
				t.Errorf("ValidateTokenOwnership() error = nil, want error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("ValidateTokenOwnership() error = %v, want nil", err)
			}
		})
	}
}

func TestValidateTokenOwnership_EmptyOwnerID(t *testing.T) {
	// RFA-7ct: Tokens with empty OwnerID must be rejected.
	// Previously, the POC auto-assigned OwnerID to the caller, allowing
	// any agent to claim ownership of an unclaimed token.
	tests := []struct {
		name      string
		token     *SPIKEToken
		spiffeID  string
		wantError error
	}{
		{
			name: "reject empty OwnerID - prevents unauthorized claiming",
			token: &SPIKEToken{
				Ref:      "abc123",
				Exp:      3600,
				Scope:    "read",
				OwnerID:  "", // Empty: simulates token without SPIKE Nexus pre-population
				IssuedAt: time.Now().Unix(),
			},
			spiffeID:  "spiffe://poc.local/agent/attacker",
			wantError: ErrEmptyOwnerID,
		},
		{
			name: "reject empty OwnerID - even for legitimate agent",
			token: &SPIKEToken{
				Ref:      "def456",
				Exp:      7200,
				Scope:    "tools.docker.read",
				OwnerID:  "", // Empty: must be rejected regardless of who calls
				IssuedAt: time.Now().Unix(),
			},
			spiffeID:  "spiffe://poc.local/agent/legitimate-agent",
			wantError: ErrEmptyOwnerID,
		},
		{
			name: "accept token with pre-populated OwnerID matching caller",
			token: &SPIKEToken{
				Ref:      "abc123",
				Exp:      3600,
				Scope:    "read",
				OwnerID:  "spiffe://poc.local/agent/legitimate-agent",
				IssuedAt: time.Now().Unix(),
			},
			spiffeID:  "spiffe://poc.local/agent/legitimate-agent",
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTokenOwnership(tt.token, tt.spiffeID)
			if tt.wantError != nil {
				if err == nil {
					t.Fatalf("ValidateTokenOwnership() = nil, want error %v", tt.wantError)
				}
				if !errors.Is(err, tt.wantError) {
					t.Errorf("ValidateTokenOwnership() error = %v, want %v", err, tt.wantError)
				}
				// Verify OwnerID was NOT mutated (the old bug would set it)
				if tt.token.OwnerID != "" {
					t.Errorf("Token OwnerID was mutated to %q, should remain empty", tt.token.OwnerID)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateTokenOwnership() error = %v, want nil", err)
				}
			}
		})
	}
}

func TestValidateTokenExpiry(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		name      string
		token     *SPIKEToken
		wantError bool
	}{
		{
			name: "valid - not expired",
			token: &SPIKEToken{
				Ref:      "abc123",
				Exp:      3600,
				IssuedAt: now,
			},
			wantError: false,
		},
		{
			name: "valid - no expiry set",
			token: &SPIKEToken{
				Ref:      "abc123",
				Exp:      0,
				IssuedAt: now,
			},
			wantError: false,
		},
		{
			name: "invalid - expired",
			token: &SPIKEToken{
				Ref:      "abc123",
				Exp:      10,
				IssuedAt: now - 20,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTokenExpiry(tt.token)
			if tt.wantError && err == nil {
				t.Errorf("ValidateTokenExpiry() error = nil, want error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("ValidateTokenExpiry() error = %v, want nil", err)
			}
		})
	}
}

func TestValidateTokenScope(t *testing.T) {
	token := &SPIKEToken{
		Ref:   "abc123",
		Scope: "tools.docker.read",
	}

	tests := []struct {
		name         string
		location     string
		operation    string
		destination  string
		wantError    bool
		errorMessage string
	}{
		{
			name:        "valid - exact scope match",
			location:    "tools",
			operation:   "docker",
			destination: "read",
			wantError:   false,
		},
		{
			name:        "invalid - location mismatch",
			location:    "secrets",
			operation:   "docker",
			destination: "read",
			wantError:   true,
		},
		{
			name:        "invalid - operation mismatch",
			location:    "tools",
			operation:   "kubectl",
			destination: "read",
			wantError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTokenScope(token, tt.location, tt.operation, tt.destination)
			if tt.wantError && err == nil {
				t.Errorf("ValidateTokenScope() error = nil, want error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("ValidateTokenScope() error = %v, want nil", err)
			}
		})
	}
}

func TestFindSPIKETokens(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "single token",
			input: `{"key": "$SPIKE{ref:abc123,exp:3600}"}`,
			want:  []string{"$SPIKE{ref:abc123,exp:3600}"},
		},
		{
			name:  "multiple tokens",
			input: `{"key1": "$SPIKE{ref:abc123}", "key2": "$SPIKE{ref:def456,exp:7200}"}`,
			want:  []string{"$SPIKE{ref:abc123}", "$SPIKE{ref:def456,exp:7200}"},
		},
		{
			name:  "no tokens",
			input: `{"key": "value"}`,
			want:  nil,
		},
		{
			name:  "token in header value",
			input: "Authorization: Bearer $SPIKE{ref:deadbeef,exp:3600,scope:api}",
			want:  []string{"$SPIKE{ref:deadbeef,exp:3600,scope:api}"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindSPIKETokens(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("FindSPIKETokens() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("FindSPIKETokens()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// Mock SecretRedeemer for testing
type mockSecretRedeemer struct {
	redeemFunc func(ctx context.Context, token *SPIKEToken) (*SPIKESecret, error)
}

func (m *mockSecretRedeemer) RedeemSecret(ctx context.Context, token *SPIKEToken) (*SPIKESecret, error) {
	if m.redeemFunc != nil {
		return m.redeemFunc(ctx, token)
	}
	return nil, errors.New("not implemented")
}

func TestSecretRedeemer(t *testing.T) {
	now := time.Now().Unix()
	token := &SPIKEToken{
		Ref:      "abc123",
		Exp:      3600,
		Scope:    "tools.docker.read",
		OwnerID:  "spiffe://poc.local/agent/test-agent",
		IssuedAt: now,
	}

	t.Run("successful redemption", func(t *testing.T) {
		mockRedeemer := &mockSecretRedeemer{
			redeemFunc: func(ctx context.Context, token *SPIKEToken) (*SPIKESecret, error) {
				return &SPIKESecret{
					Value:     "actual-secret-value",
					ExpiresAt: now + 3600,
				}, nil
			},
		}

		secret, err := mockRedeemer.RedeemSecret(context.Background(), token)
		if err != nil {
			t.Errorf("RedeemSecret() error = %v, want nil", err)
		}
		if secret.Value != "actual-secret-value" {
			t.Errorf("RedeemSecret() value = %v, want %v", secret.Value, "actual-secret-value")
		}
	})

	t.Run("redemption failure", func(t *testing.T) {
		mockRedeemer := &mockSecretRedeemer{
			redeemFunc: func(ctx context.Context, token *SPIKEToken) (*SPIKESecret, error) {
				return nil, errors.New("token not found")
			},
		}

		_, err := mockRedeemer.RedeemSecret(context.Background(), token)
		if err == nil {
			t.Errorf("RedeemSecret() error = nil, want error")
		}
	})
}

func TestSubstituteTokens(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		tokens    map[string]string
		want      string
		wantError bool
	}{
		{
			name:  "single substitution",
			input: `{"api_key": "$SPIKE{ref:abc123}"}`,
			tokens: map[string]string{
				"$SPIKE{ref:abc123}": "actual-secret-123",
			},
			want:      `{"api_key": "actual-secret-123"}`,
			wantError: false,
		},
		{
			name:  "multiple substitutions",
			input: `{"key1": "$SPIKE{ref:abc123}", "key2": "$SPIKE{ref:def456}"}`,
			tokens: map[string]string{
				"$SPIKE{ref:abc123}": "secret-1",
				"$SPIKE{ref:def456}": "secret-2",
			},
			want:      `{"key1": "secret-1", "key2": "secret-2"}`,
			wantError: false,
		},
		{
			name:      "no tokens",
			input:     `{"key": "value"}`,
			tokens:    map[string]string{},
			want:      `{"key": "value"}`,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SubstituteTokens(tt.input, tt.tokens)
			if got != tt.want {
				t.Errorf("SubstituteTokens() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestTokenSubstitutionWithScopeResolver verifies that the TokenSubstitution
// middleware uses the ScopeResolver for dynamic scope validation. RFA-0gr.
func TestTokenSubstitutionWithScopeResolver(t *testing.T) {
	ownerSPIFFEID := "spiffe://poc.local/agent/test-agent"

	// Create a mock scope resolver for tests
	type mockScopeResolver struct {
		scopes map[string]struct{ loc, op, dest string }
	}

	resolveFn := func(m *mockScopeResolver, toolName string) (string, string, string, bool) {
		if s, ok := m.scopes[toolName]; ok {
			return s.loc, s.op, s.dest, true
		}
		return "", "", "", false
	}

	t.Run("scope match - tool in registry with matching token scope", func(t *testing.T) {
		resolver := &mockScopeResolver{
			scopes: map[string]struct{ loc, op, dest string }{
				"tools/call": {loc: "tools", op: "docker", dest: "read"},
			},
		}

		echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		})

		// Use a scopeResolver adapter since interface requires a method
		adaptedResolver := &testScopeResolverAdapter{resolveFn: func(toolName string) (string, string, string, bool) {
			return resolveFn(resolver, toolName)
		}}

		// Build middleware chain: BodyCapture -> SPIFFEAuth -> TokenSubstitution -> Echo
		var handler http.Handler = echoHandler
		handler = TokenSubstitution(handler, NewPOCSecretRedeemerWithOwner(ownerSPIFFEID), nil, adaptedResolver)
		handler = SPIFFEAuth(handler, "dev")
		handler = BodyCapture(handler)

		// MCP request body: the method is "tools/call" which matches the resolver
		requestBody := `{"jsonrpc":"2.0","method":"tools/call","params":{"tool":"docker_tool"},"id":1,"api_key":"$SPIKE{ref:abc123,exp:3600,scope:tools.docker.read}"}`
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(requestBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SPIFFE-ID", ownerSPIFFEID)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		// Token should be substituted
		body := rr.Body.String()
		if !strings.Contains(body, "secret-value-for-abc123") {
			t.Errorf("Expected substituted secret, got: %s", body)
		}
	})

	t.Run("scope mismatch - tool requires different scope than token has", func(t *testing.T) {
		resolver := &mockScopeResolver{
			scopes: map[string]struct{ loc, op, dest string }{
				"tools/call": {loc: "tools", op: "s3", dest: "write"},
			},
		}

		echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		adaptedResolver := &testScopeResolverAdapter{resolveFn: func(toolName string) (string, string, string, bool) {
			return resolveFn(resolver, toolName)
		}}

		var handler http.Handler = echoHandler
		handler = TokenSubstitution(handler, NewPOCSecretRedeemerWithOwner(ownerSPIFFEID), nil, adaptedResolver)
		handler = SPIFFEAuth(handler, "dev")
		handler = BodyCapture(handler)

		// Token has scope "tools.docker.read" but registry requires "tools.s3.write"
		requestBody := `{"jsonrpc":"2.0","method":"tools/call","params":{},"id":1,"api_key":"$SPIKE{ref:abc123,exp:3600,scope:tools.docker.read}"}`
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(requestBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SPIFFE-ID", ownerSPIFFEID)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected 403 for scope mismatch, got %d: %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "token_scope_failed") {
			t.Errorf("Expected token_scope_failed error, got: %s", rr.Body.String())
		}
	})

	t.Run("tool not in resolver - scope validation is permissive", func(t *testing.T) {
		resolver := &mockScopeResolver{
			scopes: map[string]struct{ loc, op, dest string }{}, // empty - no tools registered
		}

		echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		})

		adaptedResolver := &testScopeResolverAdapter{resolveFn: func(toolName string) (string, string, string, bool) {
			return resolveFn(resolver, toolName)
		}}

		var handler http.Handler = echoHandler
		handler = TokenSubstitution(handler, NewPOCSecretRedeemerWithOwner(ownerSPIFFEID), nil, adaptedResolver)
		handler = SPIFFEAuth(handler, "dev")
		handler = BodyCapture(handler)

		// Tool not in resolver -- scope validation should be skipped (permissive)
		requestBody := `{"jsonrpc":"2.0","method":"unknown_tool","params":{},"id":1,"api_key":"$SPIKE{ref:abc123,exp:3600,scope:anything.goes.here}"}`
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(requestBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SPIFFE-ID", ownerSPIFFEID)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200 (permissive when tool not in resolver), got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("nil scope resolver - scope validation completely skipped", func(t *testing.T) {
		echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		})

		var handler http.Handler = echoHandler
		handler = TokenSubstitution(handler, NewPOCSecretRedeemerWithOwner(ownerSPIFFEID), nil, nil)
		handler = SPIFFEAuth(handler, "dev")
		handler = BodyCapture(handler)

		// With nil resolver, scope validation is completely skipped regardless of token scope
		requestBody := `{"jsonrpc":"2.0","method":"any_tool","params":{},"id":1,"api_key":"$SPIKE{ref:abc123,exp:3600,scope:any.scope.here}"}`
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(requestBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SPIFFE-ID", ownerSPIFFEID)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200 (nil resolver), got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// testScopeResolverAdapter adapts a function to the ScopeResolver interface for testing.
type testScopeResolverAdapter struct {
	resolveFn func(toolName string) (string, string, string, bool)
}

func (a *testScopeResolverAdapter) ResolveScope(toolName string) (string, string, string, bool) {
	return a.resolveFn(toolName)
}

func TestTokenSubstitutionAudit(t *testing.T) {
	event := &TokenSubstitutionEvent{
		TokenRef:    "abc123",
		SpiffeID:    "spiffe://poc.local/agent/test-agent",
		Scope:       "tools.docker.read",
		Destination: "docker-registry",
		Success:     true,
		Timestamp:   time.Now().Unix(),
	}

	// Verify that the event does not contain the actual secret value
	if event.SecretValue != "" {
		t.Errorf("TokenSubstitutionEvent contains secret value, should be empty for security")
	}

	// Verify required fields are present
	if event.TokenRef == "" {
		t.Errorf("TokenSubstitutionEvent missing TokenRef")
	}
	if event.SpiffeID == "" {
		t.Errorf("TokenSubstitutionEvent missing SpiffeID")
	}
	if event.Timestamp == 0 {
		t.Errorf("TokenSubstitutionEvent missing Timestamp")
	}
}

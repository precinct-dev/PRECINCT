package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestOPAInput_AuthMethodField verifies that auth_method is always present in OPA input JSON.
func TestOPAInput_AuthMethodField(t *testing.T) {
	tests := []struct {
		name       string
		authMethod string
		wantJSON   string
	}{
		{
			name:       "header_declared",
			authMethod: "header_declared",
			wantJSON:   `"auth_method":"header_declared"`,
		},
		{
			name:       "mtls_svid",
			authMethod: "mtls_svid",
			wantJSON:   `"auth_method":"mtls_svid"`,
		},
		{
			name:       "oauth_jwt",
			authMethod: "oauth_jwt",
			wantJSON:   `"auth_method":"oauth_jwt"`,
		},
		{
			name:       "oauth_introspection",
			authMethod: "oauth_introspection",
			wantJSON:   `"auth_method":"oauth_introspection"`,
		},
		{
			name:       "token_exchange",
			authMethod: "token_exchange",
			wantJSON:   `"auth_method":"token_exchange"`,
		},
		{
			name:       "empty_when_not_set",
			authMethod: "",
			wantJSON:   `"auth_method":""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := OPAInput{
				SPIFFEID:   "spiffe://poc.local/agents/test",
				Tool:       "some_tool",
				Action:     "execute",
				AuthMethod: tt.authMethod,
			}

			data, err := json.Marshal(input)
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}

			if !strings.Contains(string(data), tt.wantJSON) {
				t.Errorf("expected JSON to contain %s, got: %s", tt.wantJSON, string(data))
			}
		})
	}
}

// TestOPAInput_OAuthFieldsSerialization verifies oauth_scopes and oauth_issuer
// are present when set, and omitted when empty (omitempty).
func TestOPAInput_OAuthFieldsSerialization(t *testing.T) {
	t.Run("oauth_fields_present_for_bearer_auth", func(t *testing.T) {
		input := OPAInput{
			SPIFFEID:    "spiffe://poc.local/agents/test",
			Tool:        "some_tool",
			Action:      "execute",
			AuthMethod:  "oauth_jwt",
			OAuthScopes: []string{"tools:read", "tools:execute"},
			OAuthIssuer: "https://idp.example.com",
		}

		data, err := json.Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		var decoded map[string]interface{}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		// Verify auth_method
		if am, ok := decoded["auth_method"].(string); !ok || am != "oauth_jwt" {
			t.Errorf("expected auth_method=oauth_jwt, got %v", decoded["auth_method"])
		}

		// Verify oauth_scopes
		scopes, ok := decoded["oauth_scopes"].([]interface{})
		if !ok {
			t.Fatal("expected oauth_scopes field in JSON")
		}
		if len(scopes) != 2 {
			t.Errorf("expected 2 scopes, got %d", len(scopes))
		}
		if s, ok := scopes[0].(string); !ok || s != "tools:read" {
			t.Errorf("expected first scope=tools:read, got %v", scopes[0])
		}
		if s, ok := scopes[1].(string); !ok || s != "tools:execute" {
			t.Errorf("expected second scope=tools:execute, got %v", scopes[1])
		}

		// Verify oauth_issuer
		if iss, ok := decoded["oauth_issuer"].(string); !ok || iss != "https://idp.example.com" {
			t.Errorf("expected oauth_issuer=https://idp.example.com, got %v", decoded["oauth_issuer"])
		}
	})

	t.Run("oauth_fields_omitted_for_spiffe_auth", func(t *testing.T) {
		input := OPAInput{
			SPIFFEID:   "spiffe://poc.local/agents/test",
			Tool:       "some_tool",
			Action:     "execute",
			AuthMethod: "mtls_svid",
			// No OAuthScopes or OAuthIssuer
		}

		data, err := json.Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		jsonStr := string(data)
		if strings.Contains(jsonStr, `"oauth_scopes"`) {
			t.Errorf("expected oauth_scopes to be omitted for SPIFFE auth, got: %s", jsonStr)
		}
		if strings.Contains(jsonStr, `"oauth_issuer"`) {
			t.Errorf("expected oauth_issuer to be omitted for SPIFFE auth, got: %s", jsonStr)
		}
		// auth_method should still be present
		if !strings.Contains(jsonStr, `"auth_method":"mtls_svid"`) {
			t.Errorf("expected auth_method to be present, got: %s", jsonStr)
		}
	})

	t.Run("oauth_fields_omitted_for_header_declared", func(t *testing.T) {
		input := OPAInput{
			SPIFFEID:   "spiffe://poc.local/agents/test",
			Tool:       "some_tool",
			Action:     "execute",
			AuthMethod: "header_declared",
		}

		data, err := json.Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		jsonStr := string(data)
		if strings.Contains(jsonStr, `"oauth_scopes"`) {
			t.Errorf("expected oauth_scopes to be omitted for header_declared auth, got: %s", jsonStr)
		}
		if strings.Contains(jsonStr, `"oauth_issuer"`) {
			t.Errorf("expected oauth_issuer to be omitted for header_declared auth, got: %s", jsonStr)
		}
	})
}

// TestOPAPolicy_SPIFFEDevRequest_NoOAuthFields is an integration test verifying
// that a SPIFFE dev request (header_declared auth) produces OPA input with
// auth_method set but no oauth_scopes or oauth_issuer.
func TestOPAPolicy_SPIFFEDevRequest_NoOAuthFields(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	// Capture the OPA input by wrapping the engine
	var capturedInput OPAInput
	capturer := &opaInputCapturer{
		inner:    engine,
		captured: &capturedInput,
	}

	handlerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := OPAPolicy(inner, capturer)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"some_tool","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.Background()
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test")
	ctx = WithAuthMethod(ctx, "header_declared")
	ctx = WithPrincipalRole(ctx, PrincipalRole{
		Level:        1,
		Role:         "owner",
		Capabilities: []string{"admin", "read", "write", "execute"},
	})
	ctx = WithRequestBody(ctx, []byte(body))
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if !handlerCalled {
		t.Error("handler should have been called")
	}

	// Verify OPA input fields
	if capturedInput.AuthMethod != "header_declared" {
		t.Errorf("expected auth_method=header_declared, got %q", capturedInput.AuthMethod)
	}
	if len(capturedInput.OAuthScopes) != 0 {
		t.Errorf("expected no oauth_scopes for SPIFFE dev request, got %v", capturedInput.OAuthScopes)
	}
	if capturedInput.OAuthIssuer != "" {
		t.Errorf("expected no oauth_issuer for SPIFFE dev request, got %q", capturedInput.OAuthIssuer)
	}
}

// TestOPAPolicy_OAuthJWTRequest_WithOAuthFields is an integration test verifying
// that an OAuth JWT request produces OPA input with auth_method, oauth_scopes,
// and oauth_issuer all populated from context.
func TestOPAPolicy_OAuthJWTRequest_WithOAuthFields(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	var capturedInput OPAInput
	capturer := &opaInputCapturer{
		inner:    engine,
		captured: &capturedInput,
	}

	handlerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := OPAPolicy(inner, capturer)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"some_tool","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.Background()
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test")
	ctx = WithAuthMethod(ctx, "oauth_jwt")
	ctx = WithOAuthScopes(ctx, []string{"tools:read", "tools:execute", "admin:write"})
	ctx = WithOAuthIssuer(ctx, "https://idp.example.com")
	ctx = WithPrincipalRole(ctx, PrincipalRole{
		Level:        3,
		Role:         "agent",
		Capabilities: []string{"read", "execute"},
	})
	ctx = WithRequestBody(ctx, []byte(body))
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if !handlerCalled {
		t.Error("handler should have been called")
	}

	// Verify OPA input fields
	if capturedInput.AuthMethod != "oauth_jwt" {
		t.Errorf("expected auth_method=oauth_jwt, got %q", capturedInput.AuthMethod)
	}
	if len(capturedInput.OAuthScopes) != 3 {
		t.Errorf("expected 3 oauth_scopes, got %d: %v", len(capturedInput.OAuthScopes), capturedInput.OAuthScopes)
	} else {
		expectedScopes := []string{"tools:read", "tools:execute", "admin:write"}
		for i, scope := range expectedScopes {
			if capturedInput.OAuthScopes[i] != scope {
				t.Errorf("expected oauth_scopes[%d]=%q, got %q", i, scope, capturedInput.OAuthScopes[i])
			}
		}
	}
	if capturedInput.OAuthIssuer != "https://idp.example.com" {
		t.Errorf("expected oauth_issuer=https://idp.example.com, got %q", capturedInput.OAuthIssuer)
	}
}

// TestOPAPolicy_MTLSSVIDRequest_NoOAuthFields verifies that mTLS SVID
// authentication produces OPA input with auth_method=mtls_svid and no
// OAuth claim fields.
func TestOPAPolicy_MTLSSVIDRequest_NoOAuthFields(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	var capturedInput OPAInput
	capturer := &opaInputCapturer{
		inner:    engine,
		captured: &capturedInput,
	}

	handlerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := OPAPolicy(inner, capturer)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"some_tool","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.Background()
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test")
	ctx = WithAuthMethod(ctx, "mtls_svid")
	ctx = WithPrincipalRole(ctx, PrincipalRole{
		Level:        2,
		Role:         "delegated_admin",
		Capabilities: []string{"read", "write"},
	})
	ctx = WithRequestBody(ctx, []byte(body))
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if !handlerCalled {
		t.Error("handler should have been called")
	}

	if capturedInput.AuthMethod != "mtls_svid" {
		t.Errorf("expected auth_method=mtls_svid, got %q", capturedInput.AuthMethod)
	}
	if len(capturedInput.OAuthScopes) != 0 {
		t.Errorf("expected no oauth_scopes for mTLS SVID, got %v", capturedInput.OAuthScopes)
	}
	if capturedInput.OAuthIssuer != "" {
		t.Errorf("expected no oauth_issuer for mTLS SVID, got %q", capturedInput.OAuthIssuer)
	}
}

// TestOPAPolicy_OAuthIntrospection_WithOAuthFields verifies that opaque token
// (introspection) auth produces OPA input with auth_method=oauth_introspection
// and OAuth claim fields populated.
func TestOPAPolicy_OAuthIntrospection_WithOAuthFields(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	var capturedInput OPAInput
	capturer := &opaInputCapturer{
		inner:    engine,
		captured: &capturedInput,
	}

	handlerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := OPAPolicy(inner, capturer)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"some_tool","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.Background()
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test")
	ctx = WithAuthMethod(ctx, "oauth_introspection")
	ctx = WithOAuthScopes(ctx, []string{"tools:read"})
	ctx = WithOAuthIssuer(ctx, "https://auth.internal.example.com")
	ctx = WithPrincipalRole(ctx, PrincipalRole{
		Level:        3,
		Role:         "agent",
		Capabilities: []string{"read"},
	})
	ctx = WithRequestBody(ctx, []byte(body))
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if !handlerCalled {
		t.Error("handler should have been called")
	}

	if capturedInput.AuthMethod != "oauth_introspection" {
		t.Errorf("expected auth_method=oauth_introspection, got %q", capturedInput.AuthMethod)
	}
	if len(capturedInput.OAuthScopes) != 1 || capturedInput.OAuthScopes[0] != "tools:read" {
		t.Errorf("expected oauth_scopes=[tools:read], got %v", capturedInput.OAuthScopes)
	}
	if capturedInput.OAuthIssuer != "https://auth.internal.example.com" {
		t.Errorf("expected oauth_issuer=https://auth.internal.example.com, got %q", capturedInput.OAuthIssuer)
	}
}

// TestOPAPolicy_TokenExchange_WithOAuthFields verifies token_exchange auth method
// propagation.
func TestOPAPolicy_TokenExchange_WithOAuthFields(t *testing.T) {
	engine := setupPrincipalTestEngine(t)

	var capturedInput OPAInput
	capturer := &opaInputCapturer{
		inner:    engine,
		captured: &capturedInput,
	}

	handlerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := OPAPolicy(inner, capturer)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"some_tool","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.Background()
	ctx = WithSPIFFEID(ctx, "spiffe://poc.local/agents/test")
	ctx = WithAuthMethod(ctx, "token_exchange")
	ctx = WithOAuthScopes(ctx, []string{"delegated:execute"})
	ctx = WithOAuthIssuer(ctx, "https://sts.example.com")
	ctx = WithPrincipalRole(ctx, PrincipalRole{
		Level:        3,
		Role:         "agent",
		Capabilities: []string{"execute"},
	})
	ctx = WithRequestBody(ctx, []byte(body))
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if !handlerCalled {
		t.Error("handler should have been called")
	}

	if capturedInput.AuthMethod != "token_exchange" {
		t.Errorf("expected auth_method=token_exchange, got %q", capturedInput.AuthMethod)
	}
	if len(capturedInput.OAuthScopes) != 1 || capturedInput.OAuthScopes[0] != "delegated:execute" {
		t.Errorf("expected oauth_scopes=[delegated:execute], got %v", capturedInput.OAuthScopes)
	}
	if capturedInput.OAuthIssuer != "https://sts.example.com" {
		t.Errorf("expected oauth_issuer=https://sts.example.com, got %q", capturedInput.OAuthIssuer)
	}
}

// TestOPAInput_OAuthFieldsInOPAEvaluation verifies that the new OAuth claim
// fields are visible to OPA policy evaluation (i.e., they survive JSON
// marshaling through the OPA input pipeline).
func TestOPAInput_OAuthFieldsInOPAEvaluation(t *testing.T) {
	input := OPAInput{
		SPIFFEID:    "spiffe://poc.local/agents/test",
		Tool:        "some_tool",
		Action:      "execute",
		Method:      "POST",
		Path:        "/mcp",
		Params:      map[string]interface{}{},
		Session:     SessionInput{RiskScore: 0.0, PreviousActions: []ToolAction{}},
		AuthMethod:  "oauth_jwt",
		OAuthScopes: []string{"tools:read", "tools:execute"},
		OAuthIssuer: "https://idp.example.com",
	}

	// Marshal and unmarshal to simulate OPA input pipeline
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	// Verify all three fields are present
	if am, ok := decoded["auth_method"].(string); !ok || am != "oauth_jwt" {
		t.Errorf("expected auth_method=oauth_jwt, got %v", decoded["auth_method"])
	}

	scopes, ok := decoded["oauth_scopes"].([]interface{})
	if !ok {
		t.Fatal("expected oauth_scopes field in decoded JSON")
	}
	if len(scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(scopes))
	}

	if iss, ok := decoded["oauth_issuer"].(string); !ok || iss != "https://idp.example.com" {
		t.Errorf("expected oauth_issuer=https://idp.example.com, got %v", decoded["oauth_issuer"])
	}
}

// opaInputCapturer wraps an OPAEvaluator to capture the OPAInput passed to Evaluate.
// Used by integration tests to verify OPA input construction from context.
type opaInputCapturer struct {
	inner    OPAEvaluator
	captured *OPAInput
}

func (c *opaInputCapturer) Evaluate(input OPAInput) (bool, string, error) {
	*c.captured = input
	return c.inner.Evaluate(input)
}

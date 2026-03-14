// +build integration

package integration

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

// TestTokenSubstitutionMiddleware_FullFlow tests the complete token substitution flow
func TestTokenSubstitutionMiddleware_FullFlow(t *testing.T) {
	// Create a test handler that echoes the request body
	echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	// Build middleware chain: BodyCapture -> SPIFFEAuth -> TokenSubstitution -> Echo
	var handler http.Handler = echoHandler
	handler = middleware.TokenSubstitution(handler, middleware.NewPOCSecretRedeemerWithOwner("spiffe://poc.local/agent/test-agent"), nil, nil)
	handler = middleware.SPIFFEAuth(handler, "dev")
	handler = middleware.BodyCapture(handler)

	tests := []struct {
		name           string
		requestBody    string
		spiffeID       string
		expectedStatus int
		expectedBody   string
		shouldContain  bool
	}{
		{
			name:           "successful single token substitution",
			requestBody:    `{"api_key": "$SPIKE{ref:abc123,exp:3600,scope:tools.docker.read}"}`,
			spiffeID:       "spiffe://poc.local/agent/test-agent",
			expectedStatus: http.StatusOK,
			expectedBody:   "secret-value-for-abc123",
			shouldContain:  true,
		},
		{
			name:           "successful multiple token substitution",
			requestBody:    `{"key1": "$SPIKE{ref:abc123}", "key2": "$SPIKE{ref:def456}"}`,
			spiffeID:       "spiffe://poc.local/agent/test-agent",
			expectedStatus: http.StatusOK,
			expectedBody:   "secret-value-for-abc123",
			shouldContain:  true,
		},
		{
			name:           "no tokens - pass through",
			requestBody:    `{"api_key": "plain-text-key"}`,
			spiffeID:       "spiffe://poc.local/agent/test-agent",
			expectedStatus: http.StatusOK,
			expectedBody:   "plain-text-key",
			shouldContain:  true,
		},
		{
			name:           "malformed token - pass through (not a valid SPIKE token)",
			requestBody:    `{"api_key": "$SPIKE{invalid}"}`,
			spiffeID:       "spiffe://poc.local/agent/test-agent",
			expectedStatus: http.StatusOK,
			expectedBody:   "$SPIKE{invalid}", // Not a valid token, passes through unchanged
			shouldContain:  true,
		},
		{
			name:           "missing SPIFFE ID",
			requestBody:    `{"api_key": "$SPIKE{ref:abc123}"}`,
			spiffeID:       "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Missing X-SPIFFE-ID header",
			shouldContain:  true,
		},
		{
			name:           "token with expiry",
			requestBody:    `{"api_key": "$SPIKE{ref:fade1234,exp:3600}"}`,
			spiffeID:       "spiffe://poc.local/agent/test-agent",
			expectedStatus: http.StatusOK, // POC sets IssuedAt to now, so 3600s from now is not expired
			expectedBody:   "secret-value-for-fade1234",
			shouldContain:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			if tt.spiffeID != "" {
				req.Header.Set("X-SPIFFE-ID", tt.spiffeID)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Verify status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					rr.Code, tt.expectedStatus)
			}

			// Verify body content
			body := rr.Body.String()
			if tt.shouldContain && !strings.Contains(body, tt.expectedBody) {
				t.Errorf("handler returned unexpected body: got %v, want to contain %v",
					body, tt.expectedBody)
			}

			// Verify that VALID tokens are substituted (check by seeing if expected secret is present)
			// Invalid tokens (like $SPIKE{invalid}) will pass through unchanged
			if tt.expectedStatus == http.StatusOK && strings.Contains(tt.expectedBody, "secret-value-for-") {
				// This was a valid token that should have been substituted
				if strings.Contains(body, "$SPIKE{ref:") {
					t.Errorf("handler returned body with unsubstituted valid token: %v", body)
				}
			}
		})
	}
}

// TestTokenSubstitutionMiddleware_TokenParsing tests token parsing edge cases
func TestTokenSubstitutionMiddleware_TokenParsing(t *testing.T) {
	echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	var handler http.Handler = echoHandler
	handler = middleware.TokenSubstitution(handler, middleware.NewPOCSecretRedeemerWithOwner("spiffe://poc.local/agent/test-agent"), nil, nil)
	handler = middleware.SPIFFEAuth(handler, "dev")
	handler = middleware.BodyCapture(handler)

	tests := []struct {
		name           string
		requestBody    string
		expectedStatus int
	}{
		{
			name:           "hex ref only",
			requestBody:    `{"key": "$SPIKE{ref:deadbeef}"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "hex ref with expiry",
			requestBody:    `{"key": "$SPIKE{ref:1a2b3c,exp:7200}"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "hex ref with scope",
			requestBody:    `{"key": "$SPIKE{ref:abc123,scope:tools.docker.read}"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "all fields",
			requestBody:    `{"key": "$SPIKE{ref:abc123,exp:3600,scope:tools.docker.read}"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "non-hex ref - not matched as token",
			requestBody:    `{"key": "$SPIKE{ref:xyz123}"}`,
			expectedStatus: http.StatusOK, // Regex requires hex, so this doesn't match and passes through
		},
		{
			name:           "missing ref - not matched as token",
			requestBody:    `{"key": "$SPIKE{exp:3600}"}`,
			expectedStatus: http.StatusOK, // ref is required by regex, so this doesn't match and passes through
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agent/test-agent")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("handler returned wrong status code for %s: got %v want %v",
					tt.name, rr.Code, tt.expectedStatus)
			}
		})
	}
}

// TestTokenSubstitutionMiddleware_AuditLogging tests that audit logs are created
func TestTokenSubstitutionMiddleware_AuditLogging(t *testing.T) {
	echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Build handler chain (audit logging happens via stdout for POC)
	var handler http.Handler = echoHandler
	handler = middleware.TokenSubstitution(handler, middleware.NewPOCSecretRedeemerWithOwner("spiffe://poc.local/agent/test-agent"), nil, nil)
	handler = middleware.SPIFFEAuth(handler, "dev")
	handler = middleware.BodyCapture(handler)

	// Test successful substitution
	requestBody := `{"api_key": "$SPIKE{ref:abc123}"}`
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agent/test-agent")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Verify status
	if rr.Code != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
	}

	// Note: In a real integration test with composed services, we would:
	// 1. Query the audit log endpoint or database
	// 2. Verify that the log entry exists
	// 3. Verify that the secret value is NOT in the log
	// For this POC, we verify the middleware runs without error and logs to stdout
}

// TestTokenSubstitutionMiddleware_SecretNotLeaked tests that secrets are never leaked in logs or errors
func TestTokenSubstitutionMiddleware_SecretNotLeaked(t *testing.T) {
	echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Echo the body back - this simulates the upstream service receiving the secret
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	var handler http.Handler = echoHandler
	handler = middleware.TokenSubstitution(handler, middleware.NewPOCSecretRedeemerWithOwner("spiffe://poc.local/agent/test-agent"), nil, nil)
	handler = middleware.SPIFFEAuth(handler, "dev")
	handler = middleware.BodyCapture(handler)

	// Test that secret is substituted but not leaked in errors
	requestBody := `{"api_key": "$SPIKE{ref:abc123,exp:3600}"}`
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agent/test-agent")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Verify the substituted secret reached the upstream (echo) handler
	body := rr.Body.String()
	if !strings.Contains(body, "secret-value-for-abc123") {
		t.Errorf("substituted secret not found in upstream request body: %v", body)
	}

	// Verify original token is not in the response
	if strings.Contains(body, "$SPIKE{") {
		t.Errorf("original token leaked in response: %v", body)
	}

	// Note: In production, we would also:
	// 1. Check audit logs to ensure secret value is not logged (for POC, we log to stdout without secrets)
	// 2. Verify error messages never contain secret values
	// 3. Verify HTTP error responses never contain secret values
}

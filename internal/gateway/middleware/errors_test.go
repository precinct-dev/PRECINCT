package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWriteGatewayError_Serialization verifies that WriteGatewayError produces
// correct JSON with Content-Type application/json.
func TestWriteGatewayError_Serialization(t *testing.T) {
	rec := httptest.NewRecorder()
	ctx := context.Background()
	ctx = WithDecisionID(ctx, "dec-123")
	ctx = WithTraceID(ctx, "trace-456")
	req := httptest.NewRequest("POST", "/", nil).WithContext(ctx)

	ge := GatewayError{
		Code:           ErrDLPCredentialsDetected,
		Message:        "Request contains sensitive credentials",
		Middleware:     "dlp_scan",
		MiddlewareStep: 7,
		Remediation:    "Remove credentials from the request body.",
	}

	WriteGatewayError(rec, req, http.StatusForbidden, ge)

	// Check HTTP status
	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", rec.Code)
	}

	// Check Content-Type
	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %q", ct)
	}

	// Parse response body
	var result GatewayError
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response body: %v", err)
	}

	// Verify required fields
	if result.Code != ErrDLPCredentialsDetected {
		t.Errorf("Expected code %q, got %q", ErrDLPCredentialsDetected, result.Code)
	}
	if result.Message != "Request contains sensitive credentials" {
		t.Errorf("Expected message %q, got %q", "Request contains sensitive credentials", result.Message)
	}
	if result.Middleware != "dlp_scan" {
		t.Errorf("Expected middleware %q, got %q", "dlp_scan", result.Middleware)
	}
	if result.MiddlewareStep != 7 {
		t.Errorf("Expected middleware_step 7, got %d", result.MiddlewareStep)
	}
	if result.DecisionID != "dec-123" {
		t.Errorf("Expected decision_id %q, got %q", "dec-123", result.DecisionID)
	}
	if result.TraceID != "trace-456" {
		t.Errorf("Expected trace_id %q, got %q", "trace-456", result.TraceID)
	}
	if result.Remediation != "Remove credentials from the request body." {
		t.Errorf("Expected remediation %q, got %q", "Remove credentials from the request body.", result.Remediation)
	}
}

// TestWriteGatewayError_DecisionIDFromContext verifies decision_id and trace_id
// are populated from context when not explicitly set.
func TestWriteGatewayError_DecisionIDFromContext(t *testing.T) {
	rec := httptest.NewRecorder()
	ctx := context.Background()
	ctx = WithDecisionID(ctx, "ctx-decision-999")
	ctx = WithTraceID(ctx, "ctx-trace-888")
	req := httptest.NewRequest("POST", "/", nil).WithContext(ctx)

	ge := GatewayError{
		Code:           ErrAuthzPolicyDenied,
		Message:        "Policy denied: agent not authorized",
		Middleware:     "opa_policy",
		MiddlewareStep: 6,
	}

	WriteGatewayError(rec, req, http.StatusForbidden, ge)

	var result GatewayError
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if result.DecisionID != "ctx-decision-999" {
		t.Errorf("Expected decision_id from context, got %q", result.DecisionID)
	}
	if result.TraceID != "ctx-trace-888" {
		t.Errorf("Expected trace_id from context, got %q", result.TraceID)
	}
}

// TestWriteGatewayError_ExplicitIDsOverrideContext verifies that explicitly set
// IDs in the GatewayError are NOT overwritten by context values.
func TestWriteGatewayError_ExplicitIDsOverrideContext(t *testing.T) {
	rec := httptest.NewRecorder()
	ctx := context.Background()
	ctx = WithDecisionID(ctx, "context-dec")
	ctx = WithTraceID(ctx, "context-trace")
	req := httptest.NewRequest("POST", "/", nil).WithContext(ctx)

	ge := GatewayError{
		Code:           ErrCircuitOpen,
		Message:        "Circuit open",
		Middleware:     "circuit_breaker",
		MiddlewareStep: 12,
		DecisionID:     "explicit-dec",
		TraceID:        "explicit-trace",
	}

	WriteGatewayError(rec, req, http.StatusServiceUnavailable, ge)

	var result GatewayError
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if result.DecisionID != "explicit-dec" {
		t.Errorf("Expected explicit decision_id, got %q", result.DecisionID)
	}
	if result.TraceID != "explicit-trace" {
		t.Errorf("Expected explicit trace_id, got %q", result.TraceID)
	}
}

// TestWriteGatewayError_DetailsOmitEmpty verifies that the details field is
// omitted from JSON when nil.
func TestWriteGatewayError_DetailsOmitEmpty(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)

	ge := GatewayError{
		Code:           ErrRateLimitExceeded,
		Message:        "Rate limit exceeded",
		Middleware:     "rate_limit",
		MiddlewareStep: 11,
	}

	WriteGatewayError(rec, req, http.StatusTooManyRequests, ge)

	// Parse as raw map to check field presence
	var raw map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&raw); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if _, ok := raw["details"]; ok {
		t.Errorf("Expected details to be omitted when nil, but it was present")
	}
	if _, ok := raw["remediation"]; ok {
		t.Errorf("Expected remediation to be omitted when empty, but it was present")
	}
}

// TestWriteGatewayError_WithDetails verifies that details are included when set.
func TestWriteGatewayError_WithDetails(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)

	ge := GatewayError{
		Code:           ErrStepUpDenied,
		Message:        "Risk too high",
		Middleware:     "step_up_gating",
		MiddlewareStep: 9,
		Details: map[string]any{
			"gate":       "deny",
			"risk_score": 11,
		},
	}

	WriteGatewayError(rec, req, http.StatusForbidden, ge)

	var result GatewayError
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if result.Details == nil {
		t.Fatal("Expected details to be present")
	}
	if result.Details["gate"] != "deny" {
		t.Errorf("Expected details.gate=%q, got %v", "deny", result.Details["gate"])
	}
}

// TestWriteGatewayError_AllStatusCodes verifies WriteGatewayError works with
// each HTTP status code used by the error catalog.
func TestWriteGatewayError_AllStatusCodes(t *testing.T) {
	statusCodes := []struct {
		code    int
		errCode string
	}{
		{http.StatusUnauthorized, ErrAuthMissingIdentity},
		{http.StatusForbidden, ErrAuthzPolicyDenied},
		{http.StatusTooManyRequests, ErrRateLimitExceeded},
		{http.StatusServiceUnavailable, ErrCircuitOpen},
		{http.StatusRequestEntityTooLarge, ErrRequestTooLarge},
	}

	for _, tc := range statusCodes {
		t.Run(tc.errCode, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/", nil)

			ge := GatewayError{
				Code:           tc.errCode,
				Message:        "test",
				Middleware:     "test",
				MiddlewareStep: 1,
			}

			WriteGatewayError(rec, req, tc.code, ge)

			if rec.Code != tc.code {
				t.Errorf("Expected status %d, got %d", tc.code, rec.Code)
			}

			var result GatewayError
			if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}
			if result.Code != tc.errCode {
				t.Errorf("Expected code %q, got %q", tc.errCode, result.Code)
			}
		})
	}
}

// TestErrorCodes_Constants verifies all error code constants are non-empty
// and unique.
func TestErrorCodes_Constants(t *testing.T) {
	codes := []string{
		ErrAuthMissingIdentity,
		ErrAuthInvalidIdentity,
		ErrAuthzPolicyDenied,
		ErrAuthzNoMatchingGrant,
		ErrAuthzToolNotFound,
		ErrRegistryHashMismatch,
		ErrRegistryToolUnknown,
		ErrDLPCredentialsDetected,
		ErrDLPInjectionBlocked,
		ErrDLPPIIBlocked,
		ErrStepUpDenied,
		ErrStepUpApprovalRequired,
		ErrStepUpGuardBlocked,
		ErrStepUpDestinationBlocked,
		ErrDeepScanBlocked,
		ErrDeepScanUnavailableFailClosed,
		ErrRateLimitExceeded,
		ErrCircuitOpen,
		ErrRequestTooLarge,
		ErrExfiltrationDetected,
		ErrUICapabilityDenied,
		ErrUIResourceBlocked,
		ErrMCPTransportFailed,
		ErrMCPRequestFailed,
		ErrMCPInvalidResponse,
		ErrAuthTokenExpired,
		ErrAuthTokenInvalid,
		ErrAuthCredentialRejected,
	}

	seen := make(map[string]bool)
	for _, code := range codes {
		if code == "" {
			t.Error("Found empty error code constant")
		}
		if seen[code] {
			t.Errorf("Duplicate error code: %q", code)
		}
		seen[code] = true
	}

	if len(codes) != 28 {
		t.Errorf("Expected 28 error codes, got %d", len(codes))
	}
}

// TestGatewayError_JSONRoundTrip verifies the GatewayError can be serialized
// and deserialized without loss.
func TestGatewayError_JSONRoundTrip(t *testing.T) {
	original := GatewayError{
		Code:           ErrDLPCredentialsDetected,
		Message:        "Credentials found",
		Middleware:     "dlp_scan",
		MiddlewareStep: 7,
		DecisionID:     "dec-abc",
		TraceID:        "trace-xyz",
		Details:        map[string]any{"pattern": "aws_key"},
		Remediation:    "Remove the key",
		DocsURL:        "https://docs.example.com/dlp",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded GatewayError
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.Code != original.Code {
		t.Errorf("Code mismatch: %q vs %q", decoded.Code, original.Code)
	}
	if decoded.Message != original.Message {
		t.Errorf("Message mismatch")
	}
	if decoded.Middleware != original.Middleware {
		t.Errorf("Middleware mismatch")
	}
	if decoded.MiddlewareStep != original.MiddlewareStep {
		t.Errorf("MiddlewareStep mismatch")
	}
	if decoded.DecisionID != original.DecisionID {
		t.Errorf("DecisionID mismatch")
	}
	if decoded.TraceID != original.TraceID {
		t.Errorf("TraceID mismatch")
	}
	if decoded.Remediation != original.Remediation {
		t.Errorf("Remediation mismatch")
	}
	if decoded.DocsURL != original.DocsURL {
		t.Errorf("DocsURL mismatch")
	}
	if decoded.Details["pattern"] != "aws_key" {
		t.Errorf("Details.pattern mismatch")
	}
}

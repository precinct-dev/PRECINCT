package mcpgateway

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestGatewayError_Error_WithCodeAndMessage(t *testing.T) {
	ge := &GatewayError{Code: "authz_policy_denied", Message: "OPA policy denied access"}
	got := ge.Error()
	want := "gateway error authz_policy_denied: OPA policy denied access"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestGatewayError_Error_CodeOnly(t *testing.T) {
	ge := &GatewayError{Code: "ratelimit_exceeded"}
	got := ge.Error()
	want := "gateway error ratelimit_exceeded"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestGatewayError_Error_HTTPStatusOnly(t *testing.T) {
	ge := &GatewayError{HTTPStatus: 500}
	got := ge.Error()
	want := "gateway error (HTTP 500)"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestGatewayError_ImplementsErrorInterface(t *testing.T) {
	var err error = &GatewayError{Code: "test"}
	var ge *GatewayError
	if !errors.As(err, &ge) {
		t.Fatal("errors.As failed for *GatewayError")
	}
	if ge.Code != "test" {
		t.Errorf("Code = %q, want %q", ge.Code, "test")
	}
}

func TestGatewayError_JSONSerialization(t *testing.T) {
	ge := &GatewayError{
		Code:        "dlp_credentials_detected",
		Message:     "Credentials found in request",
		Middleware:   "dlp",
		Step:        7,
		DecisionID:  "dec-123",
		TraceID:     "trace-456",
		Details:     map[string]any{"pattern": "AWS_SECRET"},
		Remediation: "Remove credentials from the request body",
		DocsURL:     "https://docs.example.com/dlp",
		HTTPStatus:  403,
	}

	data, err := json.Marshal(ge)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Verify all envelope fields are present
	checks := map[string]any{
		"code":            "dlp_credentials_detected",
		"message":         "Credentials found in request",
		"middleware":       "dlp",
		"middleware_step": float64(7),
		"decision_id":     "dec-123",
		"trace_id":        "trace-456",
		"remediation":     "Remove credentials from the request body",
		"docs_url":        "https://docs.example.com/dlp",
	}
	for key, want := range checks {
		got, ok := parsed[key]
		if !ok {
			t.Errorf("missing key %q in JSON output", key)
			continue
		}
		if got != want {
			t.Errorf("key %q = %v, want %v", key, got, want)
		}
	}

	// HTTPStatus should NOT appear in JSON (json:"-" tag)
	if _, ok := parsed["HTTPStatus"]; ok {
		t.Error("HTTPStatus should not be serialized to JSON")
	}

	// Details should be present
	details, ok := parsed["details"].(map[string]any)
	if !ok {
		t.Fatal("details not present or wrong type")
	}
	if details["pattern"] != "AWS_SECRET" {
		t.Errorf("details.pattern = %v, want AWS_SECRET", details["pattern"])
	}
}

func TestGatewayError_JSONDeserialization(t *testing.T) {
	// Simulates parsing a gateway error response body
	raw := `{
		"code": "authz_policy_denied",
		"message": "OPA policy denied access",
		"middleware": "opa",
		"middleware_step": 6,
		"decision_id": "dec-789",
		"trace_id": "trace-abc",
		"details": {"policy": "default.allow"},
		"remediation": "Check OPA policy grants",
		"docs_url": "https://docs.example.com/authz"
	}`

	var ge GatewayError
	if err := json.Unmarshal([]byte(raw), &ge); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if ge.Code != "authz_policy_denied" {
		t.Errorf("Code = %q, want %q", ge.Code, "authz_policy_denied")
	}
	if ge.Message != "OPA policy denied access" {
		t.Errorf("Message = %q, want %q", ge.Message, "OPA policy denied access")
	}
	if ge.Middleware != "opa" {
		t.Errorf("Middleware = %q, want %q", ge.Middleware, "opa")
	}
	if ge.Step != 6 {
		t.Errorf("Step = %d, want %d", ge.Step, 6)
	}
	if ge.DecisionID != "dec-789" {
		t.Errorf("DecisionID = %q, want %q", ge.DecisionID, "dec-789")
	}
	if ge.TraceID != "trace-abc" {
		t.Errorf("TraceID = %q, want %q", ge.TraceID, "trace-abc")
	}
	if ge.Remediation != "Check OPA policy grants" {
		t.Errorf("Remediation = %q, want %q", ge.Remediation, "Check OPA policy grants")
	}
	if ge.Details["policy"] != "default.allow" {
		t.Errorf("Details[policy] = %v, want default.allow", ge.Details["policy"])
	}
}

func TestGatewayError_JSONOmitEmptyFields(t *testing.T) {
	ge := &GatewayError{
		Code:    "circuit_open",
		Message: "Circuit breaker is open",
	}

	data, err := json.Marshal(ge)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// These should be omitted when empty/nil
	for _, key := range []string{"details", "remediation", "docs_url"} {
		if v, ok := parsed[key]; ok && v != "" {
			t.Errorf("key %q should be omitted or empty, got %v", key, v)
		}
	}
}

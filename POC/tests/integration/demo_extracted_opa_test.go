//go:build integration
// +build integration

// Demo-extracted OPA policy integration tests.
// Extracts deterministic OPA assertions from demo/go/main.go into httptest-based
// integration tests using the embedded OPA engine with real policy files.
//
// Covers demo assertions:
// - SPIFFE auth denial (empty identity)       -- testAuthDenial
// - OPA policy denial (bash requires step-up) -- testOPADenial
// - Happy path (valid request, chain passes)  -- testHappyPath (positive path)

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
	"github.com/precinct-dev/PRECINCT/POC/internal/testutil"
)

// buildOPAChain constructs a middleware chain with real embedded OPA engine,
// real SPIFFE auth, and body capture. This exercises the actual policy files
// from config/opa/ without requiring a running OPA server.
func buildOPAChain(t *testing.T) http.Handler {
	t.Helper()

	policyDir := testutil.OPAPolicyDir()
	basePath := testutil.ProjectRoot()

	engine, err := middleware.NewOPAEngine(policyDir, middleware.OPAEngineConfig{
		AllowedBasePath: basePath,
	})
	if err != nil {
		t.Fatalf("Failed to create embedded OPA engine: %v", err)
	}
	t.Cleanup(func() { engine.Close() })

	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"reached_terminal"}`))
	})

	// Build chain: BodyCapture -> SPIFFEAuth -> OPA -> terminal
	handler := middleware.OPAPolicy(terminal, engine)
	handler = middleware.SPIFFEAuth(handler, "dev")
	handler = middleware.BodyCapture(handler)

	return handler
}

// opaMCPRequest builds a JSON-RPC tools/call request body for OPA testing.
func opaMCPRequest(tool string, params map[string]any) string {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      tool,
			"arguments": params,
		},
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

// ---------------------------------------------------------------------------
// Demo assertion: SPIFFE auth denial (empty identity)
// ---------------------------------------------------------------------------

// TestDemoExtracted_OPA_AuthDenialEmptyIdentity mirrors demo test "SPIFFE auth denial (empty identity)".
// Sends a request with NO X-SPIFFE-ID header. The SPIFFEAuth middleware should
// reject it with 401 before OPA is ever consulted.
func TestDemoExtracted_OPA_AuthDenialEmptyIdentity(t *testing.T) {
	handler := buildOPAChain(t)

	body := opaMCPRequest("read", map[string]any{"file_path": "/tmp/test"})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Intentionally omit X-SPIFFE-ID

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Expected HTTP 401 for missing SPIFFE ID, got %d: %s", rr.Code, rr.Body.String())
	}

	var ge middleware.GatewayError
	if err := json.Unmarshal(rr.Body.Bytes(), &ge); err != nil {
		t.Fatalf("Failed to parse error: %v", err)
	}
	if ge.Code != middleware.ErrAuthMissingIdentity {
		t.Errorf("Expected code=%s, got %s", middleware.ErrAuthMissingIdentity, ge.Code)
	}
	t.Logf("PASS: Empty SPIFFE ID denied with 401, code=%s", ge.Code)
}

// ---------------------------------------------------------------------------
// Demo assertion: OPA policy denial (bash requires step-up)
// ---------------------------------------------------------------------------

// TestDemoExtracted_OPA_BashDenied mirrors demo test "OPA policy denial (bash requires step-up)".
// bash is not in the researcher's allowed_tools in OPA policy, so it should be denied
// with 403 regardless of step-up token presence.
func TestDemoExtracted_OPA_BashDenied(t *testing.T) {
	handler := buildOPAChain(t)

	body := opaMCPRequest("bash", map[string]any{"command": "ls"})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("Expected HTTP 403 for bash tool (researcher), got %d: %s", rr.Code, rr.Body.String())
	}

	var ge middleware.GatewayError
	if err := json.Unmarshal(rr.Body.Bytes(), &ge); err != nil {
		t.Fatalf("Failed to parse error: %v", err)
	}
	if ge.Code != middleware.ErrAuthzPolicyDenied {
		t.Errorf("Expected code=%s, got %s", middleware.ErrAuthzPolicyDenied, ge.Code)
	}
	t.Logf("PASS: bash denied by OPA policy for researcher, code=%s", ge.Code)
}

// ---------------------------------------------------------------------------
// Demo assertion: Happy path (valid request passes OPA)
// ---------------------------------------------------------------------------

// TestDemoExtracted_OPA_HappyPath mirrors the positive path from demo test
// "Happy path (chain runs, reaches upstream)". A valid SPIFFE ID calling a
// permitted tool (read) with a valid path should pass through OPA.
func TestDemoExtracted_OPA_HappyPath(t *testing.T) {
	handler := buildOPAChain(t)

	basePath := testutil.ProjectRoot()
	body := opaMCPRequest("read", map[string]any{"file_path": basePath + "/README.md"})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Fatalf("Expected allowed request, got 403: %s", rr.Body.String())
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 for allowed request, got %d: %s", rr.Code, rr.Body.String())
	}
	t.Logf("PASS: Valid researcher+read passed OPA policy (HTTP %d)", rr.Code)
}

// ---------------------------------------------------------------------------
// Demo assertion: Unknown agent denial
// ---------------------------------------------------------------------------

// TestDemoExtracted_OPA_UnknownAgentDenied verifies that an unrecognized SPIFFE ID
// is denied by OPA policy. This is an additional OPA denial path tested in the
// existing gateway_integration_test.go but also exercised by the demo.
func TestDemoExtracted_OPA_UnknownAgentDenied(t *testing.T) {
	handler := buildOPAChain(t)

	basePath := testutil.ProjectRoot()
	body := opaMCPRequest("read", map[string]any{"file_path": basePath + "/README.md"})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/unknown/dev")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("Expected HTTP 403 for unknown agent, got %d: %s", rr.Code, rr.Body.String())
	}
	t.Logf("PASS: Unknown agent denied by OPA (HTTP %d)", rr.Code)
}

// ---------------------------------------------------------------------------
// Demo assertion: Path outside allowed base is denied
// ---------------------------------------------------------------------------

// TestDemoExtracted_OPA_PathOutsideBaseDenied verifies that reading files
// outside the allowed base path is denied by OPA policy.
func TestDemoExtracted_OPA_PathOutsideBaseDenied(t *testing.T) {
	handler := buildOPAChain(t)

	body := opaMCPRequest("read", map[string]any{"file_path": "/etc/passwd"})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("Expected HTTP 403 for path outside base, got %d: %s", rr.Code, rr.Body.String())
	}
	t.Logf("PASS: Path outside allowed base denied by OPA (HTTP %d)", rr.Code)
}

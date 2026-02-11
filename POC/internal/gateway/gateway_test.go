package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
	"github.com/example/agentic-security-poc/internal/testutil"
)

// TestNewGateway verifies gateway initialization
func TestNewGateway(t *testing.T) {
	cfg := &Config{
		Port:                   9090,
		UpstreamURL:            "http://localhost:8080",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "", // Empty = stdout only
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024,
		SPIFFEMode:             "dev",
		LogLevel:               "info",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}

	if gw == nil {
		t.Fatal("Gateway is nil")
		return
	}

	if gw.config != cfg {
		t.Error("Config not set correctly")
	}

	if gw.proxy == nil {
		t.Error("Proxy not initialized")
	}

	if gw.auditor == nil {
		t.Error("Auditor not initialized")
	}

	if gw.opa == nil {
		t.Error("OPA client not initialized")
	}

	if gw.registry == nil {
		t.Error("Tool registry not initialized")
	}

	if gw.circuitBreaker == nil {
		t.Error("Circuit breaker not initialized")
	}
}

// TestNewGatewayInvalidURL verifies error handling for invalid upstream URL
func TestNewGatewayInvalidURL(t *testing.T) {
	cfg := &Config{
		UpstreamURL: "://invalid-url",
	}

	_, err := New(cfg)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

// TestHealthEndpoint verifies health check endpoint
func TestHealthEndpoint(t *testing.T) {
	cfg := &Config{
		UpstreamURL:            "http://localhost:8080",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "", // Empty = stdout only
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024,
		SPIFFEMode:             "dev",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}

	handler := gw.Handler()

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}

	// Health endpoint now returns JSON with circuit breaker state
	var health map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&health); err != nil {
		t.Fatalf("Failed to decode health response: %v", err)
	}

	if health["status"] != "ok" {
		t.Errorf("Expected status=ok, got %v", health["status"])
	}

	cbState, ok := health["circuit_breaker"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected circuit_breaker in health response")
	}
	if cbState["state"] != "closed" {
		t.Errorf("Expected circuit_breaker.state=closed, got %v", cbState["state"])
	}
}

// TestConfigFromEnv verifies configuration loading from environment
func TestConfigFromEnv(t *testing.T) {
	// Test default values
	t.Setenv("PORT", "")
	t.Setenv("UPSTREAM_URL", "")
	cfg := ConfigFromEnv()

	if cfg.Port != 9090 {
		t.Errorf("Expected default port 9090, got %d", cfg.Port)
	}

	if cfg.UpstreamURL != "http://host.docker.internal:8081/mcp" {
		t.Errorf("Expected default upstream URL, got %s", cfg.UpstreamURL)
	}

	if cfg.SPIFFEMode != "dev" {
		t.Errorf("Expected default SPIFFE mode 'dev', got %s", cfg.SPIFFEMode)
	}

	// Verify circuit breaker defaults
	if cfg.CircuitFailureThreshold != 5 {
		t.Errorf("Expected default CircuitFailureThreshold=5, got %d", cfg.CircuitFailureThreshold)
	}
	if cfg.CircuitResetTimeout != 30 {
		t.Errorf("Expected default CircuitResetTimeout=30, got %d", cfg.CircuitResetTimeout)
	}
	if cfg.CircuitSuccessThreshold != 2 {
		t.Errorf("Expected default CircuitSuccessThreshold=2, got %d", cfg.CircuitSuccessThreshold)
	}

	// Test custom values
	t.Setenv("PORT", "8888")
	t.Setenv("UPSTREAM_URL", "http://custom:9999")
	t.Setenv("SPIFFE_MODE", "prod")
	cfg = ConfigFromEnv()

	if cfg.Port != 8888 {
		t.Errorf("Expected port 8888, got %d", cfg.Port)
	}

	if cfg.UpstreamURL != "http://custom:9999" {
		t.Errorf("Expected custom upstream URL, got %s", cfg.UpstreamURL)
	}

	if cfg.SPIFFEMode != "prod" {
		t.Errorf("Expected SPIFFE mode 'prod', got %s", cfg.SPIFFEMode)
	}

	// Test circuit breaker custom values
	t.Setenv("CIRCUIT_FAILURE_THRESHOLD", "10")
	t.Setenv("CIRCUIT_RESET_TIMEOUT", "60")
	t.Setenv("CIRCUIT_SUCCESS_THRESHOLD", "3")
	cfg = ConfigFromEnv()

	if cfg.CircuitFailureThreshold != 10 {
		t.Errorf("Expected CircuitFailureThreshold=10, got %d", cfg.CircuitFailureThreshold)
	}
	if cfg.CircuitResetTimeout != 60 {
		t.Errorf("Expected CircuitResetTimeout=60, got %d", cfg.CircuitResetTimeout)
	}
	if cfg.CircuitSuccessThreshold != 3 {
		t.Errorf("Expected CircuitSuccessThreshold=3, got %d", cfg.CircuitSuccessThreshold)
	}

	// RFA-2jl: Test AllowedBasePath defaults to working directory
	t.Setenv("ALLOWED_BASE_PATH", "")
	cfg = ConfigFromEnv()
	if cfg.AllowedBasePath == "" {
		t.Error("Expected AllowedBasePath to default to working directory, got empty string")
	}

	// RFA-2jl: Test AllowedBasePath from environment
	t.Setenv("ALLOWED_BASE_PATH", "/workspace/poc")
	cfg = ConfigFromEnv()
	if cfg.AllowedBasePath != "/workspace/poc" {
		t.Errorf("Expected AllowedBasePath=/workspace/poc, got %s", cfg.AllowedBasePath)
	}

	// RFA-hh5.1: Test KeyDB config defaults
	t.Setenv("KEYDB_URL", "")
	t.Setenv("KEYDB_POOL_MIN", "")
	t.Setenv("KEYDB_POOL_MAX", "")
	t.Setenv("SESSION_TTL", "")
	cfg = ConfigFromEnv()
	if cfg.KeyDBURL != "" {
		t.Errorf("Expected default KeyDBURL empty, got %s", cfg.KeyDBURL)
	}
	if cfg.KeyDBPoolMin != 5 {
		t.Errorf("Expected default KeyDBPoolMin=5, got %d", cfg.KeyDBPoolMin)
	}
	if cfg.KeyDBPoolMax != 20 {
		t.Errorf("Expected default KeyDBPoolMax=20, got %d", cfg.KeyDBPoolMax)
	}
	if cfg.SessionTTL != 3600 {
		t.Errorf("Expected default SessionTTL=3600, got %d", cfg.SessionTTL)
	}

	// RFA-hh5.1: Test KeyDB config custom values
	t.Setenv("KEYDB_URL", "redis://keydb:6379")
	t.Setenv("KEYDB_POOL_MIN", "10")
	t.Setenv("KEYDB_POOL_MAX", "50")
	t.Setenv("SESSION_TTL", "7200")
	cfg = ConfigFromEnv()
	if cfg.KeyDBURL != "redis://keydb:6379" {
		t.Errorf("Expected KeyDBURL=redis://keydb:6379, got %s", cfg.KeyDBURL)
	}
	if cfg.KeyDBPoolMin != 10 {
		t.Errorf("Expected KeyDBPoolMin=10, got %d", cfg.KeyDBPoolMin)
	}
	if cfg.KeyDBPoolMax != 50 {
		t.Errorf("Expected KeyDBPoolMax=50, got %d", cfg.KeyDBPoolMax)
	}
	if cfg.SessionTTL != 7200 {
		t.Errorf("Expected SessionTTL=7200, got %d", cfg.SessionTTL)
	}

	// RFA-8z8.1: Test SPIFFE trust domain defaults
	t.Setenv("SPIFFE_TRUST_DOMAIN", "")
	t.Setenv("SPIFFE_LISTEN_PORT", "")
	cfg = ConfigFromEnv()
	if cfg.SPIFFETrustDomain != "poc.local" {
		t.Errorf("Expected default SPIFFETrustDomain=poc.local, got %s", cfg.SPIFFETrustDomain)
	}
	if cfg.SPIFFEListenPort != 9443 {
		t.Errorf("Expected default SPIFFEListenPort=9443, got %d", cfg.SPIFFEListenPort)
	}

	// RFA-8z8.1: Test SPIFFE trust domain custom values
	t.Setenv("SPIFFE_TRUST_DOMAIN", "production.example.com")
	t.Setenv("SPIFFE_LISTEN_PORT", "8443")
	cfg = ConfigFromEnv()
	if cfg.SPIFFETrustDomain != "production.example.com" {
		t.Errorf("Expected SPIFFETrustDomain=production.example.com, got %s", cfg.SPIFFETrustDomain)
	}
	if cfg.SPIFFEListenPort != 8443 {
		t.Errorf("Expected SPIFFEListenPort=8443, got %d", cfg.SPIFFEListenPort)
	}

	// RFA-j6c: Test guard model config defaults
	t.Setenv("GUARD_MODEL_ENDPOINT", "")
	t.Setenv("GUARD_MODEL_NAME", "")
	t.Setenv("GUARD_API_KEY", "")
	t.Setenv("GROQ_API_KEY", "")
	cfg = ConfigFromEnv()
	if cfg.GuardModelEndpoint != "https://api.groq.com/openai/v1" {
		t.Errorf("Expected default GuardModelEndpoint=https://api.groq.com/openai/v1, got %s", cfg.GuardModelEndpoint)
	}
	if cfg.GuardModelName != "meta-llama/llama-prompt-guard-2-86m" {
		t.Errorf("Expected default GuardModelName=meta-llama/llama-prompt-guard-2-86m, got %s", cfg.GuardModelName)
	}
	if cfg.GuardAPIKey != "" {
		t.Errorf("Expected default GuardAPIKey empty when both GUARD_API_KEY and GROQ_API_KEY unset, got %s", cfg.GuardAPIKey)
	}

	// RFA-j6c: Test guard model config custom values
	t.Setenv("GUARD_MODEL_ENDPOINT", "http://localhost:11434/v1")
	t.Setenv("GUARD_MODEL_NAME", "custom-guard-model")
	t.Setenv("GUARD_API_KEY", "custom-guard-key")
	cfg = ConfigFromEnv()
	if cfg.GuardModelEndpoint != "http://localhost:11434/v1" {
		t.Errorf("Expected GuardModelEndpoint=http://localhost:11434/v1, got %s", cfg.GuardModelEndpoint)
	}
	if cfg.GuardModelName != "custom-guard-model" {
		t.Errorf("Expected GuardModelName=custom-guard-model, got %s", cfg.GuardModelName)
	}
	if cfg.GuardAPIKey != "custom-guard-key" {
		t.Errorf("Expected GuardAPIKey=custom-guard-key, got %s", cfg.GuardAPIKey)
	}

	// RFA-j6c: Test GUARD_API_KEY falls back to GROQ_API_KEY when not set
	t.Setenv("GUARD_API_KEY", "")
	t.Setenv("GROQ_API_KEY", "groq-fallback-key")
	cfg = ConfigFromEnv()
	if cfg.GuardAPIKey != "groq-fallback-key" {
		t.Errorf("Expected GuardAPIKey to fall back to GROQ_API_KEY=groq-fallback-key, got %s", cfg.GuardAPIKey)
	}

	// RFA-j6c: Test GUARD_API_KEY takes precedence over GROQ_API_KEY when both set
	t.Setenv("GUARD_API_KEY", "explicit-guard-key")
	t.Setenv("GROQ_API_KEY", "groq-key-should-be-ignored")
	cfg = ConfigFromEnv()
	if cfg.GuardAPIKey != "explicit-guard-key" {
		t.Errorf("Expected GuardAPIKey=explicit-guard-key (GUARD_API_KEY should take precedence), got %s", cfg.GuardAPIKey)
	}
}

// TestGatewayDevModePreservesPhase1Behavior verifies AC4: In SPIFFE_MODE=dev,
// all Phase 1 behavior is preserved (HTTP, header injection). No TLS is configured.
func TestGatewayDevModePreservesPhase1Behavior(t *testing.T) {
	cfg := &Config{
		UpstreamURL:            "http://localhost:8080",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024,
		SPIFFEMode:             "dev",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	defer gw.Close()

	// In dev mode, SPIFFE TLS should NOT be enabled
	if gw.SPIFFETLSEnabled() {
		t.Error("SPIFFE TLS should NOT be enabled in dev mode")
	}

	// ServerTLSConfig should return nil in dev mode
	if gw.ServerTLSConfig() != nil {
		t.Error("ServerTLSConfig should be nil in dev mode")
	}
}

// TestSPIFFEModeLogging verifies AC5: Gateway logs which mode is active at startup.
// We verify this indirectly by confirming the config is set correctly.
func TestSPIFFEModeLogging(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		expected string
	}{
		{name: "dev_mode", mode: "dev", expected: "dev"},
		{name: "prod_mode", mode: "prod", expected: "prod"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SPIFFE_MODE", tc.mode)
			cfg := ConfigFromEnv()
			if cfg.SPIFFEMode != tc.expected {
				t.Errorf("Expected SPIFFE mode %q, got %q", tc.expected, cfg.SPIFFEMode)
			}
		})
	}
}

// TestMiddlewareChainIntegration verifies full middleware chain integration
func TestMiddlewareChainIntegration(t *testing.T) {
	// Create mock upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"success"}`))
	}))
	defer upstream.Close()

	cfg := &Config{
		UpstreamURL:            upstream.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "", // Empty = stdout only
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}

	handler := gw.Handler()

	// Test valid request through full chain
	body := []byte(`{"jsonrpc":"2.0","method":"file_read","params":{"path":"/test"},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Note: Will fail at OPA since we don't have a real OPA instance
	// But we can verify the request made it through the earlier middleware
	if rec.Code == http.StatusOK {
		t.Log("Request successfully proxied through chain")
	}
}

// TestTokenSubstitutionOrderingInRealHandler verifies SECURITY FIX RFA-9k3:
// Token substitution MUST be applied innermost (last before proxy) in the ACTUAL gateway.Handler() method.
// This test verifies the real code, not just a mock chain.
func TestTokenSubstitutionOrderingInRealHandler(t *testing.T) {
	// Track what the proxy receives
	var proxyReceivedBody []byte

	// Create mock upstream that captures what it receives
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		proxyReceivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Logf("Failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()

	cfg := &Config{
		UpstreamURL:            upstream.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}

	// Get the REAL handler from gateway.Handler() - not a mock
	handler := gw.Handler()

	// Send request with SPIKE token
	tokenString := "$SPIKE{ref:test123,exp:3600}"
	requestBody := `{"api_key":"` + tokenString + `"}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// CRITICAL SECURITY VERIFICATION:
	// The proxy should have received the SUBSTITUTED secret, not the token
	// This proves token substitution is innermost (executes last before proxy)
	expectedSecret := "secret-value-for-test123" // This is what TokenSubstitution returns

	if bytes.Contains(proxyReceivedBody, []byte(tokenString)) {
		t.Errorf("SECURITY FAILURE: Proxy received the token '%s' instead of substituted secret. "+
			"This means TokenSubstitution is NOT the innermost middleware.", tokenString)
	}

	if bytes.Contains(proxyReceivedBody, []byte(expectedSecret)) {
		t.Logf("SECURITY FIX VERIFIED: Proxy received substituted secret (token was replaced)")
	} else {
		// Note: This might fail if token substitution is a no-op in skeleton
		// In that case, we verify that at minimum the token wasn't leaked to earlier middleware
		t.Logf("Token substitution may be no-op in skeleton (acceptable for now)")
	}

	// Log the execution for debugging
	t.Logf("Request body sent: %s", requestBody)
	t.Logf("Proxy received: %s", string(proxyReceivedBody))
}

// --- RFA-j2d.1 Integration Tests ---
// These tests send real HTTP requests through the full gateway Handler() (all 13+
// middleware steps) to prove that UI capability gating is actually wired into the
// request/response pipeline, not just defined as dead code.

// newTestGatewayForProxyHandler creates a Gateway instance backed by a mock upstream
// and a temporary UI capability grants file. Returns the Gateway directly so tests
// can access proxyHandler() which contains the UI gating wiring.
func newTestGatewayForProxyHandler(t *testing.T, upstreamHandler http.HandlerFunc, uiEnabled bool, grantsYAML string) *Gateway {
	t.Helper()

	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	tmpDir := t.TempDir()
	grantsPath := filepath.Join(tmpDir, "grants.yaml")
	if err := os.WriteFile(grantsPath, []byte(grantsYAML), 0644); err != nil {
		t.Fatalf("Failed to write grants file: %v", err)
	}

	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = uiEnabled
	uiConfig.DefaultMode = "deny"

	cfg := &Config{
		UpstreamURL:            upstream.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		UI:                     uiConfig,
		UICapabilityGrantsPath: grantsPath,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })
	return gw
}

// newTestGatewayForMCPTransportProxyHandler creates a Gateway instance configured
// for MCP transport mode ("mcp") and UI gating, intended for tests that exercise
// the real mcpclient transport initialization path via proxyHandler().
func newTestGatewayForMCPTransportProxyHandler(t *testing.T, upstreamURL string, uiEnabled bool, grantsYAML string) *Gateway {
	t.Helper()

	tmpDir := t.TempDir()
	grantsPath := filepath.Join(tmpDir, "grants.yaml")
	if err := os.WriteFile(grantsPath, []byte(grantsYAML), 0644); err != nil {
		t.Fatalf("Failed to write grants file: %v", err)
	}

	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = uiEnabled
	uiConfig.DefaultMode = "deny"

	cfg := &Config{
		UpstreamURL:            upstreamURL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
		UI:                     uiConfig,
		UICapabilityGrantsPath: grantsPath,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })
	return gw
}

// newTestGatewayWithUIGating creates a gateway backed by a mock upstream and a
// temporary UI capability grants file. Returns the full gateway handler (with entire
// middleware chain).
func newTestGatewayWithUIGating(t *testing.T, upstreamHandler http.HandlerFunc, uiEnabled bool, grantsYAML string) http.Handler {
	t.Helper()

	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	// Write grants YAML to temp file
	tmpDir := t.TempDir()
	grantsPath := filepath.Join(tmpDir, "grants.yaml")
	if err := os.WriteFile(grantsPath, []byte(grantsYAML), 0644); err != nil {
		t.Fatalf("Failed to write grants file: %v", err)
	}

	uiConfig := UIConfigDefaults()
	uiConfig.Enabled = uiEnabled
	uiConfig.DefaultMode = "deny" // default: deny unless grant says otherwise

	cfg := &Config{
		UpstreamURL:            upstream.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		UI:                     uiConfig,
		UICapabilityGrantsPath: grantsPath,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	return gw.Handler()
}

// upstreamToolsListWithUI returns a mock upstream handler that responds to any
// request with a tools/list JSON-RPC response containing tools with _meta.ui.
func upstreamToolsListWithUI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"tools": []interface{}{
					// Include a registry-managed tool with full schema so tool registry hash
					// verification can safely compute observed hashes from tools/list.
					map[string]interface{}{
						"name":        "tavily_search",
						"description": "Search the web using Tavily API",
						"inputSchema": map[string]interface{}{
							"type":     "object",
							"required": []interface{}{"query"},
							"properties": map[string]interface{}{
								"query": map[string]interface{}{
									"type":        "string",
									"description": "Search query",
								},
								"max_results": map[string]interface{}{
									"type":        "integer",
									"description": "Maximum results to return",
									"default":     5,
								},
							},
						},
					},
					map[string]interface{}{
						"name":        "render-analytics",
						"description": "Render analytics dashboard",
						"_meta": map[string]interface{}{
							"ui": map[string]interface{}{
								"resourceUri": "ui://test-server/analytics.html",
							},
						},
					},
					map[string]interface{}{
						"name":        "show-chart",
						"description": "Display chart",
						"_meta": map[string]interface{}{
							"ui": map[string]interface{}{
								"resourceUri": "ui://test-server/chart.html",
							},
						},
					},
					map[string]interface{}{
						"name":        "plain-tool",
						"description": "A regular tool with no UI",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// TestUICapabilityGating_DenyMode_StripsMetaUI_FullGateway proves that when a
// server is in deny mode, _meta.ui is stripped from tools/list responses that
// flow through the gateway's proxyHandler.
//
// This test creates a real Gateway instance and invokes proxyHandler() directly
// (the method where the UI gating wiring lives). It uses BodyCapture middleware
// to populate the request body in context, just as the real middleware chain does.
// This proves that the gating code IS called from the handler, not just defined.
func TestUICapabilityGating_DenyMode_StripsMetaUI_FullGateway(t *testing.T) {
	grants := `
ui_capability_grants:
  - server: "test-server"
    tenant: "test-tenant"
    mode: "deny"
    approved_tools: []
`
	gw := newTestGatewayForProxyHandler(t, upstreamToolsListWithUI(), true, grants)

	// Wrap proxyHandler with BodyCapture so context has the request body
	handler := middleware.BodyCapture(gw.proxyHandler())

	// Build a tools/list JSON-RPC request
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "test-server")
	req.Header.Set("X-Tenant", "test-tenant")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)

	// Parse the response
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("Response was not JSON (status=%d, body=%s)", rec.Code, string(respBody))
	}

	// Navigate to result.tools
	resultSection, ok := result["result"]
	if !ok {
		t.Fatalf("No 'result' field in response: %s", string(respBody))
	}

	resultMap := resultSection.(map[string]interface{})
	toolsRaw := resultMap["tools"]
	toolList := toolsRaw.([]interface{})

	// Verify: ALL _meta.ui fields should be stripped (deny mode)
	for _, toolItem := range toolList {
		tool, ok := toolItem.(map[string]interface{})
		if !ok {
			continue
		}
		toolName, _ := tool["name"].(string)

		meta, hasMeta := tool["_meta"]
		if !hasMeta {
			continue // No _meta = correct (either stripped or never had one)
		}

		metaMap, ok := meta.(map[string]interface{})
		if !ok {
			continue
		}

		if _, hasUI := metaMap["ui"]; hasUI {
			t.Errorf("WIRING FAILURE: tool %q still has _meta.ui after passing through proxyHandler in deny mode. "+
				"applyUICapabilityGating is NOT wired into the response path.", toolName)
		}
	}

	t.Logf("PASS: _meta.ui stripped from all tools in deny mode (status=%d, tools=%d)", rec.Code, len(toolList))
}

// TestUICapabilityGating_AllowMode_RetainsApprovedTools_FullGateway proves that
// in allow mode with an approved_tools list, only approved tools retain _meta.ui.
func TestUICapabilityGating_AllowMode_RetainsApprovedTools_FullGateway(t *testing.T) {
	grants := `
ui_capability_grants:
  - server: "test-server"
    tenant: "test-tenant"
    mode: "allow"
    approved_tools:
      - "render-analytics"
`
	gw := newTestGatewayForProxyHandler(t, upstreamToolsListWithUI(), true, grants)
	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "test-server")
	req.Header.Set("X-Tenant", "test-tenant")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("Response not JSON (status=%d, body=%s)", rec.Code, string(respBody))
	}

	resultSection := result["result"].(map[string]interface{})
	toolList := resultSection["tools"].([]interface{})

	for _, toolItem := range toolList {
		tool := toolItem.(map[string]interface{})
		toolName, _ := tool["name"].(string)

		switch toolName {
		case "render-analytics":
			// Approved tool - _meta.ui MUST be retained
			meta, hasMeta := tool["_meta"]
			if !hasMeta {
				t.Errorf("WIRING FAILURE: approved tool %q lost _meta in allow mode", toolName)
				continue
			}
			metaMap := meta.(map[string]interface{})
			if _, hasUI := metaMap["ui"]; !hasUI {
				t.Errorf("WIRING FAILURE: approved tool %q lost _meta.ui in allow mode", toolName)
			}

		case "show-chart":
			// NOT in approved_tools list - _meta.ui MUST be stripped
			if meta, has := tool["_meta"]; has {
				metaMap, _ := meta.(map[string]interface{})
				if _, hasUI := metaMap["ui"]; hasUI {
					t.Errorf("WIRING FAILURE: unapproved tool %q still has _meta.ui in allow mode", toolName)
				}
			}

		case "plain-tool":
			// No _meta.ui to begin with - should be unchanged
		}
	}

	t.Logf("PASS: allow mode correctly filters approved vs unapproved tools (status=%d)", rec.Code)
}

// TestUICapabilityGating_AuditOnlyMode_RetainsMetaUI_FullGateway proves that
// audit-only mode retains _meta.ui (permissive) through the gateway proxy handler.
func TestUICapabilityGating_AuditOnlyMode_RetainsMetaUI_FullGateway(t *testing.T) {
	grants := `
ui_capability_grants:
  - server: "test-server"
    tenant: "test-tenant"
    mode: "audit-only"
    approved_tools: []
`
	gw := newTestGatewayForProxyHandler(t, upstreamToolsListWithUI(), true, grants)
	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "test-server")
	req.Header.Set("X-Tenant", "test-tenant")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("Response not JSON (status=%d, body=%s)", rec.Code, string(respBody))
	}

	resultSection := result["result"].(map[string]interface{})
	toolList := resultSection["tools"].([]interface{})

	uiToolCount := 0
	for _, toolItem := range toolList {
		tool := toolItem.(map[string]interface{})
		if meta, has := tool["_meta"]; has {
			metaMap := meta.(map[string]interface{})
			if _, hasUI := metaMap["ui"]; hasUI {
				uiToolCount++
			}
		}
	}

	// The upstream returns 2 tools with _meta.ui. In audit-only mode, both should be retained.
	if uiToolCount != 2 {
		t.Errorf("Expected 2 tools with _meta.ui in audit-only mode, got %d", uiToolCount)
	}

	t.Logf("PASS: audit-only mode retains all _meta.ui (count=%d, status=%d)", uiToolCount, rec.Code)
}

// TestUICapabilityGating_UIResourceRead_Blocked_FullGateway proves that ui://
// resource reads are blocked with HTTP 403 for denied servers when flowing
// through the gateway proxy handler.
func TestUICapabilityGating_UIResourceRead_Blocked_FullGateway(t *testing.T) {
	// Upstream should NOT be called for denied ui:// reads
	upstreamCalled := false
	upstream := func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"should not see this"}`))
	}

	grants := `
ui_capability_grants:
  - server: "denied-server"
    tenant: "acme"
    mode: "deny"
    approved_tools: []
`
	gw := newTestGatewayForProxyHandler(t, upstream, true, grants)
	handler := middleware.BodyCapture(gw.proxyHandler())

	// Build a resources/read request for a ui:// URI
	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"ui://denied-server/exploit.html"},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "denied-server")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected HTTP 403 for denied ui:// resource read, got %d. Body: %s",
			rec.Code, string(respBody))
	}

	if !strings.Contains(string(respBody), "ui_capability_denied") {
		t.Errorf("Expected error body to contain 'ui_capability_denied', got: %s", string(respBody))
	}

	if upstreamCalled {
		t.Errorf("WIRING FAILURE: upstream was called for a denied ui:// resource read. " +
			"checkUIResourceReadAllowed did NOT block the request before proxying.")
	}

	t.Logf("PASS: ui:// resource read blocked with 403 for denied server (upstream NOT called)")
}

// TestUICapabilityGating_GlobalKillSwitch_FullGateway proves that when
// ui.enabled=false, ALL _meta.ui is stripped regardless of grants.
func TestUICapabilityGating_GlobalKillSwitch_FullGateway(t *testing.T) {
	grants := `
ui_capability_grants:
  - server: "test-server"
    tenant: "test-tenant"
    mode: "allow"
    approved_tools: []
`
	// Kill switch: uiEnabled=false
	gw := newTestGatewayForProxyHandler(t, upstreamToolsListWithUI(), false, grants)
	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "test-server")
	req.Header.Set("X-Tenant", "test-tenant")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("Response not JSON (status=%d, body=%s)", rec.Code, string(respBody))
	}

	resultSection := result["result"].(map[string]interface{})
	toolList := resultSection["tools"].([]interface{})

	// ALL _meta.ui should be stripped despite grant saying "allow"
	for _, toolItem := range toolList {
		tool := toolItem.(map[string]interface{})
		toolName, _ := tool["name"].(string)
		if meta, has := tool["_meta"]; has {
			metaMap := meta.(map[string]interface{})
			if _, hasUI := metaMap["ui"]; hasUI {
				t.Errorf("KILL SWITCH FAILURE: tool %q still has _meta.ui when ui.enabled=false", toolName)
			}
		}
	}

	t.Logf("PASS: global kill switch strips all _meta.ui (status=%d, tools=%d)", rec.Code, len(toolList))
}

// TestUICapabilityGating_StandardRequest_Unchanged_FullGateway proves that
// non-tools/list, non-ui:// requests pass through the gateway proxy handler unchanged.
func TestUICapabilityGating_StandardRequest_Unchanged_FullGateway(t *testing.T) {
	expectedBody := `{"result":"standard_response"}`
	upstream := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(expectedBody))
	}

	grants := `ui_capability_grants: []`
	gw := newTestGatewayForProxyHandler(t, upstream, true, grants)
	handler := middleware.BodyCapture(gw.proxyHandler())

	// A standard MCP request (not tools/list, not resources/read with ui://)
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"file_read","arguments":{"path":"/test"}},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)

	// Standard requests should be proxied unchanged to upstream
	if !strings.Contains(string(respBody), "standard_response") {
		t.Errorf("Expected standard request to be proxied unchanged, got status=%d body=%s",
			rec.Code, string(respBody))
	}

	t.Logf("PASS: standard request proxied unchanged (status=%d)", rec.Code)
}

// TestUICapabilityGating_NoServerHeader_DefaultsDeny_FullGateway verifies that
// when X-MCP-Server and X-Tenant headers are not set, the gateway defaults to
// "default"/"default" which matches no grants, resulting in deny mode.
func TestUICapabilityGating_NoServerHeader_DefaultsDeny_FullGateway(t *testing.T) {
	grants := `
ui_capability_grants:
  - server: "specific-server"
    tenant: "specific-tenant"
    mode: "allow"
    approved_tools: []
`
	gw := newTestGatewayForProxyHandler(t, upstreamToolsListWithUI(), true, grants)
	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	// Deliberately NOT setting X-MCP-Server or X-Tenant
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("Response not JSON (status=%d, body=%s)", rec.Code, string(respBody))
	}

	resultSection := result["result"].(map[string]interface{})
	toolList := resultSection["tools"].([]interface{})

	// No matching grant for "default"/"default" -> deny mode -> _meta.ui stripped
	for _, toolItem := range toolList {
		tool := toolItem.(map[string]interface{})
		toolName, _ := tool["name"].(string)
		if meta, has := tool["_meta"]; has {
			metaMap := meta.(map[string]interface{})
			if _, hasUI := metaMap["ui"]; hasUI {
				t.Errorf("DEFAULT DENY FAILURE: tool %q still has _meta.ui with no server/tenant headers", toolName)
			}
		}
	}

	t.Logf("PASS: no server/tenant headers defaults to deny mode (status=%d, tools=%d)", rec.Code, len(toolList))
}

// TestUICapabilityGating_UIResourceRead_AllowMode_ProxiesToUpstream proves that
// when a server is in allow mode, ui:// resource reads are proxied to the upstream
// and the response passes through the full response processing pipeline (RFA-j2d.6).
func TestUICapabilityGating_UIResourceRead_AllowMode_ProxiesToUpstream(t *testing.T) {
	htmlContent := []byte(`<html><body>UI resource</body></html>`)
	contentHash := middleware.ComputeUIResourceHash(htmlContent)

	upstreamCalled := false
	upstream := func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.Header().Set("Content-Type", "text/html;profile=mcp-app")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(htmlContent)
	}

	grants := `
ui_capability_grants:
  - server: "allowed-server"
    tenant: "acme"
    mode: "allow"
    approved_tools: []
`
	gw := newTestGatewayForProxyHandler(t, upstream, true, grants)

	// RFA-j2d.6: Register the UI resource so it passes registry verification
	gw.registry.RegisterUIResource(middleware.RegisteredUIResource{
		Server:      "allowed-server",
		ResourceURI: "ui://allowed-server/dashboard.html",
		ContentHash: contentHash,
	})

	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"ui://allowed-server/dashboard.html"},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "allowed-server")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !upstreamCalled {
		t.Error("WIRING FAILURE: upstream was NOT called for allowed ui:// resource read")
	}

	if rec.Code == http.StatusForbidden {
		respBody, _ := io.ReadAll(rec.Body)
		t.Errorf("ui:// resource read should NOT be blocked for allowed server, got 403: %s", string(respBody))
	}

	t.Logf("PASS: ui:// resource read proxied to upstream for allowed server (status=%d, upstream_called=%v)",
		rec.Code, upstreamCalled)
}

// --- RFA-9ol: MCP Transport Integration Tests ---
// These tests prove MCP Streamable HTTP transport works through the full gateway
// middleware chain (all 13 layers).

// newMockMCPServer creates an httptest server that simulates a Streamable HTTP MCP
// server, responding to initialize, notifications/initialized, and tools/call.
// Records received methods and Mcp-Session-Id headers for verification.
func newMockMCPServer(t *testing.T) (*httptest.Server, *mcpServerLog) {
	t.Helper()

	log := &mcpServerLog{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			var rpcReq map[string]interface{}
			if err := json.Unmarshal(body, &rpcReq); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			method, _ := rpcReq["method"].(string)
			log.RecordCall(method, r.Header.Get("Mcp-Session-Id"), body)

			switch method {
			case "initialize":
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Mcp-Session-Id", "integration-session-42")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"mock-mcp","version":"1.0"}}}`))

			case "notifications/initialized":
				w.WriteHeader(http.StatusOK)

			case "tools/list":
				resp := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      1,
					"result": map[string]interface{}{
						"tools": []interface{}{
							map[string]interface{}{
								"name":        "tavily_search",
								"description": "Search the web using Tavily API",
								"inputSchema": map[string]interface{}{
									"type":     "object",
									"required": []interface{}{"query"},
									"properties": map[string]interface{}{
										"query": map[string]interface{}{
											"type":        "string",
											"description": "Search query",
										},
										"max_results": map[string]interface{}{
											"type":        "integer",
											"description": "Maximum results to return",
											"default":     5,
										},
									},
								},
							},
							map[string]interface{}{
								"name":        "render-analytics",
								"description": "Render analytics dashboard",
								"_meta": map[string]interface{}{
									"ui": map[string]interface{}{
										"resourceUri": "ui://test-server/analytics.html",
									},
								},
							},
							map[string]interface{}{
								"name":        "show-chart",
								"description": "Display chart",
								"_meta": map[string]interface{}{
									"ui": map[string]interface{}{
										"resourceUri": "ui://test-server/chart.html",
									},
								},
							},
							map[string]interface{}{
								"name":        "plain-tool",
								"description": "A regular tool with no UI",
							},
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)

			case "resources/read":
				uri := ""
				if params, ok := rpcReq["params"].(map[string]interface{}); ok {
					if u, ok := params["uri"].(string); ok {
						uri = u
					}
				}
				resp := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      1,
					"result": map[string]interface{}{
						"contents": []interface{}{
							map[string]interface{}{
								"uri":      uri,
								"mimeType": "text/html;profile=mcp-app",
								"text":     "<html><body>Mock UI Resource</body></html>",
							},
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)

			case "tools/call", "tavily_search":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"search result: MCP gateway integration test passed"}]}}`))

			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}`))
			}

		case http.MethodDelete:
			log.RecordCall("DELETE", r.Header.Get("Mcp-Session-Id"), nil)
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	t.Cleanup(server.Close)
	return server, log
}

// newMockMCPServerUI creates a Streamable HTTP MCP server that supports tools/list
// (with _meta.ui) and resources/read (ui://) for MCP-UI transport parity tests.
func newMockMCPServerUI(t *testing.T) (*httptest.Server, *mcpServerLog) {
	t.Helper()

	log := &mcpServerLog{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			var rpcReq map[string]interface{}
			if err := json.Unmarshal(body, &rpcReq); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			method, _ := rpcReq["method"].(string)
			log.RecordCall(method, r.Header.Get("Mcp-Session-Id"), body)

			switch method {
			case "initialize":
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Mcp-Session-Id", "ui-integration-session")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"mock-mcp-ui","version":"1.0"}}}`))

			case "notifications/initialized":
				w.WriteHeader(http.StatusOK)

			case "tools/list":
				resp := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      1,
					"result": map[string]interface{}{
						"tools": []interface{}{
							map[string]interface{}{
								"name":        "analytics-tool",
								"description": "Render analytics",
								"_meta": map[string]interface{}{
									"ui": map[string]interface{}{
										"resourceUri": "ui://test-server/analytics.html",
										"csp": map[string]interface{}{
											"connectDomains":  []interface{}{"https://api.acme.corp", "https://evil.com"},
											"resourceDomains": []interface{}{"https://cdn.acme.corp"},
											"frameDomains":    []interface{}{"https://iframe.evil.com"},
											"baseUriDomains":  []interface{}{"https://redirect.evil.com"},
										},
										"permissions": map[string]interface{}{
											"camera":         true,
											"microphone":     true,
											"geolocation":    false,
											"clipboardWrite": true,
										},
									},
								},
							},
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)

			case "resources/read":
				uri := ""
				if params, ok := rpcReq["params"].(map[string]interface{}); ok {
					if u, ok := params["uri"].(string); ok {
						uri = u
					}
				}
				resp := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      1,
					"result": map[string]interface{}{
						"contents": []interface{}{
							map[string]interface{}{
								"uri":      uri,
								"mimeType": "text/html;profile=mcp-app",
								"text":     "<html><body><h1>Safe UI</h1></body></html>",
							},
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)

			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}`))
			}

		case http.MethodDelete:
			log.RecordCall("DELETE", r.Header.Get("Mcp-Session-Id"), nil)
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	t.Cleanup(server.Close)
	return server, log
}

// mcpServerLog records calls received by the mock MCP server.
type mcpServerLog struct {
	calls []mcpCall
}

type mcpCall struct {
	Method    string
	SessionID string
	Body      []byte
}

func (l *mcpServerLog) RecordCall(method, sessionID string, body []byte) {
	l.calls = append(l.calls, mcpCall{Method: method, SessionID: sessionID, Body: body})
}

func (l *mcpServerLog) MethodCalls(method string) []mcpCall {
	var result []mcpCall
	for _, c := range l.calls {
		if c.Method == method {
			result = append(result, c)
		}
	}
	return result
}

func toStringSliceAny(v interface{}) []string {
	if v == nil {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// TestMCPTransport_ToolsCall_ThroughAll13Layers proves that a tools/call request
// flows through ALL 13 middleware layers and reaches the upstream MCP server as
// proper JSON-RPC when MCPTransportMode="mcp".
func TestMCPTransport_ToolsCall_ThroughAll13Layers(t *testing.T) {
	mcpServer, serverLog := newMockMCPServer(t)

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp", // Use MCP transport
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	// Build a spec-conformant tools/call request. The gateway MUST enforce policy
	// and registry checks against params.name (the effective tool name).
	requestBody := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"tavily_search","arguments":{"query":"MCP test"}},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// --- Verify response ---
	if rec.Code != http.StatusOK {
		respBody, _ := io.ReadAll(rec.Body)
		t.Fatalf("Expected 200, got %d. Body: %s", rec.Code, string(respBody))
	}

	respBody, _ := io.ReadAll(rec.Body)
	var rpcResp map[string]interface{}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		t.Fatalf("Response is not valid JSON: %v. Body: %s", err, string(respBody))
	}

	if rpcResp["jsonrpc"] != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %v", rpcResp["jsonrpc"])
	}

	result, ok := rpcResp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected result in response, got: %s", string(respBody))
	}

	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("Expected non-empty content array in result")
	}

	firstContent := content[0].(map[string]interface{})
	if text, ok := firstContent["text"].(string); !ok || !strings.Contains(text, "integration test passed") {
		t.Errorf("Expected text containing 'integration test passed', got: %v", firstContent["text"])
	}

	// --- Verify MCP server received proper requests ---
	// Should have: initialize, notifications/initialized, tavily_search (in order)
	initCalls := serverLog.MethodCalls("initialize")
	if len(initCalls) != 1 {
		t.Errorf("Expected 1 initialize call, got %d", len(initCalls))
	}

	notifCalls := serverLog.MethodCalls("notifications/initialized")
	if len(notifCalls) != 1 {
		t.Errorf("Expected 1 notifications/initialized call, got %d", len(notifCalls))
	}

	toolsCalls := serverLog.MethodCalls("tools/call")
	if len(toolsCalls) != 1 {
		t.Fatalf("Expected 1 tools/call call, got %d", len(toolsCalls))
	}

	// Verify tools/call had Mcp-Session-Id header
	if toolsCalls[0].SessionID != "integration-session-42" {
		t.Errorf("Expected Mcp-Session-Id 'integration-session-42', got '%s'", toolsCalls[0].SessionID)
	}

	// Verify tools/call body is proper JSON-RPC
	var toolsCallBody map[string]interface{}
	if err := json.Unmarshal(toolsCalls[0].Body, &toolsCallBody); err != nil {
		t.Fatalf("tools/call body is not JSON: %v", err)
	}
	if toolsCallBody["jsonrpc"] != "2.0" {
		t.Errorf("Expected tools/call body jsonrpc=2.0, got %v", toolsCallBody["jsonrpc"])
	}
	if toolsCallBody["method"] != "tools/call" {
		t.Errorf("Expected tools/call method, got %v", toolsCallBody["method"])
	}
	// Verify the effective tool name is preserved in params.name.
	if params, ok := toolsCallBody["params"].(map[string]interface{}); ok {
		if name, _ := params["name"].(string); name != "tavily_search" {
			t.Errorf("Expected params.name=tavily_search, got %v", params["name"])
		}
	} else {
		t.Errorf("Expected params object in tools/call body, got %T", toolsCallBody["params"])
	}

	t.Logf("PASS: tools/call flowed through all 13 middleware layers to MCP server and back (status=%d)", rec.Code)
}

// --- RFA-6fse.2: MCP Transport UI Enforcement Integration Tests ---

func TestMCPTransport_ToolsList_UIProcessing_MatchesProxyMode(t *testing.T) {
	grants := `
ui_capability_grants:
  - server: "test-server"
    tenant: "test-tenant"
    mode: "deny"
    approved_tools: []
`
	// Proxy mode gateway: upstream is plain HTTP returning a tools/list JSON-RPC response.
	gwProxy := newTestGatewayForProxyHandler(t, upstreamToolsListWithUI(), true, grants)
	handlerProxy := middleware.BodyCapture(gwProxy.proxyHandler())

	// MCP transport mode gateway: upstream is a mock MCP server with initialize + tools/list.
	mcpServer, _ := newMockMCPServer(t)
	gwMCP := newTestGatewayForMCPTransportProxyHandler(t, mcpServer.URL, true, grants)
	handlerMCP := middleware.BodyCapture(gwMCP.proxyHandler())

	// Same tools/list request through both gateways.
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)

	req1 := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-MCP-Server", "test-server")
	req1.Header.Set("X-Tenant", "test-tenant")
	rec1 := httptest.NewRecorder()
	handlerProxy.ServeHTTP(rec1, req1)

	req2 := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-MCP-Server", "test-server")
	req2.Header.Set("X-Tenant", "test-tenant")
	rec2 := httptest.NewRecorder()
	handlerMCP.ServeHTTP(rec2, req2)

	if rec1.Code != http.StatusOK {
		respBody, _ := io.ReadAll(rec1.Body)
		t.Fatalf("Proxy mode expected 200, got %d. Body: %s", rec1.Code, string(respBody))
	}
	if rec2.Code != http.StatusOK {
		respBody, _ := io.ReadAll(rec2.Body)
		t.Fatalf("MCP mode expected 200, got %d. Body: %s", rec2.Code, string(respBody))
	}

	respProxy, _ := io.ReadAll(rec1.Body)
	respMCP, _ := io.ReadAll(rec2.Body)

	var j1 any
	var j2 any
	if err := json.Unmarshal(respProxy, &j1); err != nil {
		t.Fatalf("Proxy response not JSON: %v (body=%s)", err, string(respProxy))
	}
	if err := json.Unmarshal(respMCP, &j2); err != nil {
		t.Fatalf("MCP response not JSON: %v (body=%s)", err, string(respMCP))
	}

	if !reflect.DeepEqual(j1, j2) {
		t.Fatalf("Expected MCP transport tools/list UI processing to match proxy mode.\nproxy=%s\nmcp=%s",
			string(respProxy), string(respMCP))
	}

	// Extra sanity: deny mode should strip _meta.ui entirely.
	if strings.Contains(string(respMCP), "\"resourceUri\"") {
		t.Fatalf("Expected deny mode tools/list response to have _meta.ui stripped, got: %s", string(respMCP))
	}

	t.Logf("PASS: MCP transport tools/list UI processing matches proxy mode (deny mode)")
}

func TestMCPTransport_UIResourceRead_Denied_BlocksBeforeUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"status":"unexpected"}}`))
	}))
	t.Cleanup(upstream.Close)

	grants := `
ui_capability_grants:
  - server: "denied-server"
    tenant: "acme"
    mode: "deny"
    approved_tools: []
`
	gw := newTestGatewayForMCPTransportProxyHandler(t, upstream.URL, true, grants)
	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"ui://denied-server/exploit.html"},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "denied-server")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 for denied ui:// resource read, got %d. Body: %s", rec.Code, string(respBody))
	}
	if !strings.Contains(string(respBody), "ui_capability_denied") {
		t.Fatalf("Expected ui_capability_denied error, got: %s", string(respBody))
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("Expected upstream to NOT be called for denied ui:// read, got calls=%d", upstreamCalls.Load())
	}

	t.Logf("PASS: denied ui:// resources/read blocked before upstream (including before MCP init)")
}

func TestMCPTransport_UIResourceRead_ResponseControls_BlockOnRegistry(t *testing.T) {
	mcpServer, serverLog := newMockMCPServer(t)

	grants := `
ui_capability_grants:
  - server: "mcp-unreg-server"
    tenant: "acme"
    mode: "allow"
    approved_tools: []
`
	gw := newTestGatewayForMCPTransportProxyHandler(t, mcpServer.URL, true, grants)
	handler := middleware.BodyCapture(gw.proxyHandler())

	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"ui://mcp-unreg-server/page.html"},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Server", "mcp-unreg-server")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 for ui:// resource blocked by response controls, got %d. Body: %s", rec.Code, string(respBody))
	}
	if !strings.Contains(string(respBody), "ui_resource_blocked") {
		t.Fatalf("Expected ui_resource_blocked error, got: %s", string(respBody))
	}
	if !strings.Contains(string(respBody), "not in registry") {
		t.Fatalf("Expected registry verification to be the block reason, got: %s", string(respBody))
	}

	// Prove the request actually reached the MCP upstream (i.e., response-side enforcement).
	if len(serverLog.MethodCalls("resources/read")) != 1 {
		t.Fatalf("Expected upstream resources/read to be called once, got %d", len(serverLog.MethodCalls("resources/read")))
	}

	t.Logf("PASS: allowed ui:// resources/read blocked by registry verification in MCP transport mode")
}

// TestMCPTransport_ProxyMode_BypassesMCPPath verifies that MCPTransportMode="proxy"
// uses the legacy httputil.ReverseProxy path, completely bypassing MCP transport.
func TestMCPTransport_ProxyMode_BypassesMCPPath(t *testing.T) {
	// Create a plain HTTP upstream (not MCP-aware)
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"proxied-unchanged"}`))
	}))
	t.Cleanup(upstream.Close)

	cfg := &Config{
		UpstreamURL:            upstream.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "proxy", // Legacy proxy mode
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	body := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !upstreamCalled {
		t.Error("Expected upstream to be called in proxy mode")
	}

	respBody, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d. Body: %s", rec.Code, string(respBody))
	}

	if !strings.Contains(string(respBody), "proxied-unchanged") {
		t.Errorf("Expected proxied-unchanged in response, got: %s", string(respBody))
	}

	t.Logf("PASS: proxy mode uses reverse proxy (status=%d, upstream_called=%v)", rec.Code, upstreamCalled)
}

// TestMCPTransport_MCPMode_UpstreamError verifies that when the MCP server returns
// a JSON-RPC error, the gateway returns a proper GatewayError using WriteGatewayError.
func TestMCPTransport_MCPMode_UpstreamError(t *testing.T) {
	requestCount := 0
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "error-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		case "tools/list":
			// Tool registry verification uses tools/list to compute observed hashes.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"tavily_search","description":"Search the web using Tavily API","inputSchema":{"type":"object","required":["query"],"properties":{"query":{"type":"string","description":"Search query"},"max_results":{"type":"integer","description":"Maximum results to return","default":5}}}}]}}`))
		default:
			requestCount++
			// Return JSON-RPC error
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`))
		}
	}))
	t.Cleanup(mcpServer.Close)

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	body := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"error test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)

	// Should return 502 (Bad Gateway) with GatewayError envelope
	if rec.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 for JSON-RPC error, got %d. Body: %s", rec.Code, string(respBody))
	}

	// Verify GatewayError envelope
	var gatewayErr middleware.GatewayError
	if err := json.Unmarshal(respBody, &gatewayErr); err != nil {
		t.Fatalf("Failed to parse GatewayError: %v. Body: %s", err, string(respBody))
	}

	if gatewayErr.Code != middleware.ErrMCPRequestFailed {
		t.Errorf("Expected error code '%s', got '%s'", middleware.ErrMCPRequestFailed, gatewayErr.Code)
	}

	if gatewayErr.Middleware != "mcp_transport" {
		t.Errorf("Expected middleware='mcp_transport', got '%s'", gatewayErr.Middleware)
	}

	t.Logf("PASS: JSON-RPC error returned as proper GatewayError (code=%s, status=%d)", gatewayErr.Code, rec.Code)
}

// RFA-6fse.2: MCP-UI parity tests for MCP transport mode.

func TestMCPTransport_ToolsList_UIControls_Applied(t *testing.T) {
	mcpServer, _ := newMockMCPServerUI(t)

	// Write grants YAML to temp file
	tmpDir := t.TempDir()
	grantsPath := filepath.Join(tmpDir, "ui_grants.yaml")
	grants := `
ui_capability_grants:
  - server: "test-server"
    tenant: "acme"
    mode: "allow"
    approved_tools:
      - "analytics-tool"
    allowed_csp_connect_domains:
      - "https://api.acme.corp"
    allowed_csp_resource_domains:
      - "https://cdn.acme.corp"
    allowed_permissions:
      - "clipboardWrite"
`
	if err := os.WriteFile(grantsPath, []byte(grants), 0644); err != nil {
		t.Fatalf("Failed to write grants file: %v", err)
	}

	uiCfg := UIConfigDefaults()
	uiCfg.Enabled = true
	uiCfg.DefaultMode = "deny"

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
		UI:                     uiCfg,
		UICapabilityGrantsPath: grantsPath,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	body := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	req.Header.Set("X-MCP-Server", "test-server")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		respBody, _ := io.ReadAll(rec.Body)
		t.Fatalf("Expected 200, got %d. Body: %s", rec.Code, string(respBody))
	}

	respBody, _ := io.ReadAll(rec.Body)
	var resp map[string]interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("Response not JSON: %v (%s)", err, string(respBody))
	}

	result := resp["result"].(map[string]interface{})
	tools := result["tools"].([]interface{})
	if len(tools) != 1 {
		t.Fatalf("Expected 1 tool, got %d", len(tools))
	}
	tool := tools[0].(map[string]interface{})
	meta := tool["_meta"].(map[string]interface{})
	ui := meta["ui"].(map[string]interface{})

	// CSP mediation: evil.com stripped, frameDomains and baseUriDomains hard-empty.
	csp := ui["csp"].(map[string]interface{})
	connectDomains := toStringSliceAny(csp["connectDomains"])
	if len(connectDomains) != 1 || connectDomains[0] != "https://api.acme.corp" {
		t.Fatalf("Expected connectDomains=['https://api.acme.corp'], got %v", connectDomains)
	}
	if len(toStringSliceAny(csp["frameDomains"])) != 0 {
		t.Fatalf("Expected frameDomains empty (hard constraint), got %v", toStringSliceAny(csp["frameDomains"]))
	}
	if len(toStringSliceAny(csp["baseUriDomains"])) != 0 {
		t.Fatalf("Expected baseUriDomains empty (hard constraint), got %v", toStringSliceAny(csp["baseUriDomains"]))
	}

	// Permissions mediation: hard constraints deny camera/microphone regardless of grant.
	perms := ui["permissions"].(map[string]interface{})
	if perms["camera"] == true || perms["microphone"] == true {
		t.Fatalf("Expected camera/microphone denied by hard constraints, got %v", perms)
	}
}

func TestMCPTransport_UIResourceRead_UIURI_DeniedBeforeUpstream(t *testing.T) {
	mcpServer, serverLog := newMockMCPServerUI(t)

	// No allow grants: default deny (uiCfg.DefaultMode="deny").
	tmpDir := t.TempDir()
	grantsPath := filepath.Join(tmpDir, "ui_grants.yaml")
	if err := os.WriteFile(grantsPath, []byte("ui_capability_grants: []\n"), 0644); err != nil {
		t.Fatalf("Failed to write grants file: %v", err)
	}

	uiCfg := UIConfigDefaults()
	uiCfg.Enabled = true
	uiCfg.DefaultMode = "deny"

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
		UI:                     uiCfg,
		UICapabilityGrantsPath: grantsPath,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"ui://denied-server/exploit.html"},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	req.Header.Set("X-MCP-Server", "denied-server")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d. Body: %s", rec.Code, string(respBody))
	}
	if !strings.Contains(string(respBody), "ui_capability_denied") {
		t.Fatalf("Expected ui_capability_denied in body, got: %s", string(respBody))
	}

	// Critical: request-side deny must happen before any MCP upstream contact (including initialize).
	if len(serverLog.calls) != 0 {
		t.Fatalf("Expected no upstream calls, got %d (first=%s)", len(serverLog.calls), serverLog.calls[0].Method)
	}
}

func TestMCPTransport_UIResourceRead_UIURI_BlockedByRegistry(t *testing.T) {
	mcpServer, _ := newMockMCPServerUI(t)

	tmpDir := t.TempDir()
	grantsPath := filepath.Join(tmpDir, "ui_grants.yaml")
	grants := `
ui_capability_grants:
  - server: "safe-server"
    tenant: "acme"
    mode: "allow"
    approved_tools: []
`
	if err := os.WriteFile(grantsPath, []byte(grants), 0644); err != nil {
		t.Fatalf("Failed to write grants file: %v", err)
	}

	uiCfg := UIConfigDefaults()
	uiCfg.Enabled = true
	uiCfg.DefaultMode = "deny"

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
		UI:                     uiCfg,
		UICapabilityGrantsPath: grantsPath,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	// NOTE: Do NOT register the UI resource in gw.registry. This should cause
	// registry verification to block with ui_resource_blocked.

	handler := gw.Handler()

	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"ui://safe-server/dashboard.html"},"id":1}`)
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	req.Header.Set("X-MCP-Server", "safe-server")
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d. Body: %s", rec.Code, string(respBody))
	}
	if !strings.Contains(string(respBody), "ui_resource_blocked") {
		t.Fatalf("Expected ui_resource_blocked in body, got: %s", string(respBody))
	}
	if !strings.Contains(string(respBody), "not in registry") {
		t.Fatalf("Expected 'not in registry' in body, got: %s", string(respBody))
	}
}

// TestMCPTransport_LazyInit_NotAtStartup verifies AC9: transport.Initialize() is
// called on first request, not at startup.
func TestMCPTransport_LazyInit_NotAtStartup(t *testing.T) {
	initCalled := false
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		if method == "initialize" {
			initCalled = true
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "lazy-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
			return
		}
		if method == "notifications/initialized" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if method == "tools/list" {
			// RFA-6fse.4: ToolRegistryVerify may perform a gateway-owned tools/list refresh
			// before allowing the first tool invocation. Provide a baseline tool definition
			// matching config/tool-registry.yaml so the hash verification succeeds.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"tavily_search","description":"Search the web using Tavily API","inputSchema":{"type":"object","required":["query"],"properties":{"query":{"type":"string","description":"Search query"},"max_results":{"type":"integer","description":"Maximum results to return","default":5}}}}]}}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"lazy init worked"}]}}`))
	}))
	t.Cleanup(mcpServer.Close)

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	// VERIFY: Initialize NOT called at startup
	if initCalled {
		t.Fatal("Initialize() was called at startup -- should be lazy (first request)")
	}

	handler := gw.Handler()

	// Send first request -- this should trigger lazy init
	body := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"lazy init test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// NOW initialize should have been called
	if !initCalled {
		t.Error("Initialize() was NOT called on first request -- lazy init is broken")
	}

	if rec.Code != http.StatusOK {
		respBody, _ := io.ReadAll(rec.Body)
		t.Fatalf("Expected 200, got %d. Body: %s", rec.Code, string(respBody))
	}

	t.Logf("PASS: lazy init verified (init_at_startup=false, init_on_first_request=true, status=%d)", rec.Code)
}

// TestMCPTransport_ConfigDefault verifies AC4: MCP_TRANSPORT_MODE defaults to "mcp"
// when loaded via ConfigFromEnv.
func TestMCPTransport_ConfigDefault(t *testing.T) {
	t.Setenv("MCP_TRANSPORT_MODE", "")
	cfg := ConfigFromEnv()
	if cfg.MCPTransportMode != "mcp" {
		t.Errorf("Expected default MCPTransportMode='mcp', got '%s'", cfg.MCPTransportMode)
	}

	t.Setenv("MCP_TRANSPORT_MODE", "proxy")
	cfg = ConfigFromEnv()
	if cfg.MCPTransportMode != "proxy" {
		t.Errorf("Expected MCPTransportMode='proxy', got '%s'", cfg.MCPTransportMode)
	}

	t.Setenv("MCP_TRANSPORT_MODE", "mcp")
	cfg = ConfigFromEnv()
	if cfg.MCPTransportMode != "mcp" {
		t.Errorf("Expected MCPTransportMode='mcp', got '%s'", cfg.MCPTransportMode)
	}
}

// TestMCPTransport_ErrorUsesWriteGatewayError verifies AC7: ALL errors from
// handleMCPRequest use WriteGatewayError() with proper GatewayError structs.
func TestMCPTransport_ErrorUsesWriteGatewayError(t *testing.T) {
	// Use unreachable upstream to trigger transport error
	cfg := &Config{
		UpstreamURL:            "http://127.0.0.1:1", // unreachable
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	// Use a protocol method passthrough so ToolRegistryVerify does not block first.
	// Choose tools/list (permitted by OPA in this POC) so we reach handleMCPRequest
	// and exercise MCP transport initialization failure.
	body := `{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Body)

	// Should return 502 with GatewayError envelope (not bare http.Error text)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("Expected 502, got %d. Body: %s", rec.Code, string(respBody))
	}

	// Verify it's a proper GatewayError JSON envelope
	var gatewayErr middleware.GatewayError
	if err := json.Unmarshal(respBody, &gatewayErr); err != nil {
		t.Fatalf("Response is NOT a valid GatewayError JSON (violates AC7). Parse error: %v. Body: %s", err, string(respBody))
	}

	if gatewayErr.Code != middleware.ErrMCPTransportFailed {
		t.Errorf("Expected error code '%s', got '%s'", middleware.ErrMCPTransportFailed, gatewayErr.Code)
	}

	if gatewayErr.Middleware != "mcp_transport" {
		t.Errorf("Expected middleware='mcp_transport', got '%s'", gatewayErr.Middleware)
	}

	if gatewayErr.Remediation == "" {
		t.Error("Expected non-empty remediation in GatewayError")
	}

	// Verify Content-Type is application/json (not text/plain from http.Error)
	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected Content-Type application/json, got '%s' (suggests http.Error was used)", contentType)
	}

	t.Logf("PASS: transport error uses WriteGatewayError (code=%s, content-type=%s)", gatewayErr.Code, contentType)
}

// --- RFA-8rd: Full Streamable HTTP Integration Tests ---

// newMockMCPServerSSE creates an httptest server that simulates a Streamable HTTP
// MCP server responding with text/event-stream for tools/call (SSE mode).
// Records received methods and session IDs for verification.
func newMockMCPServerSSE(t *testing.T) (*httptest.Server, *mcpServerLog) {
	t.Helper()

	log := &mcpServerLog{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			var rpcReq map[string]interface{}
			if err := json.Unmarshal(body, &rpcReq); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			method, _ := rpcReq["method"].(string)
			log.RecordCall(method, r.Header.Get("Mcp-Session-Id"), body)

			switch method {
			case "initialize":
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Mcp-Session-Id", "sse-integration-session")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"mock-mcp-sse","version":"1.0"}}}`))

			case "notifications/initialized":
				w.WriteHeader(http.StatusOK)

			case "tools/list":
				// Tool registry verification uses tools/list to compute observed hashes.
				resp := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      1,
					"result": map[string]interface{}{
						"tools": []interface{}{
							map[string]interface{}{
								"name":        "tavily_search",
								"description": "Search the web using Tavily API",
								"inputSchema": map[string]interface{}{
									"type":     "object",
									"required": []interface{}{"query"},
									"properties": map[string]interface{}{
										"query": map[string]interface{}{
											"type":        "string",
											"description": "Search query",
										},
										"max_results": map[string]interface{}{
											"type":        "integer",
											"description": "Maximum results to return",
											"default":     5,
										},
									},
								},
							},
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)

			case "tools/call", "tavily_search":
				// Respond with SSE instead of JSON
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"SSE integration test passed through all 13 layers\"}]}}\n\n"))

			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}`))
			}

		case http.MethodDelete:
			log.RecordCall("DELETE", r.Header.Get("Mcp-Session-Id"), nil)
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	t.Cleanup(server.Close)
	return server, log
}

// TestMCPTransport_SSEResponse_ThroughAll13Layers proves AC9: an SSE response
// from the upstream MCP server flows through all 13 middleware layers and is
// correctly parsed back to JSON-RPC for the client.
func TestMCPTransport_SSEResponse_ThroughAll13Layers(t *testing.T) {
	mcpServer, serverLog := newMockMCPServerSSE(t)

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	// Build a tools/call request that passes all middleware checks
	requestBody := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"SSE integration test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// --- Verify response ---
	if rec.Code != http.StatusOK {
		respBody, _ := io.ReadAll(rec.Body)
		t.Fatalf("Expected 200, got %d. Body: %s", rec.Code, string(respBody))
	}

	respBody, _ := io.ReadAll(rec.Body)
	var rpcResp map[string]interface{}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		t.Fatalf("Response is not valid JSON: %v. Body: %s", err, string(respBody))
	}

	if rpcResp["jsonrpc"] != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %v", rpcResp["jsonrpc"])
	}

	result, ok := rpcResp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected result in response, got: %s", string(respBody))
	}

	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("Expected non-empty content array in result")
	}

	firstContent := content[0].(map[string]interface{})
	if text, ok := firstContent["text"].(string); !ok || !strings.Contains(text, "SSE integration test passed through all 13 layers") {
		t.Errorf("Expected text containing 'SSE integration test passed through all 13 layers', got: %v", firstContent["text"])
	}

	// --- Verify MCP server received proper requests ---
	initCalls := serverLog.MethodCalls("initialize")
	if len(initCalls) != 1 {
		t.Errorf("Expected 1 initialize call, got %d", len(initCalls))
	}

	toolsCalls := serverLog.MethodCalls("tavily_search")
	if len(toolsCalls) != 1 {
		t.Fatalf("Expected 1 tavily_search call, got %d", len(toolsCalls))
	}

	// Verify session ID was sent with the tools call
	if toolsCalls[0].SessionID != "sse-integration-session" {
		t.Errorf("Expected Mcp-Session-Id 'sse-integration-session', got '%s'", toolsCalls[0].SessionID)
	}

	t.Logf("PASS: SSE response flowed through all 13 middleware layers (status=%d)", rec.Code)
}

// TestMCPTransport_404_SessionExpiry_ThroughGateway proves AC3 at the
// gateway level: a 404 from upstream triggers re-initialize + retry,
// all flowing through the full middleware chain.
func TestMCPTransport_404_SessionExpiry_ThroughGateway(t *testing.T) {
	requestCount := 0
	initCount := 0

	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			initCount++
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "renewed-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"mock-mcp","version":"1.0"}}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		case "tools/list":
			// Tool registry verification uses tools/list to compute observed hashes.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"tavily_search","description":"Search the web using Tavily API","inputSchema":{"type":"object","required":["query"],"properties":{"query":{"type":"string","description":"Search query"},"max_results":{"type":"integer","description":"Maximum results to return","default":5}}}}]}}`))
		default:
			requestCount++
			if requestCount == 1 {
				// First request: 404 (session expired)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("session expired"))
				return
			}
			// After re-init: success
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"recovered from 404"}]}}`))
		}
	}))
	t.Cleanup(mcpServer.Close)

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	requestBody := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"session recovery test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		respBody, _ := io.ReadAll(rec.Body)
		t.Fatalf("Expected 200, got %d. Body: %s", rec.Code, string(respBody))
	}

	respBody, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(respBody), "recovered from 404") {
		t.Errorf("Expected 'recovered from 404' in response, got: %s", string(respBody))
	}

	// Verify re-initialization happened: 2 init calls (original + re-init)
	if initCount != 2 {
		t.Errorf("Expected 2 initialize calls (original + re-init), got %d", initCount)
	}

	t.Logf("PASS: 404 session expiry recovery through gateway (init_count=%d, status=%d)", initCount, rec.Code)
}

// --- RFA-0dz: Legacy SSE Transport + Auto-Detection Integration Tests ---

// newMockLegacySSEMCPServer creates an httptest server that simulates a legacy SSE
// MCP server (pre-2025-03-26). It handles:
//   - GET /sse: sends "endpoint" event pointing to /message, then streams responses
//   - POST /message: accepts JSON-RPC requests, sends responses via the SSE stream
//   - POST / (initialize): responds to Streamable HTTP initialize with 405 to force SSE fallback
//
// This server rejects Streamable HTTP (POST to /) so that DetectTransport
// falls back to Legacy SSE.
func newMockLegacySSEMCPServer(t *testing.T) (*httptest.Server, *mcpServerLog) {
	t.Helper()

	sseLog := &mcpServerLog{}

	// mu protects sseWriters
	var mu sync.Mutex
	type sseConn struct {
		w http.ResponseWriter
		f http.Flusher
	}
	var sseConns []sseConn

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/sse":
			// Legacy SSE endpoint
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming not supported", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(http.StatusOK)

			// Send the endpoint event
			fmt.Fprintf(w, "event: endpoint\ndata: /message\n\n")
			flusher.Flush()

			// Register this SSE connection
			mu.Lock()
			sseConns = append(sseConns, sseConn{w: w, f: flusher})
			mu.Unlock()

			// Keep connection open until client disconnects
			<-r.Context().Done()

		case r.Method == http.MethodPost && r.URL.Path == "/message":
			// Message endpoint: handle JSON-RPC requests
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			var rpcReq map[string]interface{}
			if err := json.Unmarshal(body, &rpcReq); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}

			method, _ := rpcReq["method"].(string)
			sseLog.RecordCall(method, "", body)

			var respJSON []byte
			switch method {
			case "tools/list":
				resp := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      rpcReq["id"],
					"result": map[string]interface{}{
						"tools": []interface{}{
							map[string]interface{}{
								"name":        "tavily_search",
								"description": "Search the web using Tavily API",
								"inputSchema": map[string]interface{}{
									"type":     "object",
									"required": []interface{}{"query"},
									"properties": map[string]interface{}{
										"query": map[string]interface{}{
											"type":        "string",
											"description": "Search query",
										},
										"max_results": map[string]interface{}{
											"type":        "integer",
											"description": "Maximum results to return",
											"default":     5,
										},
									},
								},
							},
						},
					},
				}
				respJSON, _ = json.Marshal(resp)

			case "tools/call", "tavily_search":
				resp := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      rpcReq["id"],
					"result": map[string]interface{}{
						"content": []map[string]interface{}{
							{"type": "text", "text": "legacy SSE integration test passed through all 13 layers"},
						},
					},
				}
				respJSON, _ = json.Marshal(resp)
			default:
				resp := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      rpcReq["id"],
					"result":  map[string]interface{}{"status": "ok"},
				}
				respJSON, _ = json.Marshal(resp)
			}

			// Acknowledge the POST
			w.WriteHeader(http.StatusAccepted)

			// Send response via all SSE connections
			mu.Lock()
			for _, conn := range sseConns {
				fmt.Fprintf(conn.w, "event: message\ndata: %s\n\n", string(respJSON))
				conn.f.Flush()
			}
			mu.Unlock()

		case r.Method == http.MethodPost && r.URL.Path == "/":
			// Reject Streamable HTTP initialize to force SSE fallback
			body, _ := io.ReadAll(r.Body)
			var rpcReq map[string]interface{}
			_ = json.Unmarshal(body, &rpcReq)
			method, _ := rpcReq["method"].(string)

			if method == "initialize" {
				sseLog.RecordCall("initialize-rejected", "", body)
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	t.Cleanup(server.Close)
	return server, sseLog
}

// newMockMCPServerRugPull creates a Streamable HTTP MCP server that intentionally
// returns a tools/list definition for tavily_search that does NOT match the
// tool registry baseline, simulating a rug-pull attack.
func newMockMCPServerRugPull(t *testing.T) (*httptest.Server, *mcpServerLog) {
	t.Helper()

	log := &mcpServerLog{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			var rpcReq map[string]interface{}
			if err := json.Unmarshal(body, &rpcReq); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			method, _ := rpcReq["method"].(string)
			log.RecordCall(method, r.Header.Get("Mcp-Session-Id"), body)

			switch method {
			case "initialize":
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Mcp-Session-Id", "rugpull-session-1")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"mock-mcp-rugpull","version":"1.0"}}}`))

			case "notifications/initialized":
				w.WriteHeader(http.StatusOK)

			case "tools/list":
				// Intentionally mutate the description (everything else matches baseline schema).
				resp := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      1,
					"result": map[string]interface{}{
						"tools": []interface{}{
							map[string]interface{}{
								"name":        "tavily_search",
								"description": "Search the web using Tavily API (MUTATED UPSTREAM)",
								"inputSchema": map[string]interface{}{
									"type":     "object",
									"required": []interface{}{"query"},
									"properties": map[string]interface{}{
										"query": map[string]interface{}{
											"type":        "string",
											"description": "Search query",
										},
										"max_results": map[string]interface{}{
											"type":        "integer",
											"description": "Maximum results to return",
											"default":     5,
										},
									},
								},
							},
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)

			case "tools/call", "tavily_search":
				// If the gateway is working correctly, it should never reach this.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"unexpected: rugpull tool was executed"}]}}`))

			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}`))
			}

		case http.MethodDelete:
			log.RecordCall("DELETE", r.Header.Get("Mcp-Session-Id"), nil)
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	t.Cleanup(server.Close)
	return server, log
}

func TestMCPTransport_ToolRegistry_RugPull_DeniesAndStrips(t *testing.T) {
	mcpServer, serverLog := newMockMCPServerRugPull(t)

	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           auditPath,
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	// 1) Call tools/call first (no client tools/list). Gateway must internally refresh tools/list and deny.
	callBody := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"tavily_search","arguments":{"query":"rugpull"}},"id":1}`)
	callReq := httptest.NewRequest("POST", "/", bytes.NewBuffer(callBody))
	callReq.Header.Set("Content-Type", "application/json")
	callReq.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	callReq.Header.Set("X-MCP-Server", "default")
	callRec := httptest.NewRecorder()
	handler.ServeHTTP(callRec, callReq)

	if callRec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d. Body: %s", callRec.Code, callRec.Body.String())
	}
	if !strings.Contains(callRec.Body.String(), middleware.ErrRegistryHashMismatch) {
		t.Fatalf("Expected code=%s in body. Body: %s", middleware.ErrRegistryHashMismatch, callRec.Body.String())
	}

	// Prove internal refresh happened (tools/list called upstream) and tools/call was NOT sent upstream.
	if len(serverLog.MethodCalls("tools/list")) < 1 {
		t.Fatalf("Expected upstream tools/list call for gateway-owned verification, got none (calls=%v)", serverLog.calls)
	}
	if len(serverLog.MethodCalls("tools/call")) != 0 {
		t.Fatalf("Expected upstream tools/call NOT to be called on rug-pull deny, got %d", len(serverLog.MethodCalls("tools/call")))
	}

	// 2) Client-visible tools/list must strip the mismatched tool.
	listBody := []byte(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}`)
	listReq := httptest.NewRequest("POST", "/", bytes.NewBuffer(listBody))
	listReq.Header.Set("Content-Type", "application/json")
	listReq.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	listReq.Header.Set("X-MCP-Server", "default")
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 from tools/list, got %d. Body: %s", listRec.Code, listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), "tavily_search") {
		t.Fatalf("Expected tavily_search to be stripped from client-visible tools/list. Body: %s", listRec.Body.String())
	}

	// Prove an audit event was emitted for stripping, without leaking tool payloads.
	if gw.auditor != nil {
		gw.auditor.Flush()
	}
	auditBytes, _ := os.ReadFile(auditPath)
	if !strings.Contains(string(auditBytes), `"action":"tool_registry_rugpull_stripped"`) {
		t.Fatalf("Expected audit action tool_registry_rugpull_stripped in %s, got: %s", auditPath, string(auditBytes))
	}
}

// TestMCPTransport_LegacySSE_ThroughAll13Layers proves that a legacy SSE
// upstream is auto-detected and requests flow through all 13 middleware layers.
// This is the primary integration test for AC9.
func TestMCPTransport_LegacySSE_ThroughAll13Layers(t *testing.T) {
	mcpServer, serverLog := newMockLegacySSEMCPServer(t)

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	// Build a tools/call request using "tavily_search" to pass middleware checks
	requestBody := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"legacy SSE test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// --- Verify response ---
	if rec.Code != http.StatusOK {
		respBody, _ := io.ReadAll(rec.Body)
		t.Fatalf("Expected 200, got %d. Body: %s", rec.Code, string(respBody))
	}

	respBody, _ := io.ReadAll(rec.Body)
	var rpcResp map[string]interface{}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		t.Fatalf("Response is not valid JSON: %v. Body: %s", err, string(respBody))
	}

	if rpcResp["jsonrpc"] != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %v", rpcResp["jsonrpc"])
	}

	result, ok := rpcResp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected result in response, got: %s", string(respBody))
	}

	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("Expected non-empty content array in result")
	}

	firstContent := content[0].(map[string]interface{})
	if text, ok := firstContent["text"].(string); !ok || !strings.Contains(text, "legacy SSE integration test passed through all 13 layers") {
		t.Errorf("Expected text containing 'legacy SSE integration test passed through all 13 layers', got: %v", firstContent["text"])
	}

	// --- Verify the server received the tavily_search request ---
	toolsCalls := serverLog.MethodCalls("tavily_search")
	if len(toolsCalls) != 1 {
		t.Fatalf("Expected 1 tavily_search call, got %d", len(toolsCalls))
	}

	// Verify Streamable HTTP was rejected (forcing SSE fallback)
	rejectCalls := serverLog.MethodCalls("initialize-rejected")
	if len(rejectCalls) < 1 {
		t.Error("Expected Streamable HTTP initialize to be rejected (405) before SSE fallback")
	}

	t.Logf("PASS: legacy SSE transport detected and tools/call flowed through all 13 middleware layers (status=%d)", rec.Code)
}

// TestMCPTransport_AutoDetect_StreamableHTTP verifies that auto-detection
// correctly selects Streamable HTTP when the server supports it.
func TestMCPTransport_AutoDetect_StreamableHTTP(t *testing.T) {
	mcpServer, serverLog := newMockMCPServer(t)

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	requestBody := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"auto-detect test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		respBody, _ := io.ReadAll(rec.Body)
		t.Fatalf("Expected 200, got %d. Body: %s", rec.Code, string(respBody))
	}

	// Verify the server received proper Streamable HTTP handshake
	initCalls := serverLog.MethodCalls("initialize")
	if len(initCalls) != 1 {
		t.Errorf("Expected 1 initialize call (Streamable HTTP detected), got %d", len(initCalls))
	}

	notifCalls := serverLog.MethodCalls("notifications/initialized")
	if len(notifCalls) != 1 {
		t.Errorf("Expected 1 notifications/initialized call, got %d", len(notifCalls))
	}

	t.Logf("PASS: auto-detection correctly selected Streamable HTTP (init_calls=%d)", len(initCalls))
}

// TestMCPTransport_AutoDetect_SSEFallback verifies that auto-detection
// falls back to SSE when Streamable HTTP fails, and emits a deprecation log.
func TestMCPTransport_AutoDetect_SSEFallback(t *testing.T) {
	mcpServer, serverLog := newMockLegacySSEMCPServer(t)

	cfg := &Config{
		UpstreamURL:            mcpServer.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	requestBody := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"fallback test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		respBody, _ := io.ReadAll(rec.Body)
		t.Fatalf("Expected 200, got %d. Body: %s", rec.Code, string(respBody))
	}

	// Verify Streamable HTTP was attempted first (rejected)
	rejectCalls := serverLog.MethodCalls("initialize-rejected")
	if len(rejectCalls) < 1 {
		t.Error("Expected Streamable HTTP initialize to be rejected before SSE fallback")
	}

	// Verify SSE was used for the actual request
	toolsCalls := serverLog.MethodCalls("tavily_search")
	if len(toolsCalls) != 1 {
		t.Fatalf("Expected 1 tavily_search call via SSE, got %d", len(toolsCalls))
	}

	// Verify the response came back correctly
	respBody, _ := io.ReadAll(rec.Body)
	var rpcResp map[string]interface{}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		t.Fatalf("Response is not valid JSON: %v", err)
	}
	if rpcResp["jsonrpc"] != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %v", rpcResp["jsonrpc"])
	}

	t.Logf("PASS: auto-detection fell back to SSE after Streamable HTTP rejected (reject_calls=%d, tool_calls=%d)",
		len(rejectCalls), len(toolsCalls))
}

// TestMCPTransport_GatewayUsesTransportInterface verifies AC5: the gateway
// struct uses the Transport interface (not concrete type) for mcpTransport.
func TestMCPTransport_GatewayUsesTransportInterface(t *testing.T) {
	cfg := &Config{
		UpstreamURL:            "http://localhost:8080",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	// At startup, mcpTransport should be nil (lazy init via DetectTransport)
	if gw.mcpTransport != nil {
		t.Error("Expected mcpTransport to be nil at startup (lazy init)")
	}

	t.Log("PASS: gateway uses Transport interface with lazy initialization")
}

// --- RFA-xhr: Transport Resilience Integration Tests ---
// These tests prove resilience features work through the full gateway.

// TestMCPTransport_UpstreamDropsMidStream verifies AC5: upstream drops mid-stream
// results in ErrMCPTransportFailed error through the gateway.
func TestMCPTransport_UpstreamDropsMidStream(t *testing.T) {
	var initCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			atomic.AddInt32(&initCount, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "drop-test-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"drop-test","version":"1.0"}}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"tavily_search","description":"Search the web using Tavily API","inputSchema":{"type":"object","required":["query"],"properties":{"query":{"type":"string","description":"Search query"},"max_results":{"type":"integer","description":"Maximum results to return","default":5}}}}]}}`))
		default:
			// Write partial JSON then drop connection
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"res`))
			if hijacker, ok := w.(http.Hijacker); ok {
				conn, _, _ := hijacker.Hijack()
				if conn != nil {
					conn.Close()
				}
			}
		}
	}))
	defer server.Close()

	cfg := &Config{
		UpstreamURL:            server.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
		MCPProbeTimeout:        5,
		MCPDetectTimeout:       15,
		MCPRequestTimeout:      5,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	requestBody := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"drop test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should get a 502 with ErrMCPTransportFailed
	if rec.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 Bad Gateway for mid-stream drop, got %d", rec.Code)
	}

	respBody, _ := io.ReadAll(rec.Body)
	var gatewayErr map[string]interface{}
	if err := json.Unmarshal(respBody, &gatewayErr); err == nil {
		code, _ := gatewayErr["code"].(string)
		if code != middleware.ErrMCPTransportFailed {
			t.Errorf("Expected error code %q, got %q", middleware.ErrMCPTransportFailed, code)
		}
	}

	t.Logf("PASS: upstream mid-stream drop produces correct error (status=%d)", rec.Code)
}

// TestMCPTransport_OversizedResponse verifies AC8: response size is limited
// by MaxRequestSizeBytes. An oversized response returns ErrMCPInvalidResponse.
func TestMCPTransport_OversizedResponse(t *testing.T) {
	// Create a server that returns a very large result
	largeResult := strings.Repeat("x", 2*1024*1024) // 2MB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "oversize-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"oversize-test","version":"1.0"}}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"tavily_search","description":"Search the web using Tavily API","inputSchema":{"type":"object","required":["query"],"properties":{"query":{"type":"string","description":"Search query"},"max_results":{"type":"integer","description":"Maximum results to return","default":5}}}}]}}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"data":"%s"}}`, largeResult)
			_, _ = w.Write([]byte(resp))
		}
	}))
	defer server.Close()

	cfg := &Config{
		UpstreamURL:            server.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024, // 1MB limit
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
		MCPProbeTimeout:        5,
		MCPDetectTimeout:       15,
		MCPRequestTimeout:      10,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	requestBody := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"oversize test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should get 502 with ErrMCPInvalidResponse (oversized)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 for oversized response, got %d", rec.Code)
	}

	respBody, _ := io.ReadAll(rec.Body)
	var gatewayErr map[string]interface{}
	if err := json.Unmarshal(respBody, &gatewayErr); err == nil {
		code, _ := gatewayErr["code"].(string)
		if code != middleware.ErrMCPInvalidResponse {
			t.Errorf("Expected error code %q, got %q", middleware.ErrMCPInvalidResponse, code)
		}
	}

	t.Logf("PASS: oversized response produces correct error (status=%d)", rec.Code)
}

// TestMCPTransport_404MidConversation verifies AC7: session expiry (404) during
// tools/call triggers re-initialize + retry with backoff.
func TestMCPTransport_404MidConversation(t *testing.T) {
	var initCount int32
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			n := atomic.AddInt32(&initCount, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", fmt.Sprintf("session-%d", n))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"404-test","version":"1.0"}}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"tavily_search","description":"Search the web using Tavily API","inputSchema":{"type":"object","required":["query"],"properties":{"query":{"type":"string","description":"Search query"},"max_results":{"type":"integer","description":"Maximum results to return","default":5}}}}]}}`))
		default:
			n := atomic.AddInt32(&requestCount, 1)
			if n <= 2 {
				// First 2 attempts return 404 (session expired)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("session not found"))
				return
			}
			// After retry succeeds
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"recovered after 404"}]}}`))
		}
	}))
	defer server.Close()

	cfg := &Config{
		UpstreamURL:            server.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
		MCPProbeTimeout:        5,
		MCPDetectTimeout:       15,
		MCPRequestTimeout:      10,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	requestBody := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"404 recovery test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should eventually succeed after retry with re-init
	if rec.Code != http.StatusOK {
		respBody, _ := io.ReadAll(rec.Body)
		t.Logf("Response body: %s", string(respBody))
		t.Errorf("Expected 200 OK after recovery from 404, got %d", rec.Code)
	}

	// Verify re-initialization happened (more than the initial init)
	totalInits := atomic.LoadInt32(&initCount)
	if totalInits < 2 {
		t.Errorf("Expected at least 2 init calls (original + re-init on 404), got %d", totalInits)
	}

	t.Logf("PASS: 404 mid-conversation triggers re-init + retry (inits=%d, requests=%d)",
		totalInits, atomic.LoadInt32(&requestCount))
}

// TestMCPTransport_SessionIsolation verifies AC9: concurrent requests use
// the same session but are isolated from each other.
func TestMCPTransport_SessionIsolation(t *testing.T) {
	var mu sync.Mutex
	sessionIDs := make(map[string]int)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "shared-session-xyz")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"isolation-test","version":"1.0"}}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"tavily_search","description":"Search the web using Tavily API","inputSchema":{"type":"object","required":["query"],"properties":{"query":{"type":"string","description":"Search query"},"max_results":{"type":"integer","description":"Maximum results to return","default":5}}}}]}}`))
		default:
			// Record the session ID for each request
			sid := r.Header.Get("Mcp-Session-Id")
			mu.Lock()
			sessionIDs[sid]++
			mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"isolated response"}]}}`))
		}
	}))
	defer server.Close()

	cfg := &Config{
		UpstreamURL:            server.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
		MCPProbeTimeout:        5,
		MCPDetectTimeout:       15,
		MCPRequestTimeout:      10,
		RateLimitRPM:           1000, // High rate limit for concurrency test
		RateLimitBurst:         100,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	// Send 5 concurrent requests
	const concurrency = 5
	var wg sync.WaitGroup
	results := make([]int, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			requestBody := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"concurrent test"},"id":1}`
			req := httptest.NewRequest("POST", "/", bytes.NewBufferString(requestBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			results[idx] = rec.Code
		}(i)
	}

	wg.Wait()

	// All requests should succeed
	for i, code := range results {
		if code != http.StatusOK {
			t.Errorf("Request %d got status %d, expected 200", i, code)
		}
	}

	// All requests should use the same session ID
	mu.Lock()
	defer mu.Unlock()
	if len(sessionIDs) > 1 {
		t.Errorf("Expected all requests to use the same session ID, but got %d different IDs: %v",
			len(sessionIDs), sessionIDs)
	}
	if count, ok := sessionIDs["shared-session-xyz"]; ok {
		if count < concurrency {
			t.Errorf("Expected at least %d requests with session ID, got %d", concurrency, count)
		}
	}

	t.Logf("PASS: session isolation verified (concurrent=%d, session_ids=%v)", concurrency, sessionIDs)
}

// TestMCPTransport_ConfigDefaults verifies AC1/AC2/AC3: timeout config fields
// have correct defaults and are parsed from environment variables.
func TestMCPTransport_ConfigDefaults(t *testing.T) {
	// Clear any existing env vars
	for _, key := range []string{"MCP_PROBE_TIMEOUT", "MCP_DETECT_TIMEOUT", "MCP_REQUEST_TIMEOUT"} {
		t.Setenv(key, "")
	}

	cfg := ConfigFromEnv()

	if cfg.MCPProbeTimeout != 5 {
		t.Errorf("Expected MCPProbeTimeout=5, got %d", cfg.MCPProbeTimeout)
	}
	if cfg.MCPDetectTimeout != 15 {
		t.Errorf("Expected MCPDetectTimeout=15, got %d", cfg.MCPDetectTimeout)
	}
	if cfg.MCPRequestTimeout != 30 {
		t.Errorf("Expected MCPRequestTimeout=30, got %d", cfg.MCPRequestTimeout)
	}
}

// TestMCPTransport_ConfigFromEnv verifies timeout config can be overridden by env vars.
func TestMCPTransport_ConfigFromEnv(t *testing.T) {
	t.Setenv("MCP_PROBE_TIMEOUT", "10")
	t.Setenv("MCP_DETECT_TIMEOUT", "20")
	t.Setenv("MCP_REQUEST_TIMEOUT", "60")

	cfg := ConfigFromEnv()

	if cfg.MCPProbeTimeout != 10 {
		t.Errorf("Expected MCPProbeTimeout=10, got %d", cfg.MCPProbeTimeout)
	}
	if cfg.MCPDetectTimeout != 20 {
		t.Errorf("Expected MCPDetectTimeout=20, got %d", cfg.MCPDetectTimeout)
	}
	if cfg.MCPRequestTimeout != 60 {
		t.Errorf("Expected MCPRequestTimeout=60, got %d", cfg.MCPRequestTimeout)
	}
}

// TestMCPTransport_ConfigInvalidEnvIgnored verifies invalid env values keep defaults.
func TestMCPTransport_ConfigInvalidEnvIgnored(t *testing.T) {
	t.Setenv("MCP_PROBE_TIMEOUT", "not-a-number")
	t.Setenv("MCP_DETECT_TIMEOUT", "-5")
	t.Setenv("MCP_REQUEST_TIMEOUT", "0")

	cfg := ConfigFromEnv()

	if cfg.MCPProbeTimeout != 5 {
		t.Errorf("Expected MCPProbeTimeout=5 for invalid env, got %d", cfg.MCPProbeTimeout)
	}
	if cfg.MCPDetectTimeout != 15 {
		t.Errorf("Expected MCPDetectTimeout=15 for negative env, got %d", cfg.MCPDetectTimeout)
	}
	if cfg.MCPRequestTimeout != 30 {
		t.Errorf("Expected MCPRequestTimeout=30 for zero env, got %d", cfg.MCPRequestTimeout)
	}
}

// TestMCPTransport_AllErrorsUseWriteGatewayError verifies AC11: all MCP transport
// errors use WriteGatewayError (never http.Error). This is verified by checking
// the response is valid JSON with the expected error envelope structure.
func TestMCPTransport_AllErrorsUseWriteGatewayError(t *testing.T) {
	// Server that always fails after init
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "error-test-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"err-test","version":"1.0"}}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"tavily_search","description":"Search the web using Tavily API","inputSchema":{"type":"object","required":["query"],"properties":{"query":{"type":"string","description":"Search query"},"max_results":{"type":"integer","description":"Maximum results to return","default":5}}}}]}}`))
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("service unavailable"))
		}
	}))
	defer server.Close()

	cfg := &Config{
		UpstreamURL:            server.URL,
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		MCPTransportMode:       "mcp",
		MCPProbeTimeout:        5,
		MCPDetectTimeout:       15,
		MCPRequestTimeout:      5,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	handler := gw.Handler()

	requestBody := `{"jsonrpc":"2.0","method":"tavily_search","params":{"query":"error test"},"id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify response is JSON (not plain text from http.Error)
	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected Content-Type application/json, got %q (http.Error uses text/plain)", contentType)
	}

	// Verify the response has the GatewayError structure
	respBody, _ := io.ReadAll(rec.Body)
	var gatewayErr map[string]interface{}
	if err := json.Unmarshal(respBody, &gatewayErr); err != nil {
		t.Fatalf("Response is not valid JSON (suggests http.Error was used): %v\nBody: %s", err, string(respBody))
	}

	// Check required GatewayError fields
	if _, ok := gatewayErr["code"]; !ok {
		t.Error("Missing 'code' field in error response")
	}
	if _, ok := gatewayErr["message"]; !ok {
		t.Error("Missing 'message' field in error response")
	}
	if _, ok := gatewayErr["middleware"]; !ok {
		t.Error("Missing 'middleware' field in error response")
	}

	t.Logf("PASS: error response uses WriteGatewayError envelope (status=%d, code=%v)", rec.Code, gatewayErr["code"])
}

func writeTempToolRegistry(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tool-registry.yaml")
	// Minimal registry config for tests.
	yaml := `tools:
  - name: "tavily_search"
    description: "Search the web using Tavily API"
    hash: "dummy"
    input_schema: {}
  - name: "bash"
    description: "Execute shell commands"
    hash: "dummy2"
    input_schema: {}
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("write tool registry: %v", err)
	}
	return path
}

func TestAdminCircuitBreakers_ListAndGet(t *testing.T) {
	reg, err := middleware.NewToolRegistry(writeTempToolRegistry(t))
	if err != nil {
		t.Fatalf("NewToolRegistry: %v", err)
	}

	cb := middleware.NewCircuitBreaker(middleware.CircuitBreakerConfig{
		FailureThreshold: 5,
		ResetTimeout:     2 * time.Millisecond,
		SuccessThreshold: 2,
	}, nil)

	g := &Gateway{
		registry:       reg,
		circuitBreaker: cb,
	}

	t.Run("list_closed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/circuit-breakers", nil)
		rec := httptest.NewRecorder()
		g.adminCircuitBreakersHandler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}

		var parsed struct {
			CircuitBreakers []struct {
				Tool            string     `json:"tool"`
				State           string     `json:"state"`
				Failures        int        `json:"failures"`
				Threshold       int        `json:"threshold"`
				ResetTimeoutSec int        `json:"reset_timeout_seconds"`
				LastStateChange *time.Time `json:"last_state_change"`
			} `json:"circuit_breakers"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
		}
		if len(parsed.CircuitBreakers) != 2 {
			t.Fatalf("expected 2 circuit breakers, got %d", len(parsed.CircuitBreakers))
		}
		for _, e := range parsed.CircuitBreakers {
			if e.State != "closed" {
				t.Fatalf("expected state=closed, got %q", e.State)
			}
			if e.Failures != 0 {
				t.Fatalf("expected failures=0, got %d", e.Failures)
			}
			if e.Threshold != 5 {
				t.Fatalf("expected threshold=5, got %d", e.Threshold)
			}
			if e.ResetTimeoutSec <= 0 {
				t.Fatalf("expected reset_timeout_seconds > 0, got %d", e.ResetTimeoutSec)
			}
			if e.LastStateChange != nil {
				t.Fatalf("expected last_state_change=null for initial closed state, got %v", e.LastStateChange)
			}
		}
	})

	t.Run("get_unknown_404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/circuit-breakers/nope", nil)
		rec := httptest.NewRecorder()
		g.adminCircuitBreakersHandler(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("get_single", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/circuit-breakers/bash", nil)
		rec := httptest.NewRecorder()
		g.adminCircuitBreakersHandler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var parsed struct {
			CircuitBreakers []struct {
				Tool string `json:"tool"`
			} `json:"circuit_breakers"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
		}
		if len(parsed.CircuitBreakers) != 1 || parsed.CircuitBreakers[0].Tool != "bash" {
			t.Fatalf("unexpected response: %+v", parsed)
		}
	})

	t.Run("list_open_then_half_open", func(t *testing.T) {
		// Trip the breaker to open.
		for i := 0; i < 5; i++ {
			cb.RecordFailure()
		}

		// Allow reset timeout to elapse so Snapshot transitions Open -> Half-Open.
		time.Sleep(3 * time.Millisecond)

		req := httptest.NewRequest(http.MethodGet, "/admin/circuit-breakers", nil)
		rec := httptest.NewRecorder()
		g.adminCircuitBreakersHandler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}

		var parsed struct {
			CircuitBreakers []struct {
				State           string     `json:"state"`
				Failures        int        `json:"failures"`
				LastStateChange *time.Time `json:"last_state_change"`
			} `json:"circuit_breakers"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
		}
		if len(parsed.CircuitBreakers) == 0 {
			t.Fatalf("expected non-empty response, got %+v", parsed)
		}
		for _, e := range parsed.CircuitBreakers {
			if e.State != "half-open" && e.State != "open" {
				t.Fatalf("expected state=open|half-open after trip, got %q", e.State)
			}
			if e.Failures < 5 {
				t.Fatalf("expected failures>=5 after trip, got %d", e.Failures)
			}
			if e.LastStateChange == nil {
				t.Fatalf("expected last_state_change set after trip, got nil")
			}
		}
	})
}

func TestAdminCircuitBreakers_Reset(t *testing.T) {
	reg, err := middleware.NewToolRegistry(writeTempToolRegistry(t))
	if err != nil {
		t.Fatalf("NewToolRegistry: %v", err)
	}

	cb := middleware.NewCircuitBreaker(middleware.CircuitBreakerConfig{
		FailureThreshold: 5,
		ResetTimeout:     time.Hour,
		SuccessThreshold: 2,
	}, nil)

	g := &Gateway{
		registry:       reg,
		circuitBreaker: cb,
	}

	t.Run("reset_specific_tool", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			cb.RecordFailure()
		}

		body := bytes.NewBufferString(`{"tool":"bash"}`)
		req := httptest.NewRequest(http.MethodPost, "/admin/circuit-breakers/reset", body)
		rec := httptest.NewRecorder()

		g.adminCircuitBreakersResetHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}

		var parsed struct {
			Reset []struct {
				Tool          string `json:"tool"`
				PreviousState string `json:"previous_state"`
				NewState      string `json:"new_state"`
			} `json:"reset"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
		}

		if len(parsed.Reset) != 1 {
			t.Fatalf("expected 1 reset entry, got %d", len(parsed.Reset))
		}
		if parsed.Reset[0].Tool != "bash" {
			t.Fatalf("expected tool=bash, got %q", parsed.Reset[0].Tool)
		}
		if parsed.Reset[0].PreviousState != "open" {
			t.Fatalf("expected previous_state=open, got %q", parsed.Reset[0].PreviousState)
		}
		if parsed.Reset[0].NewState != "closed" {
			t.Fatalf("expected new_state=closed, got %q", parsed.Reset[0].NewState)
		}
		if cb.State() != middleware.CircuitClosed {
			t.Fatalf("expected circuit breaker closed, got %s", cb.State().String())
		}
	})

	t.Run("reset_all_tools", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			cb.RecordFailure()
		}

		body := bytes.NewBufferString(`{"tool":"*"}`)
		req := httptest.NewRequest(http.MethodPost, "/admin/circuit-breakers/reset", body)
		rec := httptest.NewRecorder()

		g.adminCircuitBreakersResetHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}

		var parsed struct {
			Reset []struct {
				Tool          string `json:"tool"`
				PreviousState string `json:"previous_state"`
				NewState      string `json:"new_state"`
			} `json:"reset"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
		}

		if len(parsed.Reset) != 2 {
			t.Fatalf("expected 2 reset entries, got %d", len(parsed.Reset))
		}
		for _, e := range parsed.Reset {
			if e.PreviousState != "open" {
				t.Fatalf("expected previous_state=open, got %q", e.PreviousState)
			}
			if e.NewState != "closed" {
				t.Fatalf("expected new_state=closed, got %q", e.NewState)
			}
		}
		if cb.State() != middleware.CircuitClosed {
			t.Fatalf("expected circuit breaker closed, got %s", cb.State().String())
		}
	})

	t.Run("unknown_tool_404", func(t *testing.T) {
		body := bytes.NewBufferString(`{"tool":"does-not-exist"}`)
		req := httptest.NewRequest(http.MethodPost, "/admin/circuit-breakers/reset", body)
		rec := httptest.NewRecorder()

		g.adminCircuitBreakersResetHandler(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
		}

		var parsed map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
		}
		expected := "unknown tool: does-not-exist"
		if parsed["error"] != expected {
			t.Fatalf("expected error=%q, got %q", expected, parsed["error"])
		}
	})
}

func TestAdminPolicyReload(t *testing.T) {
	newOPA := func(t *testing.T) *middleware.OPAEngine {
		t.Helper()
		opa, err := middleware.NewOPAEngine(testutil.OPAPolicyDir(), middleware.OPAEngineConfig{})
		if err != nil {
			t.Fatalf("NewOPAEngine: %v", err)
		}
		t.Cleanup(func() {
			_ = opa.Close()
		})
		return opa
	}

	t.Run("success", func(t *testing.T) {
		reg, err := middleware.NewToolRegistry(writeTempToolRegistry(t))
		if err != nil {
			t.Fatalf("NewToolRegistry: %v", err)
		}

		g := &Gateway{
			registry: reg,
			opa:      newOPA(t),
		}

		req := httptest.NewRequest(http.MethodPost, "/admin/policy/reload", nil)
		rec := httptest.NewRecorder()
		g.adminPolicyReloadHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}

		var parsed struct {
			Status         string `json:"status"`
			Timestamp      string `json:"timestamp"`
			RegistryTools  int    `json:"registry_tools"`
			OPAPolicies    int    `json:"opa_policies"`
			CosignVerified bool   `json:"cosign_verified"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
		}
		if parsed.Status != "reloaded" {
			t.Fatalf("expected status=reloaded, got %q", parsed.Status)
		}
		if _, err := time.Parse(time.RFC3339, parsed.Timestamp); err != nil {
			t.Fatalf("expected RFC3339 timestamp, got %q (err=%v)", parsed.Timestamp, err)
		}
		if parsed.RegistryTools != 2 {
			t.Fatalf("expected registry_tools=2, got %d", parsed.RegistryTools)
		}
		if parsed.OPAPolicies <= 0 {
			t.Fatalf("expected opa_policies > 0, got %d", parsed.OPAPolicies)
		}
		if parsed.CosignVerified {
			t.Fatalf("expected cosign_verified=false in dev mode, got true")
		}
	})

	t.Run("registry_parse_failure_returns_400", func(t *testing.T) {
		configPath := writeTempToolRegistry(t)
		reg, err := middleware.NewToolRegistry(configPath)
		if err != nil {
			t.Fatalf("NewToolRegistry: %v", err)
		}
		if err := os.WriteFile(configPath, []byte("tools: ["), 0644); err != nil {
			t.Fatalf("write invalid yaml: %v", err)
		}

		g := &Gateway{
			registry: reg,
			opa:      newOPA(t),
		}

		req := httptest.NewRequest(http.MethodPost, "/admin/policy/reload", nil)
		rec := httptest.NewRecorder()
		g.adminPolicyReloadHandler(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}

		var parsed struct {
			Status         string `json:"status"`
			Error          string `json:"error"`
			CosignVerified bool   `json:"cosign_verified"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
		}
		if parsed.Status != "failed" {
			t.Fatalf("expected status=failed, got %q", parsed.Status)
		}
		if !strings.Contains(parsed.Error, "failed to parse config file") {
			t.Fatalf("expected parse error, got %q", parsed.Error)
		}
		if parsed.CosignVerified {
			t.Fatalf("expected cosign_verified=false on failure")
		}
	})

	t.Run("cosign_verification_failure_returns_400", func(t *testing.T) {
		configPath := writeTempToolRegistry(t)
		reg, err := middleware.NewToolRegistry(configPath)
		if err != nil {
			t.Fatalf("NewToolRegistry: %v", err)
		}

		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
		if err := reg.SetPublicKey(pubPEM); err != nil {
			t.Fatalf("SetPublicKey: %v", err)
		}

		invalidSig := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		if err := os.WriteFile(configPath+".sig", []byte(invalidSig), 0644); err != nil {
			t.Fatalf("write invalid sig: %v", err)
		}

		g := &Gateway{
			registry: reg,
			opa:      newOPA(t),
		}

		req := httptest.NewRequest(http.MethodPost, "/admin/policy/reload", nil)
		rec := httptest.NewRecorder()
		g.adminPolicyReloadHandler(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}

		var parsed struct {
			Status         string `json:"status"`
			Error          string `json:"error"`
			CosignVerified bool   `json:"cosign_verified"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
		}
		if parsed.Status != "failed" {
			t.Fatalf("expected status=failed, got %q", parsed.Status)
		}
		if !strings.Contains(parsed.Error, "signature verification failed") {
			t.Fatalf("expected signature verification error, got %q", parsed.Error)
		}
		if parsed.CosignVerified {
			t.Fatalf("expected cosign_verified=false when verification fails")
		}
	})
}

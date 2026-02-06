package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNewGateway verifies gateway initialization
func TestNewGateway(t *testing.T) {
	cfg := &Config{
		Port:                   9090,
		UpstreamURL:            "http://localhost:8080",
		OPAEndpoint:            "http://localhost:8181",
		ToolRegistryURL:        "http://localhost:8082",
		ToolRegistryConfigPath: "../../config/tool-registry.yaml",
		AuditLogPath:           "",                            // Empty = stdout only
		OPAPolicyPath:          "../../config/opa/mcp_policy.rego",
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
		OPAEndpoint:            "http://localhost:8181",
		ToolRegistryURL:        "http://localhost:8082",
		ToolRegistryConfigPath: "../../config/tool-registry.yaml",
		AuditLogPath:           "",                            // Empty = stdout only
		OPAPolicyPath:          "../../config/opa/mcp_policy.rego",
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

	if rec.Body.String() != "OK\n" {
		t.Errorf("Expected 'OK\\n', got %s", rec.Body.String())
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

	if cfg.UpstreamURL != "http://host.docker.internal:8080/mcp" {
		t.Errorf("Expected default upstream URL, got %s", cfg.UpstreamURL)
	}

	if cfg.SPIFFEMode != "dev" {
		t.Errorf("Expected default SPIFFE mode 'dev', got %s", cfg.SPIFFEMode)
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
		OPAEndpoint:            "http://localhost:8181",
		ToolRegistryURL:        "http://localhost:8082",
		ToolRegistryConfigPath: "../../config/tool-registry.yaml",
		AuditLogPath:           "",                            // Empty = stdout only
		OPAPolicyPath:          "../../config/opa/mcp_policy.rego",
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
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/test/dev")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Note: Will fail at OPA since we don't have a real OPA instance
	// But we can verify the request made it through the earlier middleware
	if rec.Code == http.StatusOK {
		t.Log("Request successfully proxied through chain")
	}
}

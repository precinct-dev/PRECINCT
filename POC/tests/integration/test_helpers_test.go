//go:build integration
// +build integration

// Shared test helpers for integration tests.
// Consolidates common utility functions and variables used across test files.

package integration

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Common service URLs used by integration tests
var (
	gatewayURL = getEnvOrDefault("GATEWAY_URL", "http://localhost:9090")
	opaURL     = getEnvOrDefault("OPA_URL", "http://localhost:8181")
)

// pocDir returns the absolute path to the POC project root.
// It checks the ALLOWED_BASE_PATH env var first, then falls back to
// resolving the path relative to the integration test directory (tests/integration/).
// This makes integration tests portable across machines (RFA-n6g).
func pocDir() string {
	if v := os.Getenv("ALLOWED_BASE_PATH"); v != "" {
		return v
	}
	// Integration tests are in tests/integration/ -- POC root is two levels up.
	abs, err := filepath.Abs("../../")
	if err != nil {
		// Fallback: current working directory (works when run from POC root)
		if wd, err2 := os.Getwd(); err2 == nil {
			return wd
		}
		return "."
	}
	return abs
}

// waitForService waits for a service to be ready by polling its health endpoint.
func waitForService(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service %s not ready after %v", url, timeout)
}

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

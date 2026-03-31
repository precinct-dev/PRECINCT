//go:build integration
// +build integration

// Shared test helpers for integration tests.
// Consolidates common utility functions and variables used across test files.

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/precinct-dev/precinct/internal/precinctcli"
	"github.com/redis/go-redis/v9"
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

func composeArgs(extra ...string) []string {
	root := pocDir()
	args := []string{
		"compose",
		"-f", filepath.Join(root, "deploy", "compose", "docker-compose.yml"),
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("DEMO_SERVICE_MODE")), "real") {
		envFile := filepath.Join(root, ".env")
		if _, err := os.Stat(envFile); err == nil {
			args = append(args, "--env-file", envFile)
		}
		args = append(args, "-f", filepath.Join(root, "deploy", "compose", "docker-compose.real.yml"))
	} else {
		args = append(args,
			"-f", filepath.Join(root, "deploy", "compose", "docker-compose.mock.yml"),
			"--profile", "mock",
		)
	}
	return append(args, extra...)
}

func composeCommand(args ...string) *exec.Cmd {
	cmd := exec.Command("docker", composeArgs(args...)...)
	cmd.Dir = pocDir()
	return cmd
}

func signWithProjectAttestationKey(t *testing.T, path string) {
	t.Helper()

	keyPath := filepath.Join(pocDir(), "config", "attestation-ed25519.key")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read attestation key %s: %v", keyPath, err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatalf("decode PEM attestation key %s", keyPath)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse attestation key %s: %v", keyPath, err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("attestation key %s is %T, want ed25519.PrivateKey", keyPath, parsed)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy file %s for signing: %v", path, err)
	}
	sig := ed25519.Sign(privateKey, content)
	if err := os.WriteFile(path+".sig", []byte(base64.StdEncoding.EncodeToString(sig)), 0o644); err != nil {
		t.Fatalf("write signature %s.sig: %v", path, err)
	}
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

// requireGateway skips the test if the gateway is not reachable.
// Use this at the start of any test that requires a running gateway instance.
// Unlike waitForService (which blocks for up to 30s), this does a single quick
// probe and skips immediately if the gateway is down -- preventing noisy failures
// during normal `make test-integration` runs without a live gateway.
func requireGateway(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(gatewayURL + "/health")
	if err != nil {
		t.Skipf("gateway not reachable at %s (requires running gateway: make up): %v", gatewayURL, err)
	}
	resp.Body.Close()
}

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func resetCircuitBreakerForTool(t *testing.T, tool string) {
	t.Helper()
	body := fmt.Sprintf(`{"tool":%q}`, tool)
	req, err := http.NewRequest(http.MethodPost, gatewayURL+"/admin/circuit-breakers/reset", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build circuit-breaker reset request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", adminSPIFFEIDForTest())

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("reset circuit-breaker %s: %v", tool, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset circuit-breaker %s returned %d", tool, resp.StatusCode)
	}
}

func postGatewayRPCMethod(t *testing.T, spiffeID, method string, params map[string]any) int {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, gatewayURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("gateway request failed: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func integrationKeyDBURL() string {
	if v := strings.TrimSpace(os.Getenv("PRECINCT_KEYDB_URL")); v != "" {
		return v
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:6379", 500*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return "redis://127.0.0.1:6379"
	}
	return "compose://keydb"
}

func keydbUsesCompose(url string) bool {
	return strings.HasPrefix(strings.TrimSpace(url), "compose://")
}

func keydbComposeService(url string) string {
	service := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(url), "compose://"))
	if service == "" {
		return "keydb"
	}
	return service
}

func keydbSetValue(t *testing.T, key, value string, ttl time.Duration) {
	t.Helper()
	keydbURL := integrationKeyDBURL()
	if keydbUsesCompose(keydbURL) {
		seconds := strconv.Itoa(int(ttl / time.Second))
		runComposeKeyDBCLI(t, keydbComposeService(keydbURL), "SET", key, value, "EX", seconds)
		return
	}

	opt, err := redis.ParseURL(keydbURL)
	if err != nil {
		t.Fatalf("parse keydb url %q: %v", keydbURL, err)
	}
	rdb := redis.NewClient(opt)
	defer func() { _ = rdb.Close() }()
	if err := rdb.Set(t.Context(), key, value, ttl).Err(); err != nil {
		t.Fatalf("set %s: %v", key, err)
	}
}

func keydbRPushValues(t *testing.T, key string, values ...string) {
	t.Helper()
	keydbURL := integrationKeyDBURL()
	if keydbUsesCompose(keydbURL) {
		args := append([]string{"RPUSH", key}, values...)
		runComposeKeyDBCLI(t, keydbComposeService(keydbURL), args...)
		return
	}

	opt, err := redis.ParseURL(keydbURL)
	if err != nil {
		t.Fatalf("parse keydb url %q: %v", keydbURL, err)
	}
	rdb := redis.NewClient(opt)
	defer func() { _ = rdb.Close() }()
	items := make([]any, len(values))
	for i, value := range values {
		items[i] = value
	}
	if err := rdb.RPush(t.Context(), key, items...).Err(); err != nil {
		t.Fatalf("rpush %s: %v", key, err)
	}
}

func keydbDeleteKeys(t *testing.T, keys ...string) {
	t.Helper()
	keydbURL := integrationKeyDBURL()
	if keydbUsesCompose(keydbURL) {
		args := append([]string{"DEL"}, keys...)
		runComposeKeyDBCLI(t, keydbComposeService(keydbURL), args...)
		return
	}

	opt, err := redis.ParseURL(keydbURL)
	if err != nil {
		t.Fatalf("parse keydb url %q: %v", keydbURL, err)
	}
	rdb := redis.NewClient(opt)
	defer func() { _ = rdb.Close() }()
	if _, err := rdb.Del(t.Context(), keys...).Result(); err != nil {
		t.Fatalf("del %v: %v", keys, err)
	}
}

func keydbExists(t *testing.T, keys ...string) int64 {
	t.Helper()
	keydbURL := integrationKeyDBURL()
	if keydbUsesCompose(keydbURL) {
		out := runComposeKeyDBCLI(t, keydbComposeService(keydbURL), append([]string{"EXISTS"}, keys...)...)
		n, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
		if err != nil {
			t.Fatalf("parse EXISTS output %q: %v", out, err)
		}
		return n
	}

	opt, err := redis.ParseURL(keydbURL)
	if err != nil {
		t.Fatalf("parse keydb url %q: %v", keydbURL, err)
	}
	rdb := redis.NewClient(opt)
	defer func() { _ = rdb.Close() }()
	n, err := rdb.Exists(t.Context(), keys...).Result()
	if err != nil {
		t.Fatalf("exists %v: %v", keys, err)
	}
	return n
}

func runComposeKeyDBCLI(t *testing.T, service string, args ...string) string {
	t.Helper()
	out, err := tryRunComposeKeyDBCLI(service, args...)
	if err != nil {
		t.Fatalf("compose service command for %s failed: %v", service, err)
	}
	return out
}

func tryRunComposeKeyDBCLI(service string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := precinctcli.RunComposeServiceCommand(ctx, service, append([]string{"keydb-cli", "--raw"}, args...)...)
	if err != nil {
		return "", err
	}
	return out, nil
}

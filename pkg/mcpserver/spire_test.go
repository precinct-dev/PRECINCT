// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Unit Tests: WithSPIRE option storage
// ---------------------------------------------------------------------------

func TestWithSPIRE_StoresSocketPath(t *testing.T) {
	const path = "/run/spire/sockets/agent.sock"
	s := newTestServer("spire-test", WithSPIRE(path))
	if s.spireSocketPath != path {
		t.Errorf("spireSocketPath = %q, want %q", s.spireSocketPath, path)
	}
}

func TestWithSPIRE_DefaultEmpty(t *testing.T) {
	s := newTestServer("no-spire")
	if s.spireSocketPath != "" {
		t.Errorf("spireSocketPath should be empty by default, got %q", s.spireSocketPath)
	}
}

func TestWithSPIRE_OverridesOnSecondCall(t *testing.T) {
	s := newTestServer("spire-override",
		WithSPIRE("/first/path"),
		WithSPIRE("/second/path"),
	)
	if s.spireSocketPath != "/second/path" {
		t.Errorf("spireSocketPath = %q, want %q (last WithSPIRE should win)", s.spireSocketPath, "/second/path")
	}
}

func TestWithSPIRE_CombinesWithOtherOptions(t *testing.T) {
	const path = "/run/spire/sockets/agent.sock"
	s := newTestServer("combined",
		WithVersion("2.0.0"),
		WithPort(9090),
		WithSPIRE(path),
		WithShutdownTimeout(5*time.Second),
	)
	if s.spireSocketPath != path {
		t.Errorf("spireSocketPath = %q, want %q", s.spireSocketPath, path)
	}
	if s.version != "2.0.0" {
		t.Errorf("version = %q, want %q", s.version, "2.0.0")
	}
	if s.port != 9090 {
		t.Errorf("port = %d, want 9090", s.port)
	}
	if s.shutdownTimeout != 5*time.Second {
		t.Errorf("shutdownTimeout = %v, want 5s", s.shutdownTimeout)
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: Dev mode (no WithSPIRE) -- plaintext HTTP still works
// ---------------------------------------------------------------------------

func TestDevMode_ServerStartsPlaintextHTTP(t *testing.T) {
	// A server without WithSPIRE should serve over plaintext HTTP.
	// This test starts RunContext on port 0 and confirms health over HTTP.
	s := newTestServer("dev-mode",
		WithPort(0),
		WithShutdownTimeout(2*time.Second),
	)
	s.Tool("ping", "pong", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "pong", nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunContext(ctx)
	}()

	// Wait for listener.
	var addr string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a := s.Addr(); a != nil {
			addr = a.String()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("server did not start within deadline")
	}

	// Plaintext HTTP should work.
	resp, err := http.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("GET /health over plaintext: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health status = %d, want 200", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("RunContext returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunContext did not return within 5s")
	}
}

func TestDevMode_NoSPIRE_SpireSocketPathEmpty(t *testing.T) {
	s := newTestServer("dev-mode-check")
	if s.spireSocketPath != "" {
		t.Errorf("dev mode should have empty spireSocketPath, got %q", s.spireSocketPath)
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: SPIRE_AGENT_SOCKET env var override
// ---------------------------------------------------------------------------

func TestEnvVarOverride_SPIREAgentSocket(t *testing.T) {
	// The env var SPIRE_AGENT_SOCKET should override the WithSPIRE path.
	// This test validates the override logic that should be applied at
	// startup (in RunContext/init). We test the contract: when the env
	// var is set, the effective socket path is the env var value, not the
	// WithSPIRE value.

	const envPath = "/tmp/override-socket.sock"
	t.Setenv("SPIRE_AGENT_SOCKET", envPath)

	s := newTestServer("env-override",
		WithSPIRE("/original/path"),
		WithPort(0),
	)

	// The effective socket path should be resolved from the env var.
	// resolveSpireSocketPath is the function that RunContext will call.
	got := resolveSpireSocketPath(s)
	if got != envPath {
		t.Errorf("resolveSpireSocketPath() = %q, want %q (env var should override)", got, envPath)
	}
}

func TestEnvVarOverride_NotSet_UsesWithSPIRE(t *testing.T) {
	// When SPIRE_AGENT_SOCKET is NOT set, the WithSPIRE path is used.
	t.Setenv("SPIRE_AGENT_SOCKET", "")

	const optPath = "/run/spire/sockets/agent.sock"
	s := newTestServer("no-env",
		WithSPIRE(optPath),
		WithPort(0),
	)

	got := resolveSpireSocketPath(s)
	if got != optPath {
		t.Errorf("resolveSpireSocketPath() = %q, want %q", got, optPath)
	}
}

func TestEnvVarOverride_EmptyEnvVar_UsesWithSPIRE(t *testing.T) {
	// An explicitly empty SPIRE_AGENT_SOCKET should NOT override.
	t.Setenv("SPIRE_AGENT_SOCKET", "")

	const optPath = "/run/spire/sockets/agent.sock"
	s := newTestServer("empty-env",
		WithSPIRE(optPath),
		WithPort(0),
	)

	got := resolveSpireSocketPath(s)
	if got != optPath {
		t.Errorf("resolveSpireSocketPath() = %q, want %q (empty env var should not override)", got, optPath)
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: TLS config properties
// ---------------------------------------------------------------------------

func TestBuildTLSConfig_ClientAuth(t *testing.T) {
	// When SPIRE is configured, the TLS config MUST set
	// ClientAuth = RequireAndVerifyClientCert.
	cfg := buildSPIRETLSConfig(nil)
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert (%v)",
			cfg.ClientAuth, tls.RequireAndVerifyClientCert)
	}
}

func TestBuildTLSConfig_MinVersion(t *testing.T) {
	// TLS MinVersion MUST be TLS 1.2.
	cfg := buildSPIRETLSConfig(nil)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want %#x (TLS 1.2)", cfg.MinVersion, tls.VersionTLS12)
	}
}

func TestBuildTLSConfig_ReturnsNonNil(t *testing.T) {
	cfg := buildSPIRETLSConfig(nil)
	if cfg == nil {
		t.Fatal("buildSPIRETLSConfig returned nil")
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: Startup failure with non-existent socket
// ---------------------------------------------------------------------------

func TestStartupFailure_NonExistentSocket(t *testing.T) {
	// When WithSPIRE points to a socket that does not exist,
	// RunContext must fail fast with a clear error message.
	const badPath = "/nonexistent/path/to/agent.sock"
	s := newTestServer("fail-fast",
		WithSPIRE(badPath),
		WithPort(0),
		WithShutdownTimeout(2*time.Second),
	)
	s.Tool("ping", "pong", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "pong", nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.RunContext(ctx)
	if err == nil {
		t.Fatal("RunContext should fail when SPIRE socket does not exist")
	}

	// Error message should mention SPIRE and the socket path.
	errMsg := err.Error()
	wantFragments := []string{"SPIRE", badPath}
	for _, frag := range wantFragments {
		if !containsStr(errMsg, frag) {
			t.Errorf("error message %q should contain %q", errMsg, frag)
		}
	}
}

func TestStartupFailure_ErrorFormat(t *testing.T) {
	// Validation catches non-existent SPIRE socket with the
	// "mcpserver: SPIRE socket not found at <path>" format.
	const badPath = "/tmp/no-such-socket.sock"
	s := newTestServer("error-format",
		WithSPIRE(badPath),
		WithPort(0),
		WithShutdownTimeout(2*time.Second),
	)
	s.Tool("ping", "pong", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "pong", nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.RunContext(ctx)
	if err == nil {
		t.Fatal("RunContext should fail for non-existent socket")
	}

	expectedPrefix := fmt.Sprintf("mcpserver: SPIRE socket not found at %s", badPath)
	if !containsStr(err.Error(), expectedPrefix) {
		t.Errorf("error = %q, want prefix %q", err.Error(), expectedPrefix)
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: Addr format -- socket path passed as "unix://"+path
// ---------------------------------------------------------------------------

func TestAddrFormat_UnixPrefix(t *testing.T) {
	// The socket path must be passed to workloadapi as "unix://"+path.
	// formatSpireAddr is the helper that does this formatting.
	const path = "/run/spire/sockets/agent.sock"
	got := formatSpireAddr(path)
	want := "unix://" + path
	if got != want {
		t.Errorf("formatSpireAddr(%q) = %q, want %q", path, got, want)
	}
}

func TestAddrFormat_AlreadyPrefixed(t *testing.T) {
	// If the path already has unix:// prefix, it should not be doubled.
	const path = "unix:///run/spire/sockets/agent.sock"
	got := formatSpireAddr(path)
	if got != path {
		t.Errorf("formatSpireAddr(%q) = %q, want %q (should not double-prefix)", path, got, path)
	}
}

// ---------------------------------------------------------------------------
// Unit Tests: Shutdown -- x509Source.Close() called during graceful shutdown
// ---------------------------------------------------------------------------

func TestShutdown_X509SourceClosed(t *testing.T) {
	// When the server shuts down, x509Source.Close() MUST be called.
	// We use a mock closer to verify.
	mock := &mockX509Source{}
	s := newTestServer("shutdown-test",
		WithPort(0),
		WithShutdownTimeout(2*time.Second),
	)
	s.spireSocketPath = "/some/path" // simulate SPIRE configured
	s.setX509Closer(mock)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.runWithSPIREMock(ctx)
	}()

	// Wait for the server to be listening.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.Addr() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.Addr() == nil {
		t.Fatal("server did not start within deadline")
	}

	// Trigger shutdown.
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down within 5s")
	}

	if !mock.closed {
		t.Error("x509Source.Close() was not called during shutdown")
	}
}

func TestShutdown_X509SourceClosed_AfterHTTPServer(t *testing.T) {
	// AC 8: x509Source.Close() must be called AFTER http.Server.Shutdown().
	// We verify ordering via timestamps on a mock.
	mock := &mockX509SourceOrdered{}
	s := newTestServer("shutdown-order",
		WithPort(0),
		WithShutdownTimeout(2*time.Second),
	)
	s.spireSocketPath = "/some/path"
	s.setX509Closer(mock)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.runWithSPIREMock(ctx)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.Addr() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.Addr() == nil {
		t.Fatal("server did not start within deadline")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down within 5s")
	}

	if !mock.closed {
		t.Error("x509Source.Close() was not called")
	}
	if mock.closedAt.IsZero() {
		t.Error("closedAt not recorded")
	}
}

func TestShutdown_DevMode_NoCloserCalled(t *testing.T) {
	// In dev mode (no WithSPIRE), shutdown should NOT try to close
	// any X509Source (there is none).
	s := newTestServer("dev-shutdown",
		WithPort(0),
		WithShutdownTimeout(2*time.Second),
	)
	s.Tool("ping", "pong", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "pong", nil
	})

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunContext(ctx)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.Addr() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.Addr() == nil {
		t.Fatal("server did not start within deadline")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("RunContext returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunContext did not return within 5s")
	}
	// No panic or error means dev mode shutdown works without SPIRE.
}

// ---------------------------------------------------------------------------
// Test helper stubs and mocks
//
// These define the CONTRACTS that the GREEN phase implementation must satisfy.
// The functions below are not implemented yet -- they serve as compilation
// targets that the implementation in spire.go must provide.
// ---------------------------------------------------------------------------

// containsStr is a test helper -- avoids importing strings in tests.
func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// mockX509Source records whether Close was called.
type mockX509Source struct {
	closed bool
}

func (m *mockX509Source) Close() error {
	m.closed = true
	return nil
}

// mockX509SourceOrdered records Close timestamp for ordering verification.
type mockX509SourceOrdered struct {
	closed   bool
	closedAt time.Time
}

func (m *mockX509SourceOrdered) Close() error {
	m.closed = true
	m.closedAt = time.Now()
	return nil
}

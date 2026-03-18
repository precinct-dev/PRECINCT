package mcpserver

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Unit Tests: validate ---

func TestValidate_ValidConfig(t *testing.T) {
	s := newTestServer("valid-server")
	s.Tool("echo", "Echoes", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	if err := s.validate(); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidate_EmptyName(t *testing.T) {
	s := &Server{
		name:   "",
		port:   8080,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	s.Tool("echo", "Echoes", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	err := s.validate()
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if !strings.Contains(err.Error(), "mcpserver: server name must not be empty") {
		t.Errorf("error = %q, want to contain name error", err.Error())
	}
}

func TestValidate_Port_ZeroIsValid(t *testing.T) {
	// Port 0 means "OS-assigned random port" -- valid for testing.
	s := newTestServer("test")
	s.port = 0
	s.Tool("echo", "Echoes", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	if err := s.validate(); err != nil {
		t.Fatalf("port 0 should be valid (OS-assigned), got: %v", err)
	}
}

func TestValidate_InvalidPort_TooHigh(t *testing.T) {
	s := newTestServer("test")
	s.port = 70000
	s.Tool("echo", "Echoes", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	err := s.validate()
	if err == nil {
		t.Fatal("expected error for port 70000")
	}
	if !strings.Contains(err.Error(), "mcpserver: port 70000 is out of range 0-65535") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestValidate_InvalidPort_Negative(t *testing.T) {
	s := newTestServer("test")
	s.port = -1
	s.Tool("echo", "Echoes", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	err := s.validate()
	if err == nil {
		t.Fatal("expected error for port -1")
	}
	if !strings.Contains(err.Error(), "mcpserver: port -1 is out of range 0-65535") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestValidate_ZeroTools(t *testing.T) {
	s := newTestServer("test")

	err := s.validate()
	if err == nil {
		t.Fatal("expected error for zero tools")
	}
	if !strings.Contains(err.Error(), "mcpserver: at least one tool must be registered") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestValidate_SPIRESocketNotFound(t *testing.T) {
	s := newTestServer("test")
	s.spireSocketPath = "/nonexistent/spire/socket.sock"
	s.Tool("echo", "Echoes", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	err := s.validate()
	if err == nil {
		t.Fatal("expected error for missing SPIRE socket")
	}
	if !strings.Contains(err.Error(), "mcpserver: SPIRE socket not found") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestValidate_SPIRESocketExists(t *testing.T) {
	// Create a temp file to simulate the socket.
	tmp := filepath.Join(t.TempDir(), "spire.sock")
	if err := os.WriteFile(tmp, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	s := newTestServer("test")
	s.spireSocketPath = tmp
	s.Tool("echo", "Echoes", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	if err := s.validate(); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidate_SPIRESocketWithUnixPrefix(t *testing.T) {
	s := newTestServer("test")
	s.spireSocketPath = "unix:///nonexistent/spire/socket.sock"
	s.Tool("echo", "Echoes", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	err := s.validate()
	if err == nil {
		t.Fatal("expected error for missing SPIRE socket with unix:// prefix")
	}
	if !strings.Contains(err.Error(), "mcpserver: SPIRE socket not found") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestValidate_BatchErrors_AllReportedAtOnce(t *testing.T) {
	s := &Server{
		name:            "",
		port:            -1,
		spireSocketPath: "/nonexistent/socket",
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:           newSessionStore(),
	}
	// No tools registered either.

	err := s.validate()
	if err == nil {
		t.Fatal("expected multiple errors")
	}

	errStr := err.Error()

	// Should contain all four errors at once.
	if !strings.Contains(errStr, "server name must not be empty") {
		t.Errorf("missing name error in: %s", errStr)
	}
	if !strings.Contains(errStr, "port -1 is out of range") {
		t.Errorf("missing port error in: %s", errStr)
	}
	if !strings.Contains(errStr, "at least one tool must be registered") {
		t.Errorf("missing tools error in: %s", errStr)
	}
	if !strings.Contains(errStr, "SPIRE socket not found") {
		t.Errorf("missing SPIRE socket error in: %s", errStr)
	}
}

func TestValidate_ValidPort_Boundaries(t *testing.T) {
	for _, port := range []int{0, 1, 80, 443, 8080, 65535} {
		s := newTestServer("test")
		s.port = port
		s.Tool("echo", "Echoes", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
			return "ok", nil
		})

		if err := s.validate(); err != nil {
			t.Errorf("port %d should be valid, got error: %v", port, err)
		}
	}
}

func TestValidate_ErrorMessageFormat(t *testing.T) {
	s := &Server{
		name:   "",
		port:   99999,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  newSessionStore(),
	}
	// No tools -- triggers multiple errors.

	err := s.validate()
	if err == nil {
		t.Fatal("expected error")
	}

	// Every error line must start with "mcpserver: ".
	for _, line := range strings.Split(err.Error(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "mcpserver: ") {
			t.Errorf("error line does not follow format: %q", line)
		}
	}
}

// --- Unit Tests: applyEnvOverrides ---

// envGuard sets an env var for the test and returns a cleanup function.
func envGuard(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv(key, value)
}

func TestApplyEnvOverrides_PORT(t *testing.T) {
	envGuard(t, "PORT", "9090")

	s := newTestServer("test")
	if err := applyEnvOverrides(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.port != 9090 {
		t.Errorf("port = %d, want 9090", s.port)
	}
}

func TestApplyEnvOverrides_PORT_Invalid(t *testing.T) {
	envGuard(t, "PORT", "not-a-number")

	s := newTestServer("test")
	err := applyEnvOverrides(s)
	if err == nil {
		t.Fatal("expected error for invalid PORT")
	}
	if !strings.Contains(err.Error(), "mcpserver: invalid PORT") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestApplyEnvOverrides_PORT_OverridesFunctionalOption(t *testing.T) {
	envGuard(t, "PORT", "3000")

	s := newTestServer("test", WithPort(9090))
	if err := applyEnvOverrides(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.port != 3000 {
		t.Errorf("port = %d, want 3000 (env should override option)", s.port)
	}
}

func TestApplyEnvOverrides_CACHE_ENABLED_False(t *testing.T) {
	envGuard(t, "CACHE_ENABLED", "false")

	s := newTestServer("test")
	if err := applyEnvOverrides(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s.cachingDisabled {
		t.Error("cachingDisabled should be true when CACHE_ENABLED=false")
	}
}

func TestApplyEnvOverrides_CACHE_ENABLED_True(t *testing.T) {
	envGuard(t, "CACHE_ENABLED", "true")

	s := newTestServer("test", WithoutCaching())
	if err := applyEnvOverrides(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.cachingDisabled {
		t.Error("cachingDisabled should be false when CACHE_ENABLED=true")
	}
}

func TestApplyEnvOverrides_CACHE_ENABLED_Invalid(t *testing.T) {
	envGuard(t, "CACHE_ENABLED", "maybe")

	s := newTestServer("test")
	err := applyEnvOverrides(s)
	if err == nil {
		t.Fatal("expected error for invalid CACHE_ENABLED")
	}
	if !strings.Contains(err.Error(), "mcpserver: invalid CACHE_ENABLED") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestApplyEnvOverrides_CACHE_TTL(t *testing.T) {
	envGuard(t, "CACHE_TTL", "10m")

	s := newTestServer("test")
	if err := applyEnvOverrides(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.cacheTTL != 10*time.Minute {
		t.Errorf("cacheTTL = %v, want 10m", s.cacheTTL)
	}
}

func TestApplyEnvOverrides_CACHE_TTL_Invalid(t *testing.T) {
	envGuard(t, "CACHE_TTL", "not-a-duration")

	s := newTestServer("test")
	err := applyEnvOverrides(s)
	if err == nil {
		t.Fatal("expected error for invalid CACHE_TTL")
	}
	if !strings.Contains(err.Error(), "mcpserver: invalid CACHE_TTL") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestApplyEnvOverrides_LOG_LEVEL_Valid(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error", "DEBUG", "Info", "WARN"} {
		t.Run(level, func(t *testing.T) {
			envGuard(t, "LOG_LEVEL", level)

			s := newTestServer("test")
			if err := applyEnvOverrides(s); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// Logger should have been replaced (not nil).
			if s.logger == nil {
				t.Error("logger should not be nil")
			}
		})
	}
}

func TestApplyEnvOverrides_LOG_LEVEL_Invalid(t *testing.T) {
	envGuard(t, "LOG_LEVEL", "verbose")

	s := newTestServer("test")
	err := applyEnvOverrides(s)
	if err == nil {
		t.Fatal("expected error for invalid LOG_LEVEL")
	}
	if !strings.Contains(err.Error(), "mcpserver: invalid LOG_LEVEL") {
		t.Errorf("error = %q", err.Error())
	}
	if !strings.Contains(err.Error(), "must be one of debug, info, warn, error") {
		t.Errorf("error = %q, should list valid values", err.Error())
	}
}

func TestApplyEnvOverrides_RATE_LIMIT_ENABLED_False(t *testing.T) {
	envGuard(t, "RATE_LIMIT_ENABLED", "false")

	s := newTestServer("test")
	if err := applyEnvOverrides(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s.rateLimitDisabled {
		t.Error("rateLimitDisabled should be true when RATE_LIMIT_ENABLED=false")
	}
}

func TestApplyEnvOverrides_RATE_LIMIT_ENABLED_Invalid(t *testing.T) {
	envGuard(t, "RATE_LIMIT_ENABLED", "nah")

	s := newTestServer("test")
	err := applyEnvOverrides(s)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "mcpserver: invalid RATE_LIMIT_ENABLED") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestApplyEnvOverrides_RATE_LIMIT_RPS(t *testing.T) {
	envGuard(t, "RATE_LIMIT_RPS", "50.5")

	s := newTestServer("test")
	if err := applyEnvOverrides(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.rateRPS != 50.5 {
		t.Errorf("rateRPS = %v, want 50.5", s.rateRPS)
	}
}

func TestApplyEnvOverrides_RATE_LIMIT_RPS_Invalid(t *testing.T) {
	envGuard(t, "RATE_LIMIT_RPS", "fast")

	s := newTestServer("test")
	err := applyEnvOverrides(s)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "mcpserver: invalid RATE_LIMIT_RPS") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestApplyEnvOverrides_RATE_LIMIT_BURST(t *testing.T) {
	envGuard(t, "RATE_LIMIT_BURST", "20")

	s := newTestServer("test")
	if err := applyEnvOverrides(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.rateBurst != 20 {
		t.Errorf("rateBurst = %d, want 20", s.rateBurst)
	}
}

func TestApplyEnvOverrides_RATE_LIMIT_BURST_Invalid(t *testing.T) {
	envGuard(t, "RATE_LIMIT_BURST", "lots")

	s := newTestServer("test")
	err := applyEnvOverrides(s)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "mcpserver: invalid RATE_LIMIT_BURST") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestApplyEnvOverrides_SHUTDOWN_TIMEOUT(t *testing.T) {
	envGuard(t, "SHUTDOWN_TIMEOUT", "30s")

	s := newTestServer("test")
	if err := applyEnvOverrides(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.shutdownTimeout != 30*time.Second {
		t.Errorf("shutdownTimeout = %v, want 30s", s.shutdownTimeout)
	}
}

func TestApplyEnvOverrides_SHUTDOWN_TIMEOUT_Invalid(t *testing.T) {
	envGuard(t, "SHUTDOWN_TIMEOUT", "long")

	s := newTestServer("test")
	err := applyEnvOverrides(s)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "mcpserver: invalid SHUTDOWN_TIMEOUT") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestApplyEnvOverrides_MultipleInvalidVars(t *testing.T) {
	envGuard(t, "PORT", "abc")
	envGuard(t, "CACHE_TTL", "xyz")
	envGuard(t, "LOG_LEVEL", "trace")

	s := newTestServer("test")
	err := applyEnvOverrides(s)
	if err == nil {
		t.Fatal("expected multiple errors")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "invalid PORT") {
		t.Errorf("missing PORT error in: %s", errStr)
	}
	if !strings.Contains(errStr, "invalid CACHE_TTL") {
		t.Errorf("missing CACHE_TTL error in: %s", errStr)
	}
	if !strings.Contains(errStr, "invalid LOG_LEVEL") {
		t.Errorf("missing LOG_LEVEL error in: %s", errStr)
	}
}

func TestApplyEnvOverrides_NoEnvVarsSet(t *testing.T) {
	// Unset all known env vars to ensure clean state.
	for _, key := range []string{"PORT", "SPIRE_AGENT_SOCKET", "LOG_LEVEL",
		"CACHE_ENABLED", "CACHE_TTL", "RATE_LIMIT_ENABLED",
		"RATE_LIMIT_RPS", "RATE_LIMIT_BURST", "SHUTDOWN_TIMEOUT"} {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}

	s := newTestServer("test")
	originalPort := s.port

	if err := applyEnvOverrides(s); err != nil {
		t.Fatalf("unexpected error with no env vars: %v", err)
	}
	if s.port != originalPort {
		t.Errorf("port changed from %d to %d without env var", originalPort, s.port)
	}
}

func TestApplyEnvOverrides_SPIRE_AGENT_SOCKET(t *testing.T) {
	envGuard(t, "SPIRE_AGENT_SOCKET", "/tmp/test-spire.sock")

	s := newTestServer("test")
	if err := applyEnvOverrides(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.spireSocketPath != "/tmp/test-spire.sock" {
		t.Errorf("spireSocketPath = %q, want /tmp/test-spire.sock", s.spireSocketPath)
	}
}

func TestApplyEnvOverrides_SPIRE_AGENT_SOCKET_OverridesOption(t *testing.T) {
	envGuard(t, "SPIRE_AGENT_SOCKET", "/env/socket.sock")

	s := newTestServer("test", WithSPIRE("/option/socket.sock"))
	if err := applyEnvOverrides(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.spireSocketPath != "/env/socket.sock" {
		t.Errorf("spireSocketPath = %q, want /env/socket.sock (env should override option)", s.spireSocketPath)
	}
}

// --- Integration Test: RunContext rejects invalid config ---

func TestRunContext_RejectsZeroTools(t *testing.T) {
	s := newTestServer("no-tools", WithPort(8080))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := s.RunContext(ctx)
	if err == nil {
		t.Fatal("expected error for zero tools")
	}
	if !strings.Contains(err.Error(), "at least one tool must be registered") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestRunContext_RejectsInvalidPort(t *testing.T) {
	s := newTestServer("bad-port")
	s.port = -5
	s.Tool("echo", "Echoes", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := s.RunContext(ctx)
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
	if !strings.Contains(err.Error(), "port -5 is out of range") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestRunContext_RejectsInvalidEnvVar(t *testing.T) {
	envGuard(t, "PORT", "banana")

	s := newTestServer("env-fail", WithPort(8080))
	s.Tool("echo", "Echoes", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := s.RunContext(ctx)
	if err == nil {
		t.Fatal("expected error for invalid PORT env var")
	}
	if !strings.Contains(err.Error(), "mcpserver: invalid PORT") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestRunContext_EnvOverrideTakesPrecedence(t *testing.T) {
	// Use a valid port that differs from the option to prove env wins.
	envGuard(t, "PORT", "18321")

	s := newTestServer("precedence-test", WithPort(9090))
	s.Tool("echo", "Echoes", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunContext(ctx)
	}()

	// Wait for the server to start.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.Addr() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if s.Addr() == nil {
		cancel()
		t.Fatal("server did not start")
	}

	// Verify port 18321 was used (env override), not 9090 (option).
	if s.port != 18321 {
		t.Errorf("port = %d, want 18321 (env override)", s.port)
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

func TestRunContext_BatchValidationErrors(t *testing.T) {
	s := &Server{
		name:            "",
		port:            -1,
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		shutdownTimeout: 2 * time.Second,
		readTimeout:     30 * time.Second,
		writeTimeout:    30 * time.Second,
		store:           newSessionStore(),
	}
	// No tools registered.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := s.RunContext(ctx)
	if err == nil {
		t.Fatal("expected batch errors")
	}

	errStr := err.Error()
	// Should report all errors at once.
	if !strings.Contains(errStr, "server name must not be empty") {
		t.Errorf("missing name error in: %s", errStr)
	}
	if !strings.Contains(errStr, "port -1 is out of range") {
		t.Errorf("missing port error in: %s", errStr)
	}
	if !strings.Contains(errStr, "at least one tool must be registered") {
		t.Errorf("missing tools error in: %s", errStr)
	}
}

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateDevRuntimeGuardrails(t *testing.T) {
	t.Run("prod mode allowed without dev flags", func(t *testing.T) {
		cfg := &Config{
			SPIFFEMode:       "prod",
			Port:             9443,
			PublicListenPort: 0,
		}
		if err := ValidateDevRuntimeGuardrails(cfg); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("prod public listener requires oauth config", func(t *testing.T) {
		cfg := &Config{
			SPIFFEMode:       "prod",
			PublicListenPort: defaultPublicListenPort,
		}
		if err := ValidateDevRuntimeGuardrails(cfg); err == nil {
			t.Fatal("expected error when prod public listener is enabled without oauth config")
		}
	})

	t.Run("prod public listener accepts valid oauth config", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "oauth-resource-server.yaml")
		content := []byte("oauth_resource_server:\n  issuer: http://issuer\n  audience: gateway\n  jwks_url: http://issuer/jwks.json\n")
		if err := os.WriteFile(configPath, content, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		cfg := &Config{
			SPIFFEMode:                    "prod",
			PublicListenPort:              defaultPublicListenPort,
			OAuthResourceServerConfigPath: configPath,
		}
		if err := ValidateDevRuntimeGuardrails(cfg); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("dev mode requires explicit insecure flag", func(t *testing.T) {
		cfg := &Config{
			SPIFFEMode:    "dev",
			Port:          9090,
			DevListenHost: "127.0.0.1",
		}
		if err := ValidateDevRuntimeGuardrails(cfg); err == nil {
			t.Fatal("expected error when ALLOW_INSECURE_DEV_MODE is not enabled")
		}
	})

	t.Run("dev mode loopback allowed when explicit dev flag enabled", func(t *testing.T) {
		cfg := &Config{
			SPIFFEMode:           "dev",
			AllowInsecureDevMode: true,
			Port:                 9090,
			DevListenHost:        "127.0.0.1",
		}
		if err := ValidateDevRuntimeGuardrails(cfg); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("dev mode non-loopback requires explicit override", func(t *testing.T) {
		cfg := &Config{
			SPIFFEMode:           "dev",
			AllowInsecureDevMode: true,
			Port:                 9090,
			DevListenHost:        "0.0.0.0",
		}
		if err := ValidateDevRuntimeGuardrails(cfg); err == nil {
			t.Fatal("expected error for non-loopback dev bind without override")
		}
	})

	t.Run("dev mode non-loopback allowed with explicit override", func(t *testing.T) {
		cfg := &Config{
			SPIFFEMode:              "dev",
			AllowInsecureDevMode:    true,
			AllowNonLoopbackDevBind: true,
			Port:                    9090,
			DevListenHost:           "0.0.0.0",
		}
		if err := ValidateDevRuntimeGuardrails(cfg); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})
}

func TestResolveDevListenAddrDefaults(t *testing.T) {
	cfg := &Config{
		SPIFFEMode:           "dev",
		AllowInsecureDevMode: true,
		Port:                 9090,
	}
	if got := ResolveDevListenAddr(cfg); got != "127.0.0.1:9090" {
		t.Fatalf("expected 127.0.0.1:9090, got %s", got)
	}
}

func TestResolvePublicListenAddrDefaults(t *testing.T) {
	cfg := &Config{
		SPIFFEMode:       "prod",
		PublicListenPort: defaultPublicListenPort,
	}
	if got := ResolvePublicListenAddr(cfg); got != "0.0.0.0:9090" {
		t.Fatalf("expected 0.0.0.0:9090, got %s", got)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{host: "127.0.0.1", want: true},
		{host: "localhost", want: true},
		{host: "::1", want: true},
		{host: "[::1]", want: true},
		{host: "0.0.0.0", want: false},
		{host: "192.168.1.10", want: false},
	}
	for _, tc := range cases {
		if got := isLoopbackHost(tc.host); got != tc.want {
			t.Fatalf("isLoopbackHost(%q)=%t want %t", tc.host, got, tc.want)
		}
	}
}

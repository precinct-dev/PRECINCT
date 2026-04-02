package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/precinct-dev/precinct/internal/testutil"
)

func TestConfigFromEnv_PublicListenerDefaultsAndOverrides(t *testing.T) {
	t.Setenv("PUBLIC_LISTEN_PORT", "")
	t.Setenv("PUBLIC_LISTEN_HOST", "")
	t.Setenv("PUBLIC_ROUTE_ALLOWLIST", "")
	t.Setenv("PUBLIC_TRUSTED_PROXY_CIDRS", "")

	cfg := ConfigFromEnv()
	if cfg.PublicListenPort != defaultPublicListenPort {
		t.Fatalf("PublicListenPort = %d, want %d", cfg.PublicListenPort, defaultPublicListenPort)
	}
	if cfg.PublicListenHost != defaultPublicListenHost {
		t.Fatalf("PublicListenHost = %q, want %q", cfg.PublicListenHost, defaultPublicListenHost)
	}
	if cfg.PublicRouteAllowlist != defaultPublicRouteAllowlist {
		t.Fatalf("PublicRouteAllowlist = %q, want %q", cfg.PublicRouteAllowlist, defaultPublicRouteAllowlist)
	}
	if cfg.PublicTrustedProxyCIDRs != "" {
		t.Fatalf("PublicTrustedProxyCIDRs = %q, want empty", cfg.PublicTrustedProxyCIDRs)
	}

	t.Setenv("PUBLIC_LISTEN_PORT", "19090")
	t.Setenv("PUBLIC_LISTEN_HOST", "127.0.0.1")
	t.Setenv("PUBLIC_ROUTE_ALLOWLIST", "/health,/")
	t.Setenv("PUBLIC_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,192.168.0.0/16")

	cfg = ConfigFromEnv()
	if cfg.PublicListenPort != 19090 {
		t.Fatalf("PublicListenPort = %d, want 19090", cfg.PublicListenPort)
	}
	if cfg.PublicListenHost != "127.0.0.1" {
		t.Fatalf("PublicListenHost = %q, want 127.0.0.1", cfg.PublicListenHost)
	}
	if cfg.PublicRouteAllowlist != "/health,/" {
		t.Fatalf("PublicRouteAllowlist = %q, want /health,/", cfg.PublicRouteAllowlist)
	}
	if cfg.PublicTrustedProxyCIDRs != "10.0.0.0/8,192.168.0.0/16" {
		t.Fatalf("PublicTrustedProxyCIDRs = %q", cfg.PublicTrustedProxyCIDRs)
	}
}

func TestPublicHandler_AllowlistRouting(t *testing.T) {
	gw := newProdPublicGatewayForTest(t, defaultPublicRouteAllowlist)
	handler := gw.PublicHandler()

	t.Run("health is reachable", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("root reaches middleware", func(t *testing.T) {
		body := bytes.NewBufferString(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
		req := httptest.NewRequest(http.MethodPost, "/", body)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}

		var response map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if got := response["code"]; got != "auth_missing_identity" {
			t.Fatalf("code = %v, want auth_missing_identity", got)
		}
	})

	t.Run("non allowlisted path returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/openai/v1/chat/completions", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("exact root match does not expose subpaths", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/foo", bytes.NewBufferString(`{}`))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("custom allowlist can remove root", func(t *testing.T) {
		customGW := newProdPublicGatewayForTest(t, "/health")
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{}`))
		rec := httptest.NewRecorder()

		customGW.PublicHandler().ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("token exchange is not reachable by default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange", bytes.NewBufferString(`{}`))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func newProdPublicGatewayForTest(t *testing.T, allowlist string) *Gateway {
	t.Helper()

	cfg := &Config{
		UpstreamURL:                   "http://127.0.0.1:1",
		OPAPolicyDir:                  testutil.OPAPolicyDir(),
		ToolRegistryConfigPath:        testutil.ToolRegistryConfigPath(),
		AuditLogPath:                  "",
		OPAPolicyPath:                 testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:           1024 * 1024,
		SPIFFEMode:                    "prod",
		SPIFFETrustDomain:             "poc.local",
		PublicListenPort:              defaultPublicListenPort,
		PublicListenHost:              defaultPublicListenHost,
		PublicRouteAllowlist:          allowlist,
		OAuthResourceServerConfigPath: writeGatewayOAuthConfig(t, "http://issuer"),
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })
	return gw
}

package integration

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway"
	"github.com/RamXX/agentic_reference_architecture/POC/internal/testutil"
)

func TestDemoRugpullAdminAuthorizationFlow(t *testing.T) {
	var upstreamCalls int32
	var lastPath atomic.Value
	lastPath.Store("")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamCalls, 1)
		lastPath.Store(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	cfg := &gateway.Config{
		Port:                         9090,
		UpstreamURL:                  upstream.URL,
		OPAPolicyDir:                 testutil.OPAPolicyDir(),
		ToolRegistryConfigPath:       testutil.ToolRegistryConfigPath(),
		AuditLogPath:                 "",
		OPAPolicyPath:                testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:          1024 * 1024,
		SPIFFEMode:                   "dev",
		AllowInsecureDevMode:         true,
		DevListenHost:                "127.0.0.1",
		RateLimitRPM:                 100000,
		RateLimitBurst:               100000,
		DemoRugpullAdminEnabled:      true,
		AdminAuthzAllowedSPIFFEIDs:   []string{"spiffe://poc.local/gateways/mcp-security-gateway/dev"},
		EnforcementProfile:           "dev",
		EnforceModelMediationGate:    true,
		EnforceHIPAAPromptSafetyGate: true,
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	t.Cleanup(func() {
		_ = gw.Close()
	})
	handler := gw.Handler()

	t.Run("unauthenticated denied", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/__demo__/rugpull/off", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("authenticated but unauthorized denied", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/__demo__/rugpull/off", nil)
		req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/not-admin/dev")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("authorized admin succeeds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/__demo__/rugpull/off", nil)
		req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/mcp-security-gateway/dev")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	if got := atomic.LoadInt32(&upstreamCalls); got != 1 {
		t.Fatalf("expected exactly one upstream call, got %d", got)
	}
	if path, _ := lastPath.Load().(string); path != "/__demo__/rugpull/off" {
		t.Fatalf("expected upstream path /__demo__/rugpull/off, got %q", path)
	}
}

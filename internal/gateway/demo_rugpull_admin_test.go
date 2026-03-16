package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/precinct-dev/precinct/internal/testutil"
)

func newDemoRugpullGateway(t *testing.T, upstreamURL string, auditPath string, enabled bool) *Gateway {
	t.Helper()
	cfg := &Config{
		Port:                         9090,
		UpstreamURL:                  upstreamURL,
		OPAPolicyDir:                 testutil.OPAPolicyDir(),
		ToolRegistryConfigPath:       testutil.ToolRegistryConfigPath(),
		AuditLogPath:                 auditPath,
		OPAPolicyPath:                testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:          1024 * 1024,
		SPIFFEMode:                   "dev",
		AllowInsecureDevMode:         true,
		DevListenHost:                "127.0.0.1",
		RateLimitRPM:                 100000,
		RateLimitBurst:               100000,
		DemoRugpullAdminEnabled:      enabled,
		AdminAuthzAllowedSPIFFEIDs:   []string{"spiffe://poc.local/gateways/precinct-gateway/dev"},
		EnforcementProfile:           "dev",
		EnforceModelMediationGate:    true,
		EnforceHIPAAPromptSafetyGate: true,
	}
	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	t.Cleanup(func() {
		_ = gw.Close()
	})
	return gw
}

func TestDemoRugpullEndpointRequiresAdminAuthorization(t *testing.T) {
	var upstreamCalls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	gw := newDemoRugpullGateway(t, upstream.URL, "", true)
	handler := gw.Handler()

	t.Run("missing identity denied before admin auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/__demo__/rugpull/on", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("non-admin identity denied", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/__demo__/rugpull/on", nil)
		req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/not-admin/dev")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("admin identity allowed and forwarded", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/__demo__/rugpull/on", nil)
		req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/precinct-gateway/dev")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	if got := atomic.LoadInt32(&upstreamCalls); got != 1 {
		t.Fatalf("expected exactly one upstream call for authorized request, got %d", got)
	}
}

func TestDemoRugpullEndpointDisabledByDefault(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := newDemoRugpullGateway(t, upstream.URL, "", false)
	req := httptest.NewRequest(http.MethodPost, "/__demo__/rugpull/on", nil)
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/precinct-gateway/dev")
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when demo rugpull is disabled, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDemoRugpullEndpointWritesAuditEvent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	gw := newDemoRugpullGateway(t, upstream.URL, auditPath, true)

	req := httptest.NewRequest(http.MethodPost, "/__demo__/rugpull/on", nil)
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/gateways/precinct-gateway/dev")
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	gw.auditor.Flush()
	content, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	text := string(content)
	for _, want := range []string{
		`"action":"demo_rugpull_enable"`,
		`"result":"allowed"`,
		`"spiffe_id":"spiffe://poc.local/gateways/precinct-gateway/dev"`,
		`"path":"/__demo__/rugpull/on"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected audit log to contain %s, got %s", want, text)
		}
	}
}

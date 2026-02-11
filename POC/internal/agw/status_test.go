package agw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

type fakeDocker struct {
	containers []DockerContainer
}

func (f fakeDocker) PS(ctx context.Context) ([]DockerContainer, error) { return f.containers, nil }

type fakeExec struct {
	out string
	err error
}

func (f fakeExec) Run(ctx context.Context, name string, args ...string) (string, error) {
	return f.out, f.err
}

func TestCollectStatus_AllComponentsOK(t *testing.T) {
	// Gateway /health
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","circuit_breaker":{"state":"closed"}}`))
	}))
	t.Cleanup(gw.Close)

	// Phoenix root
	phoenix := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(phoenix.Close)

	// OTel health extension
	otel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(otel.Close)

	// Redis
	mr := miniredis.RunT(t)
	mr.Set("k1", "v1")
	redisURL := "redis://" + mr.Addr()

	deps := DefaultDeps()
	deps.Docker = fakeDocker{containers: []DockerContainer{
		{Service: "spire-server", State: "running", Health: "healthy"},
		{Service: "spike-nexus", State: "running", Health: "healthy"},
	}}
	deps.Exec = fakeExec{out: "SPIFFE ID\nspiffe://poc.local/spire/agent/x\n", err: nil}
	deps.ReadFile = func(path string) ([]byte, error) {
		return []byte(`server { trust_domain = "poc.local" }`), nil
	}

	cfg := DefaultConfig()
	cfg.GatewayURL = gw.URL
	cfg.PhoenixURL = phoenix.URL
	cfg.OtelHealthURL = otel.URL
	cfg.KeyDBURL = redisURL

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	out, allOK, err := CollectStatus(ctx, cfg, deps)
	if err != nil {
		t.Fatalf("CollectStatus err: %v", err)
	}
	if !allOK {
		t.Fatalf("expected allOK=true, got false (out=%+v)", out)
	}
	if len(out.Components) != 6 {
		t.Fatalf("expected 6 components, got %d", len(out.Components))
	}
}

func TestCollectStatus_ComponentFilterUnknown(t *testing.T) {
	deps := DefaultDeps()
	cfg := DefaultConfig()
	cfg.GatewayURL = "http://example.invalid"
	cfg.Component = "nope"
	_, _, err := CollectStatus(context.Background(), cfg, deps)
	if err == nil {
		t.Fatalf("expected error for unknown component, got nil")
	}
}


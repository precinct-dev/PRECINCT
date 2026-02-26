package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway"
	"github.com/RamXX/agentic_reference_architecture/POC/internal/testutil"
)

func newOpenClawHTTPTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	tmpDir := t.TempDir()
	destinationsPath := filepath.Join(tmpDir, "destinations.yaml")
	if err := os.WriteFile(destinationsPath, []byte("allowed_destinations:\n  - \"127.0.0.1\"\n  - \"localhost\"\n  - \"::1\"\n"), 0644); err != nil {
		t.Fatalf("write destinations.yaml: %v", err)
	}

	cfg := &gateway.Config{
		Port:                   0,
		UpstreamURL:            "http://127.0.0.1:65535",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		RateLimitRPM:           100000,
		RateLimitBurst:         100000,
		SPIFFEMode:             "dev",
		DestinationsConfigPath: destinationsPath,
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("gateway.New failed: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	return httptest.NewServer(gw.Handler())
}

func TestOpenClawHTTP_OpenResponses_Integration(t *testing.T) {
	modelProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl_int_1",
			"choices":[{"index":0,"message":{"role":"assistant","content":"integration response ok"}}],
			"usage":{"prompt_tokens":9,"completion_tokens":5,"total_tokens":14}
		}`))
	}))
	defer modelProvider.Close()

	gatewayServer := newOpenClawHTTPTestServer(t)
	defer gatewayServer.Close()

	reqBody := []byte(`{"model":"llama-3.3-70b-versatile","input":"run integration flow"}`)
	req, err := http.NewRequest(http.MethodPost, gatewayServer.URL+"/v1/responses", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	req.Header.Set("X-Model-Provider", "groq")
	req.Header.Set("X-Provider-Endpoint-Groq", modelProvider.URL)
	req.Header.Set("X-Residency-Intent", "us")
	req.Header.Set("X-Budget-Profile", "standard")
	req.Header.Set("X-Budget-Units", "1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Precinct-Reason-Code"); got != string(gateway.ReasonModelAllow) {
		t.Fatalf("expected reason %s, got %s", gateway.ReasonModelAllow, got)
	}
}

func TestOpenClawHTTP_ToolsInvoke_Integration(t *testing.T) {
	gatewayServer := newOpenClawHTTPTestServer(t)
	defer gatewayServer.Close()

	post := func(body string) (*http.Response, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, gatewayServer.URL+"/tools/invoke", bytes.NewBufferString(body))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		decoded := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&decoded)
		return resp, decoded
	}

	allowResp, allowBody := post(`{"tool":"read","args":{"path":"/tmp/demo.txt"}}`)
	if allowResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for allowed tool, got %d body=%v", allowResp.StatusCode, allowBody)
	}

	denyResp, denyBody := post(`{"tool":"sessions_send","args":{"message":"inject"}}`)
	if denyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for denied tool, got %d body=%v", denyResp.StatusCode, denyBody)
	}
	if got := denyResp.Header.Get("X-Precinct-Reason-Code"); got != string(gateway.ReasonToolCLICommandDenied) {
		t.Fatalf("expected reason %s, got %s", gateway.ReasonToolCLICommandDenied, got)
	}
}

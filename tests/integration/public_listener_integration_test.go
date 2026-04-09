// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/testutil"
)

func TestPublicListener_ProdModeRoutesAndMiddleware(t *testing.T) {
	cfg := &gateway.Config{
		UpstreamURL:                   "http://127.0.0.1:1",
		OPAPolicyDir:                  testutil.OPAPolicyDir(),
		ToolRegistryConfigPath:        testutil.ToolRegistryConfigPath(),
		AuditLogPath:                  "",
		OPAPolicyPath:                 testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:           1024 * 1024,
		SPIFFEMode:                    "prod",
		SPIFFETrustDomain:             "poc.local",
		PublicListenPort:              19090,
		PublicListenHost:              "127.0.0.1",
		PublicRouteAllowlist:          "/,/health",
		OAuthResourceServerConfigPath: writeIntegrationOAuthConfig(t),
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           gw.PublicHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	defer func() {
		_ = srv.Close()
	}()

	baseURL := "http://" + ln.Addr().String()

	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health status = %d, want 200", resp.StatusCode)
	}

	resp, err = http.Get(baseURL + "/not-allowlisted")
	if err != nil {
		t.Fatalf("GET /not-allowlisted: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /not-allowlisted status = %d, want 404", resp.StatusCode)
	}

	reqBody := bytes.NewBufferString(`{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}`)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/", reqBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err = (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST / status = %d, want 401", resp.StatusCode)
	}

	var gatewayErr map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&gatewayErr); err != nil {
		t.Fatalf("Decode error response: %v", err)
	}
	if got := gatewayErr["code"]; got != "auth_missing_identity" {
		t.Fatalf("code = %v, want auth_missing_identity", got)
	}
}

func writeIntegrationOAuthConfig(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "oauth-resource-server.yaml")
	content := []byte("oauth_resource_server:\n" +
		"  issuer: http://issuer\n" +
		"  audience: gateway\n" +
		"  jwks_url: http://issuer/jwks.json\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/testutil"
)

func TestNewPublicServer_ProdOnly(t *testing.T) {
	cfg := &gateway.Config{
		UpstreamURL:                   "http://127.0.0.1:1",
		OPAPolicyDir:                  testutil.OPAPolicyDir(),
		ToolRegistryConfigPath:        testutil.ToolRegistryConfigPath(),
		AuditLogPath:                  "",
		OPAPolicyPath:                 testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:           1024,
		SPIFFEMode:                    "dev",
		Port:                          9090,
		PublicListenPort:              9090,
		PublicListenHost:              "0.0.0.0",
		OAuthResourceServerConfigPath: writeOAuthConfig(t),
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	if srv := newPublicServer(cfg, gw); srv != nil {
		t.Fatal("expected no public server in dev mode")
	}

	cfg.SPIFFEMode = "prod"
	srv := newPublicServer(cfg, gw)
	if srv == nil {
		t.Fatal("expected public server in prod mode")
		return
	}
	if got, want := srv.Addr, "0.0.0.0:9090"; got != want {
		t.Fatalf("public server addr = %q, want %q", got, want)
	}
}

func TestNewInternalServer_UsesModeSpecificAddressing(t *testing.T) {
	cfg := &gateway.Config{
		UpstreamURL:            "http://127.0.0.1:1",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024,
		SPIFFEMode:             "dev",
		Port:                   9090,
		DevListenHost:          "127.0.0.1",
		SPIFFEListenPort:       9443,
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	if got, want := newInternalServer(cfg, gw).Addr, "127.0.0.1:9090"; got != want {
		t.Fatalf("dev internal addr = %q, want %q", got, want)
	}

	cfg.SPIFFEMode = "prod"
	if got, want := newInternalServer(cfg, gw).Addr, ":9443"; got != want {
		t.Fatalf("prod internal addr = %q, want %q", got, want)
	}
}

func writeOAuthConfig(t *testing.T) string {
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

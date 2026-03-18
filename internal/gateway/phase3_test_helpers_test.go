package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/precinct-dev/precinct/internal/testutil"
)

func newPhase3TestGateway(t *testing.T) (*Gateway, *Config) {
	t.Helper()

	tmpDir := t.TempDir()
	destinationsPath := filepath.Join(tmpDir, "destinations.yaml")

	// Allow only local destinations for provider stubs (httptest servers).
	// All other destinations remain blocked by default (see DestinationAllowlistDenied test).
	if err := os.WriteFile(destinationsPath, []byte("allowed_destinations:\n  - \"127.0.0.1\"\n  - \"localhost\"\n  - \"::1\"\n"), 0644); err != nil {
		t.Fatalf("write destinations.yaml: %v", err)
	}

	cfg := &Config{
		Port:                   0,
		UpstreamURL:            "http://localhost:8080",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		AdminAuthzAllowedSPIFFEIDs: []string{
			"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		},
		DestinationsConfigPath: destinationsPath,
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("New gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })
	return gw, cfg
}

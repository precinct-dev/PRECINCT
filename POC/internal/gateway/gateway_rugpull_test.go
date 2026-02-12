package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

func pocRootDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	// file = .../POC/internal/gateway/gateway_rugpull_test.go
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

func TestFilterAndCacheToolsListResponse_StripsMismatchedTool_AndAudits(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	pocRoot := pocRootDir(t)

	// Use real bundle/registry digests to keep Auditor construction realistic.
	auditor, err := middleware.NewAuditor(
		auditPath,
		filepath.Join(pocRoot, "config", "opa", "mcp_policy.rego"),
		filepath.Join(pocRoot, "config", "tool-registry.yaml"),
	)
	if err != nil {
		t.Fatalf("NewAuditor: %v", err)
	}
	defer func() {
		_ = auditor.Close()
	}()

	registry, err := middleware.NewToolRegistry(filepath.Join(pocRoot, "config", "tool-registry.yaml"))
	if err != nil {
		t.Fatalf("NewToolRegistry: %v", err)
	}

	g := &Gateway{
		auditor:            auditor,
		registry:           registry,
		observedToolHashes: middleware.NewObservedToolHashCache(5 * time.Minute),
	}

	// tools/list response with a rug-pulled tavily_search description (hash mismatch vs baseline registry).
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"tools": []any{
				map[string]any{
					"name":        "tavily_search",
					"description": "Search the web using Tavily API (RUGPULL)",
					"inputSchema": map[string]any{
						"type":     "object",
						"required": []any{"query"},
						"properties": map[string]any{
							"query": map[string]any{"type": "string", "description": "Search query"},
						},
					},
				},
				map[string]any{
					"name":        "echo",
					"description": "Returns the input arguments as-is. Useful for testing.",
					"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
				},
			},
		},
	}
	b, _ := json.Marshal(resp)

	req := httptestRequestWithAuditContext(t)
	out := g.filterAndCacheToolsListResponse(req, b, "default")

	var env map[string]any
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("expected JSON envelope, got: %s", string(out))
	}
	result, _ := env["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	for _, it := range tools {
		m, _ := it.(map[string]any)
		if m["name"] == "tavily_search" {
			t.Fatalf("expected tavily_search to be stripped from tools/list")
		}
	}

	// Ensure audit writer has flushed before reading file.
	auditor.Flush()

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	auditOut := string(data)
	if !strings.Contains(auditOut, `"action":"tool_registry_rugpull_stripped"`) {
		t.Fatalf("expected audit log to contain tool_registry_rugpull_stripped, got: %s", auditOut)
	}
	// Security constraint: no tool description/schema should be persisted to logs (avoid log poisoning).
	if strings.Contains(auditOut, "RUGPULL") || strings.Contains(auditOut, "Search the web using Tavily API") {
		t.Fatalf("expected audit log to not contain tool description payload, got: %s", auditOut)
	}
}

func httptestRequestWithAuditContext(t *testing.T) *http.Request {
	t.Helper()
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(nil))
	ctx := req.Context()
	ctx = middleware.WithSessionID(ctx, "test-session")
	ctx = middleware.WithDecisionID(ctx, "test-decision")
	ctx = middleware.WithTraceID(ctx, "test-trace")
	ctx = middleware.WithSPIFFEID(ctx, "spiffe://poc.local/test")
	return req.WithContext(ctx)
}

// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/precinct-dev/precinct/internal/gateway/mcpclient"
)

func writeRegistryYAML(t *testing.T, dir, toolName, toolDesc string, inputSchema map[string]any) string {
	t.Helper()
	hash := ComputeHash(toolDesc, inputSchema)
	p := filepath.Join(dir, "tool-registry.yaml")
	yaml := fmt.Sprintf(`tools:
  - name: %q
    description: %q
    hash: %q
    risk_level: low
`, toolName, toolDesc, hash)
	if err := os.WriteFile(p, []byte(yaml), 0644); err != nil {
		t.Fatalf("write registry yaml: %v", err)
	}
	return p
}

func tavilySchemaBaseline() map[string]any {
	// Must match POC/config/tool-registry.yaml semantics used in ComputeHash.
	return map[string]any{
		"type": "object",
		"required": []any{
			"query",
		},
		"properties": map[string]any{
			"query": map[string]any{
				"type":        "string",
				"description": "Search query",
			},
			"max_results": map[string]any{
				"type":        "integer",
				"description": "Maximum results to return",
				"default":     float64(5), // JSON numbers decode as float64; keep stable for hashing in tests.
			},
		},
	}
}

func TestToolRegistryVerify_ObservedHashRefresh_MissingTriggersRefresh(t *testing.T) {
	tmpDir := t.TempDir()

	toolName := "tavily_search"
	toolDesc := "Search the web using Tavily API"
	regPath := writeRegistryYAML(t, tmpDir, toolName, toolDesc, tavilySchemaBaseline())

	registry, err := NewToolRegistry(regPath)
	if err != nil {
		t.Fatalf("NewToolRegistry: %v", err)
	}

	var refreshCalls int32
	refresh := func(ctx context.Context, server string) (map[string]string, error) {
		atomic.AddInt32(&refreshCalls, 1)
		// Return the expected baseline hash so the request is allowed and marked verified.
		return map[string]string{toolName: ComputeHash(toolDesc, tavilySchemaBaseline())}, nil
	}

	cache := NewObservedToolHashCache(5 * time.Minute)

	var sawVerified bool
	handler := ToolRegistryVerify(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawVerified = GetToolHashVerified(r.Context())
		w.WriteHeader(http.StatusOK)
	}), registry, cache, refresh)

	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"tavily_search","arguments":{"query":"hi"}},"id":1}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(body))
	req.Header.Set("X-MCP-Server", "default")
	req = req.WithContext(WithRequestBody(req.Context(), body))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if atomic.LoadInt32(&refreshCalls) != 1 {
		t.Fatalf("expected refresh to be called once, got %d", refreshCalls)
	}
	if !sawVerified {
		t.Fatalf("expected tool hash to be marked verified in context")
	}
}

func TestToolRegistryVerify_ObservedHashRefresh_StaleTriggersRefresh(t *testing.T) {
	tmpDir := t.TempDir()

	toolName := "tavily_search"
	toolDesc := "Search the web using Tavily API"
	regPath := writeRegistryYAML(t, tmpDir, toolName, toolDesc, tavilySchemaBaseline())

	registry, err := NewToolRegistry(regPath)
	if err != nil {
		t.Fatalf("NewToolRegistry: %v", err)
	}

	cache := NewObservedToolHashCache(1 * time.Second)
	// Seed a stale entry.
	cache.Set("default", toolName, ComputeHash(toolDesc, tavilySchemaBaseline()))
	cache.mu.Lock()
	k := observedToolHashKey("default", toolName)
	e := cache.entries[k]
	e.ObservedAt = time.Now().Add(-10 * time.Second)
	cache.entries[k] = e
	cache.mu.Unlock()

	var refreshCalls int32
	refresh := func(ctx context.Context, server string) (map[string]string, error) {
		atomic.AddInt32(&refreshCalls, 1)
		return map[string]string{toolName: ComputeHash(toolDesc, tavilySchemaBaseline())}, nil
	}

	handler := ToolRegistryVerify(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), registry, cache, refresh)

	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"tavily_search","arguments":{"query":"hi"}},"id":1}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(body))
	req.Header.Set("X-MCP-Server", "default")
	req = req.WithContext(WithRequestBody(req.Context(), body))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if atomic.LoadInt32(&refreshCalls) != 1 {
		t.Fatalf("expected refresh to be called once for stale entry, got %d", refreshCalls)
	}
}

func TestToolRegistryVerify_RugPullMismatchDenied_NoClientToolHash(t *testing.T) {
	// Integration test: ToolRegistryVerify triggers a real upstream tools/list call
	// (Streamable HTTP MCP) and denies tools/call when upstream metadata hash mismatches.
	tmpDir := t.TempDir()

	toolName := "tavily_search"
	baselineDesc := "Search the web using Tavily API"
	baselineSchema := tavilySchemaBaseline()
	regPath := writeRegistryYAML(t, tmpDir, toolName, baselineDesc, baselineSchema)

	registry, err := NewToolRegistry(regPath)
	if err != nil {
		t.Fatalf("NewToolRegistry: %v", err)
	}

	// Upstream server returns a modified description to simulate rug-pull.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = r.Body.Close()
		method, _ := req["method"].(string)

		switch method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "test-sid")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{}}}`))
			return
		case "notifications/initialized":
			w.WriteHeader(http.StatusNoContent)
			return
		case "tools/list":
			tools := map[string]any{
				"tools": []any{
					map[string]any{
						"name":        toolName,
						"description": baselineDesc + " (UPDATED)",
						"inputSchema": baselineSchema,
					},
				},
			}
			resp := map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"result":  tools,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		default:
			// Not used by this test (middleware denies before proxying).
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"result":  map[string]any{},
			})
		}
	}))
	defer upstream.Close()

	transport := mcpclient.NewStreamableHTTPTransport(upstream.URL, nil)

	refresh := func(ctx context.Context, server string) (map[string]string, error) {
		if err := transport.Initialize(ctx); err != nil {
			return nil, err
		}
		rpcReq := &mcpclient.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/list",
			Params:  map[string]any{},
		}
		rpcResp, err := transport.Send(ctx, rpcReq)
		if err != nil {
			return nil, err
		}
		if rpcResp.Error != nil {
			return nil, fmt.Errorf("tools/list error: %d %s", rpcResp.Error.Code, rpcResp.Error.Message)
		}
		var result struct {
			Tools []struct {
				Name        string         `json:"name"`
				Description string         `json:"description"`
				InputSchema map[string]any `json:"inputSchema"`
			} `json:"tools"`
		}
		if err := json.Unmarshal(rpcResp.Result, &result); err != nil {
			return nil, err
		}
		hashes := map[string]string{}
		for _, t := range result.Tools {
			hashes[t.Name] = ComputeHash(t.Description, t.InputSchema)
		}
		return hashes, nil
	}

	cache := NewObservedToolHashCache(5 * time.Minute)
	handler := ToolRegistryVerify(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next handler should not be reached on rug-pull mismatch")
	}), registry, cache, refresh)

	// tools/call request with NO client tool_hash
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"tavily_search","arguments":{"query":"hi"}},"id":1}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(body))
	req.Header.Set("X-MCP-Server", "default")
	req = req.WithContext(WithRequestBody(req.Context(), body))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	var ge GatewayError
	if err := json.Unmarshal(rec.Body.Bytes(), &ge); err != nil {
		t.Fatalf("expected GatewayError JSON, got: %s", rec.Body.String())
	}
	if ge.Code != ErrRegistryHashMismatch {
		t.Fatalf("expected code=%s, got %s", ErrRegistryHashMismatch, ge.Code)
	}
}

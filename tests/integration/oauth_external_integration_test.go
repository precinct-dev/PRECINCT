// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

// OC-8r7q: Conformance -- External OAuth client can tools/list + tools/call.
//
// Proves end-to-end that an external OAuth client (no SPIFFE identity) can
// authenticate via bearer token and call MCP tools through the PRECINCT
// gateway. Uses an in-process gateway with real OPA, real JWT validation,
// real httptest mock servers for the OAuth issuer and MCP upstream -- no mocks
// for the gateway or OPA engine.
package integration

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/testutil"
)

// ---------------------------------------------------------------------------
// Inline mock OAuth issuer (RS256 JWT + JWKS)
// ---------------------------------------------------------------------------

// testOAuthIssuer is a minimal OAuth issuer that mints RS256 JWTs with
// an RSA key pair. It exposes /health, /jwks.json, and /token endpoints,
// matching the contract of examples/mock-oauth-issuer.
type testOAuthIssuer struct {
	kid       string
	privKey   *rsa.PrivateKey
	issuerURL string
}

func newTestOAuthIssuer(issuerURL, kid string) *testOAuthIssuer {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("generate RSA key: " + err.Error())
	}
	return &testOAuthIssuer{kid: kid, privKey: privKey, issuerURL: issuerURL}
}

func (s *testOAuthIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/health":
		writeTestJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	case r.URL.Path == "/jwks.json":
		s.handleJWKS(w)
	case r.URL.Path == "/token" && r.Method == http.MethodPost:
		s.handleToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *testOAuthIssuer) handleJWKS(w http.ResponseWriter) {
	pubJWK := jose.JSONWebKey{
		Key:       &s.privKey.PublicKey,
		KeyID:     s.kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK}}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}

func (s *testOAuthIssuer) handleToken(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeTestJSON(w, http.StatusBadRequest, map[string]any{"error": "read_body"})
		return
	}
	_ = r.Body.Close()

	var req struct {
		ClientID   string `json:"client_id"`
		Subject    string `json:"subject"`
		Scope      string `json:"scope"`
		Audience   string `json:"audience"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeTestJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_json"})
		return
	}

	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 3600
	}
	clientID := req.ClientID
	if clientID == "" {
		clientID = "test-client"
	}
	subject := req.Subject
	if subject == "" {
		subject = "test-subject"
	}
	audience := req.Audience
	if audience == "" {
		audience = "test-audience"
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(ttl) * time.Second)

	token, err := s.signJWT(subject, audience, req.Scope, clientID, now, expiresAt)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]any{"error": "sign_jwt"})
		return
	}

	writeTestJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   ttl,
		"scope":        req.Scope,
	})
}

func (s *testOAuthIssuer) signJWT(subject, audience, scope, clientID string, now, expiresAt time.Time) (string, error) {
	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{
		Key:       s.privKey,
		KeyID:     s.kid,
		Algorithm: string(jose.RS256),
	}}
	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}

	claims := map[string]any{
		"iss":       s.issuerURL,
		"sub":       subject,
		"aud":       audience,
		"scope":     scope,
		"client_id": clientID,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       expiresAt.Unix(),
	}

	builder := josejwt.Signed(signer)
	builder = builder.Claims(claims)

	return builder.Serialize()
}

// ---------------------------------------------------------------------------
// Inline mock MCP server
// ---------------------------------------------------------------------------

// testMCPServer is a minimal MCP server that handles initialize,
// notifications/initialized, tools/list, and tools/call. It echoes debug
// headers (X-Mock-Authorization, X-Mock-Precinct-Auth-Method) for verification.
type testMCPServer struct {
	mu       sync.RWMutex
	sessions map[string]bool
}

func newTestMCPServer() *testMCPServer {
	return &testMCPServer{sessions: make(map[string]bool)}
}

func (s *testMCPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		writeTestJSON(w, http.StatusOK, map[string]any{"status": "ok"})
		return
	}

	// Echo debug headers so tests can verify token non-passthrough.
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		authHeader = "<none>"
	}
	authMethod := strings.TrimSpace(r.Header.Get("X-Precinct-Auth-Method"))
	if authMethod == "" {
		authMethod = "<none>"
	}
	w.Header().Set("X-Mock-Authorization", authHeader)
	w.Header().Set("X-Mock-Precinct-Auth-Method", authMethod)

	if r.Method != http.MethodPost {
		writeTestJSONRPCError(w, nil, -32600, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeTestJSONRPCError(w, nil, -32700, "read body failed", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id,omitempty"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params,omitempty"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeTestJSONRPCError(w, nil, -32700, "parse error", http.StatusBadRequest)
		return
	}

	switch req.Method {
	case "initialize":
		sid := s.createSession()
		result, _ := json.Marshal(map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": true}},
			"serverInfo":      map[string]any{"name": "test-mcp-server", "version": "1.0.0"},
		})
		w.Header().Set("Mcp-Session-Id", sid)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		writeTestJSONRPCResult(w, req.ID, result)

	case "notifications/initialized":
		w.WriteHeader(http.StatusOK)

	case "tools/list":
		// Tool definition must match config/tool-registry.yaml exactly so
		// the gateway's hash verification (rug-pull detection) passes.
		result, _ := json.Marshal(map[string]any{
			"tools": []map[string]any{
				{
					"name":        "tavily_search",
					"description": "Search the web for current information on any topic. Use for news, facts, or data beyond your knowledge cutoff. Returns snippets and source URLs.",
					"inputSchema": map[string]any{
						"type":     "object",
						"required": []string{"query"},
						"properties": map[string]any{
							"query": map[string]any{
								"type":        "string",
								"description": "Search query",
							},
							"search_depth": map[string]any{
								"type": "string",
								"enum": []string{"basic", "advanced", "fast", "ultra-fast"},
							},
							"max_results": map[string]any{
								"type":        "number",
								"description": "The maximum number of search results to return",
								"default":     5,
							},
						},
					},
				},
			},
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		writeTestJSONRPCResult(w, req.ID, result)

	case "tools/call":
		var callParams struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if req.Params != nil {
			_ = json.Unmarshal(req.Params, &callParams)
		}
		result, _ := json.Marshal(map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": "search result for " + callParams.Name},
			},
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		writeTestJSONRPCResult(w, req.ID, result)

	default:
		writeTestJSONRPCError(w, req.ID, -32601, "method not found: "+req.Method, http.StatusOK)
	}
}

func (s *testMCPServer) createSession() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	sid := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[sid] = true
	s.mu.Unlock()
	return sid
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

func writeTestJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeTestJSONRPCResult(w io.Writer, id json.RawMessage, result json.RawMessage) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	})
}

func writeTestJSONRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg string, httpStatus int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": msg},
	})
}

// ---------------------------------------------------------------------------
// Test environment
// ---------------------------------------------------------------------------

type oauthExternalTestEnv struct {
	GatewayURL     string
	OAuthIssuerURL string
}

func setupOAuthExternalEnv(t *testing.T) oauthExternalTestEnv {
	t.Helper()

	// 1. Start mock OAuth issuer. We need the URL before creating the issuer
	//    (the JWT iss claim must match), so we create a listener first, then
	//    wire the handler.
	oauthLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for oauth issuer: %v", err)
	}
	oauthURL := "http://" + oauthLn.Addr().String()
	oauthIssuer := newTestOAuthIssuer(oauthURL, "conformance-key")
	oauthSrv := &httptest.Server{
		Listener: oauthLn,
		Config:   &http.Server{Handler: oauthIssuer},
	}
	oauthSrv.Start()
	t.Cleanup(oauthSrv.Close)

	// 2. Start mock MCP server.
	mcpServer := newTestMCPServer()
	mcpTS := httptest.NewServer(mcpServer)
	t.Cleanup(mcpTS.Close)

	// 3. Write OAuth config pointing to the test issuer.
	oauthConfigPath := writeOAuthExternalConfig(t, oauthURL)

	// 4. Write a tool registry with hashes that match the inline MCP server's
	//    tool definitions (avoids false rug-pull detection).
	toolRegistryPath := writeOAuthExternalToolRegistry(t)

	cfg := &gateway.Config{
		UpstreamURL:                   mcpTS.URL,
		OPAPolicyDir:                  testutil.OPAPolicyDir(),
		ToolRegistryConfigPath:        toolRegistryPath,
		AuditLogPath:                  "",
		OPAPolicyPath:                 testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:           1024 * 1024,
		SPIFFEMode:                    "dev",
		SPIFFETrustDomain:             "poc.local",
		OAuthResourceServerConfigPath: oauthConfigPath,
		MCPTransportMode:              "proxy",
		RateLimitRPM:                  100000,
		RateLimitBurst:                100000,
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	// Start the gateway on a random port.
	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen for gateway: %v", err)
	}
	t.Cleanup(func() { _ = gwLn.Close() })

	gwSrv := &http.Server{
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = gwSrv.Serve(gwLn) }()
	t.Cleanup(func() { _ = gwSrv.Close() })

	gwURL := "http://" + gwLn.Addr().String()

	if err := waitForService(gwURL+"/health", 10*time.Second); err != nil {
		t.Fatalf("gateway not ready: %v", err)
	}

	return oauthExternalTestEnv{
		GatewayURL:     gwURL,
		OAuthIssuerURL: oauthURL,
	}
}

// writeOAuthExternalToolRegistry writes a temporary tool-registry.yaml with
// a tavily_search tool whose hash matches the inline test MCP server's
// tools/list response. This avoids rug-pull detection failures which are
// orthogonal to the OAuth conformance being tested.
func writeOAuthExternalToolRegistry(t *testing.T) string {
	t.Helper()

	// Compute the hash from the exact tool definition our inline MCP
	// server returns (description + json.Marshal(inputSchema)).
	desc := "Search the web for current information on any topic. " +
		"Use for news, facts, or data beyond your knowledge cutoff. " +
		"Returns snippets and source URLs."
	schema := map[string]any{
		"type":     "object",
		"required": []string{"query"},
		"properties": map[string]any{
			"query": map[string]any{
				"type":        "string",
				"description": "Search query",
			},
			"search_depth": map[string]any{
				"type": "string",
				"enum": []string{"basic", "advanced", "fast", "ultra-fast"},
			},
			"max_results": map[string]any{
				"type":        "number",
				"description": "The maximum number of search results to return",
				"default":     5,
			},
		},
	}
	schemaJSON, _ := json.Marshal(schema)
	h := sha256.Sum256([]byte(desc + string(schemaJSON)))
	toolHash := hex.EncodeToString(h[:])

	path := filepath.Join(t.TempDir(), "tool-registry.yaml")
	content := "tools:\n" +
		"  - name: \"tavily_search\"\n" +
		"    description: \"" + desc + "\"\n" +
		"    hash: \"" + toolHash + "\"\n" +
		"    input_schema:\n" +
		"      type: \"object\"\n" +
		"      required: [\"query\"]\n" +
		"      properties:\n" +
		"        query:\n" +
		"          type: \"string\"\n" +
		"          description: \"Search query\"\n" +
		"        search_depth:\n" +
		"          type: \"string\"\n" +
		"          enum: [\"basic\", \"advanced\", \"fast\", \"ultra-fast\"]\n" +
		"        max_results:\n" +
		"          type: \"number\"\n" +
		"          description: \"The maximum number of search results to return\"\n" +
		"          default: 5\n" +
		"    risk_level: \"medium\"\n" +
		"    requires_step_up: false\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write tool registry: %v", err)
	}
	return path
}

func writeOAuthExternalConfig(t *testing.T, issuerURL string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oauth-resource-server.yaml")
	content := "oauth_resource_server:\n" +
		"  issuer: " + issuerURL + "\n" +
		"  audience: gateway\n" +
		"  jwks_url: " + issuerURL + "/jwks.json\n" +
		"  required_scopes:\n" +
		"    - \"mcp:tools\"\n" +
		"  clock_skew_seconds: 30\n" +
		"  cache_ttl_seconds: 60\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write oauth config: %v", err)
	}
	return path
}

// mintConformanceToken mints a JWT from the in-process test OAuth issuer.
func mintConformanceToken(t *testing.T, issuerURL, scopes string) string {
	t.Helper()
	payload := `{"client_id":"conformance","subject":"ext-user","scope":"` + scopes + `","audience":"gateway","ttl_seconds":180}`
	return mintOAuthAccessToken(t, issuerURL, payload)
}

// conformanceRPC sends a JSON-RPC POST to the given gateway URL with bearer
// token and optional session ID.
func conformanceRPC(t *testing.T, gwURL, token, sessionID string, body map[string]any) *http.Response {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal rpc body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, gwURL, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if strings.TrimSpace(sessionID) != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

// initConformanceSession performs the MCP initialize + notifications/initialized
// handshake and returns the session ID.
func initConformanceSession(t *testing.T, gwURL, token string) string {
	t.Helper()

	initResp := conformanceRPC(t, gwURL, token, "", map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "oauth-conformance",
				"version": "1.0.0",
			},
		},
		"id": 1,
	})
	if initResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(initResp.Body)
		_ = initResp.Body.Close()
		t.Fatalf("initialize status=%d body=%s", initResp.StatusCode, strings.TrimSpace(string(body)))
	}
	sessionID := strings.TrimSpace(initResp.Header.Get("Mcp-Session-Id"))
	if sessionID == "" {
		t.Fatal("initialize response missing Mcp-Session-Id")
	}
	_ = initResp.Body.Close()

	notifyResp := conformanceRPC(t, gwURL, token, sessionID, map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		"params":  map[string]any{},
	})
	if notifyResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(notifyResp.Body)
		_ = notifyResp.Body.Close()
		t.Fatalf("notifications/initialized status=%d body=%s", notifyResp.StatusCode, strings.TrimSpace(string(body)))
	}
	_ = notifyResp.Body.Close()

	return sessionID
}

// ---------------------------------------------------------------------------
// Conformance tests
// ---------------------------------------------------------------------------

// TestOAuthExternalConformance is the conformance suite for external OAuth
// client access to MCP tools via the PRECINCT gateway. It uses an in-process
// gateway with real OPA engine, real JWT validation, and real HTTP servers
// for the mock OAuth issuer and mock MCP upstream.
func TestOAuthExternalConformance(t *testing.T) {
	env := setupOAuthExternalEnv(t)

	// AC: GET /.well-known/oauth-protected-resource returns expected fields.
	t.Run("WellKnownOAuthProtectedResource", func(t *testing.T) {
		resp, err := http.Get(env.GatewayURL + "/.well-known/oauth-protected-resource")
		if err != nil {
			t.Fatalf("GET /.well-known/oauth-protected-resource: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("status=%d body=%s, want 200", resp.StatusCode, string(body))
		}

		ct := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("content-type=%q, want application/json prefix", ct)
		}

		var meta map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
			t.Fatalf("decode response: %v", err)
		}

		// resource == configured audience
		if got, ok := meta["resource"].(string); !ok || got != "gateway" {
			t.Fatalf("resource=%v, want \"gateway\"", meta["resource"])
		}

		// authorization_servers includes the configured issuer
		servers, ok := meta["authorization_servers"].([]any)
		if !ok || len(servers) == 0 {
			t.Fatalf("authorization_servers missing or empty: %v", meta["authorization_servers"])
		}
		if servers[0].(string) != env.OAuthIssuerURL {
			t.Fatalf("authorization_servers[0]=%v, want %q", servers[0], env.OAuthIssuerURL)
		}

		// scopes_supported includes the configured required scope
		scopes, ok := meta["scopes_supported"].([]any)
		if !ok || len(scopes) == 0 {
			t.Fatalf("scopes_supported missing or empty: %v", meta["scopes_supported"])
		}
		hasMCPTools := false
		for _, s := range scopes {
			if s.(string) == "mcp:tools" {
				hasMCPTools = true
				break
			}
		}
		if !hasMCPTools {
			t.Fatalf("scopes_supported=%v does not include \"mcp:tools\"", scopes)
		}

		// mcp_endpoint == "/"
		if got := meta["mcp_endpoint"]; got != "/" {
			t.Fatalf("mcp_endpoint=%v, want \"/\"", got)
		}
	})

	// AC: POST / with method=tools/list works with bearer token + correct scopes.
	t.Run("ToolsList_AllowedWithCorrectScope", func(t *testing.T) {
		token := mintConformanceToken(t, env.OAuthIssuerURL, "mcp:tools")
		sessionID := initConformanceSession(t, env.GatewayURL, token)

		resp := conformanceRPC(t, env.GatewayURL, token, sessionID, map[string]any{
			"jsonrpc": "2.0",
			"method":  "tools/list",
			"params":  map[string]any{},
			"id":      2,
		})
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("tools/list status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var rpc integrationRPCResponse
		if err := json.Unmarshal(body, &rpc); err != nil {
			t.Fatalf("decode tools/list: %v", err)
		}
		if rpc.Error != nil {
			t.Fatalf("tools/list returned error: code=%d message=%s", rpc.Error.Code, rpc.Error.Message)
		}
		if !strings.Contains(string(rpc.Result), "tavily_search") {
			t.Fatalf("tools/list result does not include tavily_search: %s", string(rpc.Result))
		}
	})

	// AC: POST / with method=tools/call works for an allowlisted tool.
	t.Run("ToolsCall_AllowedWithCorrectScopes", func(t *testing.T) {
		// Token needs all required scopes:
		//   mcp:tools            -- gateway-level required scope
		//   mcp:tools:call       -- OPA requires for tools/call invocations
		//   mcp:tool:tavily_search -- per-tool scope from tool_grants.yaml
		token := mintConformanceToken(t, env.OAuthIssuerURL, "mcp:tools mcp:tools:call mcp:tool:tavily_search")
		sessionID := initConformanceSession(t, env.GatewayURL, token)

		resp := conformanceRPC(t, env.GatewayURL, token, sessionID, map[string]any{
			"jsonrpc": "2.0",
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "tavily_search",
				"arguments": map[string]any{"query": "test"},
			},
			"id": 3,
		})
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("tools/call status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var rpc integrationRPCResponse
		if err := json.Unmarshal(body, &rpc); err != nil {
			t.Fatalf("decode tools/call: %v", err)
		}
		if rpc.Error != nil {
			t.Fatalf("tools/call error: code=%d message=%s", rpc.Error.Code, rpc.Error.Message)
		}
	})

	// AC: tools/call denies when scope is missing.
	t.Run("ToolsCall_DeniedWhenScopeMissing", func(t *testing.T) {
		// Token has the gateway-level scope (mcp:tools) but NOT the
		// mcp:tools:call scope required by OPA for tools/call.
		token := mintConformanceToken(t, env.OAuthIssuerURL, "mcp:tools")
		sessionID := initConformanceSession(t, env.GatewayURL, token)

		resp := conformanceRPC(t, env.GatewayURL, token, sessionID, map[string]any{
			"jsonrpc": "2.0",
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "tavily_search",
				"arguments": map[string]any{"query": "test"},
			},
			"id": 4,
		})
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)

		// OPA denies with oauth_scope_missing -- gateway returns 403.
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("tools/call with missing scope status=%d (want 403) body=%s",
				resp.StatusCode, strings.TrimSpace(string(body)))
		}
	})

	// AC: token non-passthrough -- upstream does NOT receive the inbound bearer token.
	t.Run("TokenNonPassthrough", func(t *testing.T) {
		token := mintConformanceToken(t, env.OAuthIssuerURL, "mcp:tools")
		sessionID := initConformanceSession(t, env.GatewayURL, token)

		resp := conformanceRPC(t, env.GatewayURL, token, sessionID, map[string]any{
			"jsonrpc": "2.0",
			"method":  "tools/list",
			"params":  map[string]any{},
			"id":      5,
		})
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("tools/list status=%d, expected 200", resp.StatusCode)
		}

		// The mock MCP server echoes what it received in X-Mock-Authorization.
		// When the gateway strips the bearer token, the upstream sees "<none>".
		upstreamAuth := resp.Header.Get("X-Mock-Authorization")
		if upstreamAuth != "<none>" {
			t.Fatalf("upstream received Authorization=%q, want \"<none>\" (token should be stripped)", upstreamAuth)
		}
	})

	// AC: X-Precinct-Auth-Method is "oauth_jwt".
	t.Run("AuthMethodIsOAuthJWT", func(t *testing.T) {
		token := mintConformanceToken(t, env.OAuthIssuerURL, "mcp:tools")
		sessionID := initConformanceSession(t, env.GatewayURL, token)

		resp := conformanceRPC(t, env.GatewayURL, token, sessionID, map[string]any{
			"jsonrpc": "2.0",
			"method":  "tools/list",
			"params":  map[string]any{},
			"id":      6,
		})
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("tools/list status=%d, expected 200", resp.StatusCode)
		}

		authMethod := resp.Header.Get("X-Mock-Precinct-Auth-Method")
		if authMethod != "oauth_jwt" {
			t.Fatalf("X-Mock-Precinct-Auth-Method=%q, want \"oauth_jwt\"", authMethod)
		}
	})
}

// examples/tavily-mcp-server/main.go -- Minimal MCP server speaking Streamable HTTP
// that calls the real Tavily search API.
//
// Handles:
//
//	POST /       method=initialize              -> server capabilities + Mcp-Session-Id
//	POST /       method=notifications/initialized -> 200 (ack)
//	POST /       method=tools/call              -> real Tavily API results
//	POST /       method=tools/list              -> available tool list
//	DELETE /     Mcp-Session-Id                 -> session termination (204)
//	GET /health                                  -> 200 (Docker healthcheck)
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// --- JSON-RPC types ---

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// --- Tool definition ---

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

var availableTools = []toolDef{
	{
		Name:        "tavily_search",
		Description: "Search the web using Tavily API",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{
					"type":        "string",
					"description": "Search query",
				},
				"max_results": map[string]any{
					"type":        "integer",
					"description": "Maximum results (default 3)",
				},
			},
			"required": []string{"query"},
		},
	},
}

// --- Tavily API ---

const tavilyAPIURL = "https://api.tavily.com/search"

var httpClient = &http.Client{Timeout: 30 * time.Second}

type tavilyRequest struct {
	APIKey      string `json:"api_key"`
	Query       string `json:"query"`
	MaxResults  int    `json:"max_results"`
	SearchDepth string `json:"search_depth"`
}

func callTavily(query string, maxResults int) (json.RawMessage, error) {
	apiKey := os.Getenv("TAVILY_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("TAVILY_API_KEY environment variable not set")
	}

	if maxResults <= 0 {
		maxResults = 3
	}

	reqBody := tavilyRequest{
		APIKey:      apiKey,
		Query:       query,
		MaxResults:  maxResults,
		SearchDepth: "basic",
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal tavily request: %w", err)
	}

	resp, err := httpClient.Post(tavilyAPIURL, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("tavily API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read tavily response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tavily API returned %d: %s", resp.StatusCode, string(respBody[:minInt(len(respBody), 500)]))
	}

	return respBody, nil
}

// --- Session management ---

type sessionManager struct {
	mu       sync.RWMutex
	sessions map[string]bool
}

func newSessionManager() *sessionManager {
	return &sessionManager{sessions: make(map[string]bool)}
}

func (sm *sessionManager) create() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	sid := hex.EncodeToString(b)
	sm.mu.Lock()
	sm.sessions[sid] = true
	sm.mu.Unlock()
	return sid
}

func (sm *sessionManager) valid(sid string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[sid]
}

func (sm *sessionManager) remove(sid string) {
	sm.mu.Lock()
	delete(sm.sessions, sid)
	sm.mu.Unlock()
}

// --- Server ---

type server struct {
	sessions *sessionManager
	mux      *http.ServeMux
}

func newServer() *server {
	s := &server{
		sessions: newSessionManager(),
		mux:      http.NewServeMux(),
	}
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/", s.handleRoot)
	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	log.Printf("[tavily-mcp] %s %s (Mcp-Session-Id: %s)", r.Method, r.URL.Path, r.Header.Get("Mcp-Session-Id"))
	switch r.Method {
	case http.MethodPost:
		s.handlePost(w, r)
	case http.MethodDelete:
		s.handleDelete(w, r)
	default:
		writeJSONRPCError(w, nil, -32600, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handlePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONRPCError(w, nil, -32700, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("[tavily-mcp] Parse error: %v, body: %s", err, string(body[:minInt(len(body), 200)]))
		writeJSONRPCError(w, nil, -32700, "Parse error: invalid JSON", http.StatusBadRequest)
		return
	}
	log.Printf("[tavily-mcp] Method: %s, ID: %s", req.Method, string(req.ID))

	if req.JSONRPC != "2.0" {
		writeJSONRPCError(w, req.ID, -32600, "Invalid Request: jsonrpc must be '2.0'", http.StatusBadRequest)
		return
	}

	switch req.Method {
	case "initialize":
		s.handleInitialize(w, req)
	case "notifications/initialized":
		w.WriteHeader(http.StatusOK)
	case "tools/call":
		s.handleToolsCall(w, r, req)
	case "tools/list":
		s.handleToolsList(w, r, req)
	default:
		writeJSONRPCError(w, req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method), http.StatusOK)
	}
}

func (s *server) handleInitialize(w http.ResponseWriter, req jsonRPCRequest) {
	sid := s.sessions.create()

	result := map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities": map[string]any{
			"tools": map[string]any{
				"listChanged": true,
			},
		},
		"serverInfo": map[string]any{
			"name":    "tavily-mcp-server",
			"version": "1.0.0",
		},
	}

	resultBytes, _ := json.Marshal(result)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Mcp-Session-Id", sid)
	w.WriteHeader(http.StatusOK)

	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  resultBytes,
	}
	_ = json.NewEncoder(w).Encode(resp)

	log.Printf("[tavily-mcp] Session initialized: %s", sid)
}

func (s *server) handleToolsCall(w http.ResponseWriter, r *http.Request, req jsonRPCRequest) {
	sid := r.Header.Get("Mcp-Session-Id")
	if sid == "" || !s.sessions.valid(sid) {
		writeJSONRPCError(w, req.ID, -32000, "Session not found or expired", http.StatusNotFound)
		return
	}

	var callParams struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			writeJSONRPCError(w, req.ID, -32602, "Invalid params for tools/call", http.StatusBadRequest)
			return
		}
	}

	if callParams.Name != "tavily_search" {
		writeJSONRPCError(w, req.ID, -32601, fmt.Sprintf("Tool not found: %s", callParams.Name), http.StatusOK)
		return
	}

	// Parse arguments
	var args struct {
		Query      string `json:"query"`
		MaxResults int    `json:"max_results"`
	}
	if callParams.Arguments != nil {
		if err := json.Unmarshal(callParams.Arguments, &args); err != nil {
			writeJSONRPCError(w, req.ID, -32602, "Invalid arguments for tavily_search", http.StatusBadRequest)
			return
		}
	}
	if args.Query == "" {
		writeJSONRPCError(w, req.ID, -32602, "Missing required argument: query", http.StatusBadRequest)
		return
	}

	log.Printf("[tavily-mcp] Calling Tavily API: query=%q max_results=%d", args.Query, args.MaxResults)

	tavilyResp, err := callTavily(args.Query, args.MaxResults)
	if err != nil {
		log.Printf("[tavily-mcp] Tavily API error: %v", err)
		writeJSONRPCError(w, req.ID, -32000, fmt.Sprintf("Tavily API error: %v", err), http.StatusOK)
		return
	}

	// Wrap Tavily response as MCP text content
	result := map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": string(tavilyResp),
			},
		},
	}
	resultBytes, _ := json.Marshal(result)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  resultBytes,
	}
	_ = json.NewEncoder(w).Encode(resp)

	log.Printf("[tavily-mcp] tools/call: tavily_search (session=%s)", sid)
}

func (s *server) handleToolsList(w http.ResponseWriter, r *http.Request, req jsonRPCRequest) {
	sid := r.Header.Get("Mcp-Session-Id")
	if sid == "" || !s.sessions.valid(sid) {
		writeJSONRPCError(w, req.ID, -32000, "Session not found or expired", http.StatusNotFound)
		return
	}

	result := map[string]any{"tools": availableTools}
	resultBytes, _ := json.Marshal(result)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  resultBytes,
	}
	_ = json.NewEncoder(w).Encode(resp)

	log.Printf("[tavily-mcp] tools/list (session=%s)", sid)
}

func (s *server) handleDelete(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("Mcp-Session-Id")
	if sid != "" {
		s.sessions.remove(sid)
		log.Printf("[tavily-mcp] Session terminated: %s", sid)
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeJSONRPCError writes a JSON-RPC 2.0 error response.
func writeJSONRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string, httpStatus int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &jsonRPCError{
			Code:    code,
			Message: message,
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "perform a health check and exit 0/1")
	flag.Parse()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	if *healthcheck {
		resp, err := http.Get("http://127.0.0.1:" + port + "/health")
		if err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "healthcheck returned %d\n", resp.StatusCode)
			os.Exit(1)
		}
		os.Exit(0)
	}

	srv := newServer()
	addr := ":" + port
	log.Printf("[tavily-mcp] Starting Tavily MCP server on %s", addr)
	log.Printf("[tavily-mcp] Available tools: tavily_search")
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatalf("[tavily-mcp] Server failed: %v", err)
	}
}

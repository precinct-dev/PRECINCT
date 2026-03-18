package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Helpers ---

// rpcBody builds a JSON-RPC 2.0 request body.
func rpcBody(t *testing.T, id any, method string, params any) io.Reader {
	t.Helper()
	m := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if id != nil {
		m["id"] = id
	}
	if params != nil {
		m["params"] = params
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return bytes.NewReader(b)
}

// doPost sends a POST / request with the given body and optional session header.
func doPost(t *testing.T, ts *httptest.Server, body io.Reader, sessionID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/", body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// readJSON decodes a JSON-RPC response from the HTTP response body.
func readJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal response %q: %v", string(b), err)
	}
	return m
}

// initSession performs an initialize handshake and returns the session ID.
func initSession(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	resp := doPost(t, ts, rpcBody(t, 1, "initialize", nil), "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize: status %d", resp.StatusCode)
	}
	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("initialize: missing Mcp-Session-Id header")
	}
	resp.Body.Close()
	return sid
}

// newTestServer creates a Server with a discard logger.
func newTestServer(name string, opts ...Option) *Server {
	allOpts := append([]Option{WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))}, opts...)
	return New(name, allOpts...)
}

// --- Unit Tests ---

func TestNew_RequiresName(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for empty name")
		}
		s, ok := r.(string)
		if !ok || !strings.Contains(s, "name must not be empty") {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	New("")
}

func TestNew_Defaults(t *testing.T) {
	s := newTestServer("test-server")
	if s.name != "test-server" {
		t.Errorf("name = %q, want %q", s.name, "test-server")
	}
	if s.version != "0.0.0" {
		t.Errorf("version = %q, want %q", s.version, "0.0.0")
	}
	if s.port != 8080 {
		t.Errorf("port = %d, want %d", s.port, 8080)
	}
}

func TestOptions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New("test",
		WithVersion("2.0.0"),
		WithPort(9090),
		WithAddress("127.0.0.1"),
		WithLogger(logger),
		WithShutdownTimeout(30*time.Second),
		WithReadTimeout(15*time.Second),
		WithWriteTimeout(20*time.Second),
	)
	if s.version != "2.0.0" {
		t.Errorf("version = %q", s.version)
	}
	if s.port != 9090 {
		t.Errorf("port = %d", s.port)
	}
	if s.address != "127.0.0.1" {
		t.Errorf("address = %q", s.address)
	}
	if s.shutdownTimeout != 30*time.Second {
		t.Errorf("shutdownTimeout = %v", s.shutdownTimeout)
	}
	if s.readTimeout != 15*time.Second {
		t.Errorf("readTimeout = %v", s.readTimeout)
	}
	if s.writeTimeout != 20*time.Second {
		t.Errorf("writeTimeout = %v", s.writeTimeout)
	}
}

func TestToolRegistration(t *testing.T) {
	s := newTestServer("test")
	s.Tool("echo", "Echoes input", Schema{
		Type:     "object",
		Required: []string{"message"},
		Properties: map[string]Property{
			"message": {Type: "string", Description: "Message to echo"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		return args["message"], nil
	})

	if len(s.tools) != 1 {
		t.Fatalf("tools count = %d, want 1", len(s.tools))
	}
	if s.tools[0].Name != "echo" {
		t.Errorf("tool name = %q, want %q", s.tools[0].Name, "echo")
	}
}

// --- Integration Tests (httptest) ---

func TestInitialize(t *testing.T) {
	s := newTestServer("my-server", WithVersion("1.0.0"))
	ts := httptest.NewServer(s)
	defer ts.Close()

	resp := doPost(t, ts, rpcBody(t, 1, "initialize", nil), "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Fatal("missing Mcp-Session-Id header")
	}

	body := readJSON(t, resp)
	if body["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v", body["jsonrpc"])
	}

	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("result is not an object: %T", body["result"])
	}
	if result["protocolVersion"] != protocolVersion {
		t.Errorf("protocolVersion = %v, want %q", result["protocolVersion"], protocolVersion)
	}

	serverInfo, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatalf("serverInfo is not an object")
	}
	if serverInfo["name"] != "my-server" {
		t.Errorf("serverInfo.name = %v", serverInfo["name"])
	}
	if serverInfo["version"] != "1.0.0" {
		t.Errorf("serverInfo.version = %v", serverInfo["version"])
	}

	caps, ok := result["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("capabilities is not an object")
	}
	tools, ok := caps["tools"].(map[string]any)
	if !ok {
		t.Fatalf("capabilities.tools is not an object")
	}
	if tools["listChanged"] != false {
		t.Errorf("capabilities.tools.listChanged = %v", tools["listChanged"])
	}
}

func TestNotificationsInitialized(t *testing.T) {
	s := newTestServer("test")
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts)

	resp := doPost(t, ts, rpcBody(t, nil, "notifications/initialized", nil), sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(b) != 0 {
		t.Errorf("expected empty body, got %q", string(b))
	}
}

func TestToolsList(t *testing.T) {
	s := newTestServer("test", WithVersion("1.0.0"))
	s.Tool("echo", "Echoes input", Schema{
		Type:     "object",
		Required: []string{"message"},
		Properties: map[string]Property{
			"message": {Type: "string", Description: "Message to echo"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		return args["message"], nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts)
	resp := doPost(t, ts, rpcBody(t, 2, "tools/list", nil), sid)
	body := readJSON(t, resp)

	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("result is not an object")
	}
	tools, ok := result["tools"].([]any)
	if !ok {
		t.Fatalf("tools is not an array: %T", result["tools"])
	}
	if len(tools) != 1 {
		t.Fatalf("tools count = %d, want 1", len(tools))
	}
	tool := tools[0].(map[string]any)
	if tool["name"] != "echo" {
		t.Errorf("tool name = %v", tool["name"])
	}
	if tool["description"] != "Echoes input" {
		t.Errorf("tool description = %v", tool["description"])
	}
	schema, ok := tool["inputSchema"].(map[string]any)
	if !ok {
		t.Fatal("inputSchema missing")
	}
	if schema["type"] != "object" {
		t.Errorf("schema type = %v", schema["type"])
	}
}

func TestToolsCall_Success(t *testing.T) {
	s := newTestServer("test")
	s.Tool("echo", "Echoes input", Schema{
		Type:     "object",
		Required: []string{"message"},
		Properties: map[string]Property{
			"message": {Type: "string", Description: "Message to echo"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		return args["message"], nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts)
	resp := doPost(t, ts, rpcBody(t, 3, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"message": "hello"},
	}), sid)

	body := readJSON(t, resp)
	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("result is not an object: %v", body)
	}
	content, ok := result["content"].([]any)
	if !ok {
		t.Fatalf("content is not an array")
	}
	if len(content) != 1 {
		t.Fatalf("content count = %d", len(content))
	}
	item := content[0].(map[string]any)
	if item["type"] != "text" {
		t.Errorf("content type = %v", item["type"])
	}
	if item["text"] != "hello" {
		t.Errorf("content text = %v, want %q", item["text"], "hello")
	}
	if _, hasError := result["isError"]; hasError {
		t.Errorf("unexpected isError in response")
	}
}

func TestToolsCall_HandlerError(t *testing.T) {
	s := newTestServer("test")
	s.Tool("fail", "Always fails", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return nil, fmt.Errorf("something broke")
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts)
	resp := doPost(t, ts, rpcBody(t, 4, "tools/call", map[string]any{
		"name": "fail",
	}), sid)

	body := readJSON(t, resp)
	result := body["result"].(map[string]any)
	if result["isError"] != true {
		t.Errorf("isError = %v, want true", result["isError"])
	}
	content := result["content"].([]any)
	item := content[0].(map[string]any)
	if item["text"] != "something broke" {
		t.Errorf("error text = %v", item["text"])
	}
}

func TestToolsCall_UnknownTool(t *testing.T) {
	s := newTestServer("test")
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts)
	resp := doPost(t, ts, rpcBody(t, 5, "tools/call", map[string]any{
		"name": "nonexistent",
	}), sid)

	body := readJSON(t, resp)
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got: %v", body)
	}
	code := int(errObj["code"].(float64))
	if code != codeInvalidParams {
		t.Errorf("error code = %d, want %d", code, codeInvalidParams)
	}
}

func TestInvalidJSON(t *testing.T) {
	s := newTestServer("test")
	ts := httptest.NewServer(s)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}

	body := readJSON(t, resp)
	errObj := body["error"].(map[string]any)
	code := int(errObj["code"].(float64))
	if code != codeParseError {
		t.Errorf("error code = %d, want %d", code, codeParseError)
	}
}

func TestMissingMethod(t *testing.T) {
	s := newTestServer("test")
	ts := httptest.NewServer(s)
	defer ts.Close()

	// Send a request with jsonrpc but no method field.
	body := `{"jsonrpc":"2.0","id":1}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	result := readJSON(t, resp)
	errObj := result["error"].(map[string]any)
	code := int(errObj["code"].(float64))
	if code != codeInvalidRequest {
		t.Errorf("error code = %d, want %d", code, codeInvalidRequest)
	}
}

func TestInvalidJSONRPCVersion(t *testing.T) {
	s := newTestServer("test")
	ts := httptest.NewServer(s)
	defer ts.Close()

	body := `{"jsonrpc":"1.0","id":1,"method":"initialize"}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	result := readJSON(t, resp)
	errObj := result["error"].(map[string]any)
	code := int(errObj["code"].(float64))
	if code != codeInvalidRequest {
		t.Errorf("error code = %d, want %d", code, codeInvalidRequest)
	}
}

func TestUnknownMethod(t *testing.T) {
	s := newTestServer("test")
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts)
	resp := doPost(t, ts, rpcBody(t, 6, "resources/list", nil), sid)
	body := readJSON(t, resp)
	errObj := body["error"].(map[string]any)
	code := int(errObj["code"].(float64))
	if code != codeMethodNotFound {
		t.Errorf("error code = %d, want %d", code, codeMethodNotFound)
	}
}

func TestHealthEndpoint(t *testing.T) {
	s := newTestServer("health-test", WithVersion("3.2.1"))
	ts := httptest.NewServer(s)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}

	body := readJSON(t, resp)
	if body["status"] != "ok" {
		t.Errorf("status = %v", body["status"])
	}
	if body["server"] != "health-test" {
		t.Errorf("server = %v", body["server"])
	}
	if body["version"] != "3.2.1" {
		t.Errorf("version = %v", body["version"])
	}
}

func TestHealth_MethodNotAllowed(t *testing.T) {
	s := newTestServer("test")
	ts := httptest.NewServer(s)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/health", nil)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestRoot_MethodNotAllowed(t *testing.T) {
	s := newTestServer("test")
	ts := httptest.NewServer(s)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestUnknownPath(t *testing.T) {
	s := newTestServer("test")
	ts := httptest.NewServer(s)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/unknown")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestSessionID_MissingOnNonInitialize(t *testing.T) {
	s := newTestServer("test")
	ts := httptest.NewServer(s)
	defer ts.Close()

	// No session ID header on a tools/list request.
	resp := doPost(t, ts, rpcBody(t, 1, "tools/list", nil), "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSessionID_InvalidOnNonInitialize(t *testing.T) {
	s := newTestServer("test")
	ts := httptest.NewServer(s)
	defer ts.Close()

	// Use a made-up session ID.
	resp := doPost(t, ts, rpcBody(t, 1, "tools/list", nil), "bad-session-id")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestEndToEnd(t *testing.T) {
	s := newTestServer("e2e-server", WithVersion("1.0.0"))
	s.Tool("greet", "Greets a user", Schema{
		Type:     "object",
		Required: []string{"name"},
		Properties: map[string]Property{
			"name": {Type: "string", Description: "User name"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		return fmt.Sprintf("Hello, %s!", args["name"]), nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	// Step 1: initialize
	resp := doPost(t, ts, rpcBody(t, 1, "initialize", nil), "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize: status %d", resp.StatusCode)
	}
	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("initialize: missing session ID")
	}
	initBody := readJSON(t, resp)
	result := initBody["result"].(map[string]any)
	if result["protocolVersion"] != protocolVersion {
		t.Errorf("protocolVersion = %v", result["protocolVersion"])
	}

	// Step 2: notifications/initialized
	resp = doPost(t, ts, rpcBody(t, nil, "notifications/initialized", nil), sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("notifications/initialized: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Step 3: tools/list
	resp = doPost(t, ts, rpcBody(t, 2, "tools/list", nil), sid)
	listBody := readJSON(t, resp)
	listResult := listBody["result"].(map[string]any)
	tools := listResult["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools count = %d", len(tools))
	}
	tool := tools[0].(map[string]any)
	if tool["name"] != "greet" {
		t.Errorf("tool name = %v", tool["name"])
	}

	// Step 4: tools/call
	resp = doPost(t, ts, rpcBody(t, 3, "tools/call", map[string]any{
		"name":      "greet",
		"arguments": map[string]any{"name": "World"},
	}), sid)
	callBody := readJSON(t, resp)
	callResult := callBody["result"].(map[string]any)
	content := callResult["content"].([]any)
	item := content[0].(map[string]any)
	if item["text"] != "Hello, World!" {
		t.Errorf("text = %v, want %q", item["text"], "Hello, World!")
	}
}

func TestMultipleTools(t *testing.T) {
	s := newTestServer("test")
	s.Tool("add", "Adds two numbers", Schema{
		Type:     "object",
		Required: []string{"a", "b"},
		Properties: map[string]Property{
			"a": {Type: "number"},
			"b": {Type: "number"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		a := args["a"].(float64)
		b := args["b"].(float64)
		return a + b, nil
	})

	s.Tool("upper", "Uppercases a string", Schema{
		Type:     "object",
		Required: []string{"text"},
		Properties: map[string]Property{
			"text": {Type: "string"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		return strings.ToUpper(args["text"].(string)), nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts)

	// List should show both tools.
	resp := doPost(t, ts, rpcBody(t, 1, "tools/list", nil), sid)
	body := readJSON(t, resp)
	result := body["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools count = %d, want 2", len(tools))
	}

	// Call each tool.
	resp = doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{
		"name":      "add",
		"arguments": map[string]any{"a": 3.0, "b": 4.0},
	}), sid)
	body = readJSON(t, resp)
	result = body["result"].(map[string]any)
	content := result["content"].([]any)
	item := content[0].(map[string]any)
	if item["text"] != "7" {
		t.Errorf("add result = %v, want %q", item["text"], "7")
	}

	resp = doPost(t, ts, rpcBody(t, 3, "tools/call", map[string]any{
		"name":      "upper",
		"arguments": map[string]any{"text": "hello"},
	}), sid)
	body = readJSON(t, resp)
	result = body["result"].(map[string]any)
	content = result["content"].([]any)
	item = content[0].(map[string]any)
	if item["text"] != "HELLO" {
		t.Errorf("upper result = %v, want %q", item["text"], "HELLO")
	}
}

func TestContentTypeOnResponses(t *testing.T) {
	s := newTestServer("test")
	ts := httptest.NewServer(s)
	defer ts.Close()

	// initialize response should have Content-Type: application/json.
	resp := doPost(t, ts, rpcBody(t, 1, "initialize", nil), "")
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	resp.Body.Close()
}

func TestMultipleSessions(t *testing.T) {
	s := newTestServer("test")
	s.Tool("ping", "pong", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "pong", nil
	})
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid1 := initSession(t, ts)
	sid2 := initSession(t, ts)
	if sid1 == sid2 {
		t.Error("two initialize calls produced the same session ID")
	}

	// Both sessions should work independently.
	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{"name": "ping"}), sid1)
	body := readJSON(t, resp)
	if body["error"] != nil {
		t.Errorf("session 1 call failed: %v", body["error"])
	}

	resp = doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{"name": "ping"}), sid2)
	body = readJSON(t, resp)
	if body["error"] != nil {
		t.Errorf("session 2 call failed: %v", body["error"])
	}
}

func TestToolsCall_NoParams(t *testing.T) {
	s := newTestServer("test")
	s.Tool("noop", "does nothing", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "done", nil
	})
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts)

	// tools/call with no params should return invalid params error.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	result := readJSON(t, resp)
	errObj := result["error"].(map[string]any)
	code := int(errObj["code"].(float64))
	if code != codeInvalidParams {
		t.Errorf("error code = %d, want %d", code, codeInvalidParams)
	}
}

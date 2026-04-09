// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpclient

import (
	"encoding/json"
	"testing"
)

func TestJSONRPCRequest_Serialization(t *testing.T) {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: ToolCallParams{
			Name: "web_search",
			Arguments: map[string]interface{}{
				"query": "hello world",
			},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded["jsonrpc"] != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %v", decoded["jsonrpc"])
	}
	if decoded["method"] != "tools/call" {
		t.Errorf("Expected method=tools/call, got %v", decoded["method"])
	}
	// ID is float64 in JSON decoding
	if decoded["id"].(float64) != 1 {
		t.Errorf("Expected id=1, got %v", decoded["id"])
	}

	params := decoded["params"].(map[string]interface{})
	if params["name"] != "web_search" {
		t.Errorf("Expected params.name=web_search, got %v", params["name"])
	}
}

func TestJSONRPCRequest_OmitsEmptyParams(t *testing.T) {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if _, hasParams := decoded["params"]; hasParams {
		t.Error("Expected params to be omitted when nil")
	}
}

func TestJSONRPCResponse_Deserialization_Success(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}`

	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}
	if resp.ID != 1 {
		t.Errorf("Expected id=1, got %d", resp.ID)
	}
	if resp.Error != nil {
		t.Errorf("Expected no error, got %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Verify result can be decoded
	var result map[string]interface{}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}
	if _, ok := result["content"]; !ok {
		t.Error("Expected result to have 'content' field")
	}
}

func TestJSONRPCResponse_Deserialization_Error(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request","data":null}}`

	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("Expected non-nil error")
	}
	if resp.Error.Code != -32600 {
		t.Errorf("Expected error code -32600, got %d", resp.Error.Code)
	}
	if resp.Error.Message != "Invalid Request" {
		t.Errorf("Expected error message 'Invalid Request', got %s", resp.Error.Message)
	}
}

func TestJSONRPCNotification_NoIDField(t *testing.T) {
	notif := JSONRPCNotification{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}

	data, err := json.Marshal(notif)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if _, hasID := decoded["id"]; hasID {
		t.Error("Notification MUST NOT have an 'id' field per JSON-RPC 2.0 spec")
	}
	if decoded["method"] != "notifications/initialized" {
		t.Errorf("Expected method=notifications/initialized, got %v", decoded["method"])
	}
}

func TestToolCallParams_Serialization(t *testing.T) {
	params := ToolCallParams{
		Name: "web_search",
		Arguments: map[string]interface{}{
			"query":       "MCP specification",
			"max_results": 10,
		},
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded["name"] != "web_search" {
		t.Errorf("Expected name=web_search, got %v", decoded["name"])
	}

	args := decoded["arguments"].(map[string]interface{})
	if args["query"] != "MCP specification" {
		t.Errorf("Expected arguments.query='MCP specification', got %v", args["query"])
	}
}

func TestInitializeParams_Serialization(t *testing.T) {
	params := InitializeParams{
		ProtocolVersion: "2025-03-26",
		Capabilities:    ClientCapabilities{},
		ClientInfo: ClientInfo{
			Name:    "precinct-gateway",
			Version: "1.0.0",
		},
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded["protocolVersion"] != "2025-03-26" {
		t.Errorf("Expected protocolVersion=2025-03-26, got %v", decoded["protocolVersion"])
	}

	clientInfo := decoded["clientInfo"].(map[string]interface{})
	if clientInfo["name"] != "precinct-gateway" {
		t.Errorf("Expected clientInfo.name=precinct-gateway, got %v", clientInfo["name"])
	}
}

// --- RFA-8rd: New type tests ---

func TestClientCapabilities_WithRoots(t *testing.T) {
	caps := ClientCapabilities{
		Roots: &RootsCapability{ListChanged: true},
	}

	data, err := json.Marshal(caps)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	roots, ok := decoded["roots"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected roots in capabilities")
	}
	if listChanged, ok := roots["listChanged"].(bool); !ok || !listChanged {
		t.Error("Expected roots.listChanged=true")
	}
}

func TestClientCapabilities_EmptyOmitsFields(t *testing.T) {
	caps := ClientCapabilities{}

	data, err := json.Marshal(caps)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if _, has := decoded["roots"]; has {
		t.Error("Expected roots to be omitted when nil")
	}
	if _, has := decoded["sampling"]; has {
		t.Error("Expected sampling to be omitted when nil")
	}
}

func TestServerCapabilities_Deserialization(t *testing.T) {
	raw := `{"tools":{"listChanged":true},"resources":{"subscribe":true,"listChanged":false},"prompts":{"listChanged":true},"logging":{}}`

	var caps ServerCapabilities
	if err := json.Unmarshal([]byte(raw), &caps); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if caps.Tools == nil {
		t.Fatal("Expected non-nil tools capability")
	}
	if !caps.Tools.ListChanged {
		t.Error("Expected tools.listChanged=true")
	}

	if caps.Resources == nil {
		t.Fatal("Expected non-nil resources capability")
	}
	if !caps.Resources.Subscribe {
		t.Error("Expected resources.subscribe=true")
	}
	if caps.Resources.ListChanged {
		t.Error("Expected resources.listChanged=false")
	}

	if caps.Prompts == nil {
		t.Fatal("Expected non-nil prompts capability")
	}
	if !caps.Prompts.ListChanged {
		t.Error("Expected prompts.listChanged=true")
	}

	if caps.Logging == nil {
		t.Fatal("Expected non-nil logging capability")
	}
}

func TestInitializeResult_Deserialization(t *testing.T) {
	raw := `{"protocolVersion":"2025-03-26","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"test-server","version":"2.0"}}`

	var result InitializeResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if result.ProtocolVersion != "2025-03-26" {
		t.Errorf("Expected protocolVersion=2025-03-26, got %s", result.ProtocolVersion)
	}
	if result.ServerInfo.Name != "test-server" {
		t.Errorf("Expected serverInfo.name=test-server, got %s", result.ServerInfo.Name)
	}
	if result.ServerInfo.Version != "2.0" {
		t.Errorf("Expected serverInfo.version=2.0, got %s", result.ServerInfo.Version)
	}
	if result.Capabilities.Tools == nil {
		t.Fatal("Expected tools capability")
	}
	if !result.Capabilities.Tools.ListChanged {
		t.Error("Expected tools.listChanged=true")
	}
}

func TestSessionState_Values(t *testing.T) {
	// Verify the enum values are distinct
	if SessionUninitialized == SessionActive {
		t.Error("SessionUninitialized should not equal SessionActive")
	}
	if SessionActive == SessionExpired {
		t.Error("SessionActive should not equal SessionExpired")
	}
	if SessionUninitialized == SessionExpired {
		t.Error("SessionUninitialized should not equal SessionExpired")
	}

	// Verify iota ordering
	if SessionUninitialized != 0 {
		t.Errorf("Expected SessionUninitialized=0, got %d", SessionUninitialized)
	}
	if SessionActive != 1 {
		t.Errorf("Expected SessionActive=1, got %d", SessionActive)
	}
	if SessionExpired != 2 {
		t.Errorf("Expected SessionExpired=2, got %d", SessionExpired)
	}
}

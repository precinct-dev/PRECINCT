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
			"query":      "MCP specification",
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
			Name:    "mcp-security-gateway",
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
	if clientInfo["name"] != "mcp-security-gateway" {
		t.Errorf("Expected clientInfo.name=mcp-security-gateway, got %v", clientInfo["name"])
	}
}

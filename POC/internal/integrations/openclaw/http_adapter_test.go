package openclaw

import "testing"

func TestOpenClawParseResponsesRequest_StringInput(t *testing.T) {
	raw := []byte(`{
		"model":"llama-3.3-70b-versatile",
		"input":"Summarize this text.",
		"instructions":"Use concise bullet points.",
		"stream":false,
		"max_output_tokens":128
	}`)

	req, err := ParseResponsesRequest(raw)
	if err != nil {
		t.Fatalf("ParseResponsesRequest failed: %v", err)
	}
	if req.Model != "llama-3.3-70b-versatile" {
		t.Fatalf("expected model, got %q", req.Model)
	}
	if len(req.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(req.Messages))
	}
	if req.Messages[0].Role != "user" {
		t.Fatalf("expected user role, got %q", req.Messages[0].Role)
	}
	if req.Messages[0].Content != "Summarize this text." {
		t.Fatalf("unexpected message content: %q", req.Messages[0].Content)
	}

	openAIMessages := BuildOpenAIMessages(req)
	if len(openAIMessages) != 2 {
		t.Fatalf("expected system + user messages, got %d", len(openAIMessages))
	}
}

func TestOpenClawParseResponsesRequest_ItemInput(t *testing.T) {
	raw := []byte(`{
		"model":"gpt-4o",
		"input":[
			{"type":"message","role":"developer","content":"Follow security policy."},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"Hello"},{"type":"input_text","text":"world"}]},
			{"type":"function_call_output","call_id":"call_1","output":"{\"ok\":true}"}
		]
	}`)

	req, err := ParseResponsesRequest(raw)
	if err != nil {
		t.Fatalf("ParseResponsesRequest failed: %v", err)
	}
	if len(req.Messages) != 3 {
		t.Fatalf("expected 3 normalized messages, got %d", len(req.Messages))
	}
	if req.Messages[0].Role != "system" {
		t.Fatalf("expected normalized developer->system role, got %q", req.Messages[0].Role)
	}
	if req.Messages[1].Content != "Hello\nworld" {
		t.Fatalf("unexpected merged content: %q", req.Messages[1].Content)
	}
	if req.Messages[2].Role != "tool" {
		t.Fatalf("expected function_call_output normalized to tool role, got %q", req.Messages[2].Role)
	}
}

func TestOpenClawParseToolsInvokeRequest(t *testing.T) {
	raw := []byte(`{
		"tool":"read",
		"action":"tool.execute",
		"sessionKey":"openresponses-main",
		"args":{"path":"/tmp/demo.txt","approval_capability_token":"tok_123"}
	}`)

	req, err := ParseToolsInvokeRequest(raw)
	if err != nil {
		t.Fatalf("ParseToolsInvokeRequest failed: %v", err)
	}
	if req.Tool != "read" {
		t.Fatalf("expected tool read, got %q", req.Tool)
	}
	if req.ApprovalToken != "tok_123" {
		t.Fatalf("expected approval token from args, got %q", req.ApprovalToken)
	}

	target := ResolveToolPolicyTarget(req)
	if target.CapabilityID != "tool.default.mcp" {
		t.Fatalf("expected default mcp capability, got %q", target.CapabilityID)
	}
	if target.Resource != "tool/read" {
		t.Fatalf("expected tool/read resource, got %q", target.Resource)
	}
}

func TestOpenClawDangerousToolDetection(t *testing.T) {
	if !IsDangerousHTTPTool("sessions_spawn") {
		t.Fatal("sessions_spawn should be dangerous")
	}
	if !IsDangerousHTTPTool("BASH") {
		t.Fatal("BASH should be dangerous (case-insensitive)")
	}
	if IsDangerousHTTPTool("read") {
		t.Fatal("read should not be dangerous")
	}
}

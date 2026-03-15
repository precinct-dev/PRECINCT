package mcpclient

import (
	"strings"
	"testing"
)

// --- SSE Event Parsing Tests ---

func TestParseSSEEvents_SingleEvent(t *testing.T) {
	input := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"ok\"}}\n\n"
	events, err := ParseSSEEvents(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	if events[0].Event != "message" {
		t.Errorf("Expected event type 'message', got '%s'", events[0].Event)
	}
	if events[0].Data != `{"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}` {
		t.Errorf("Unexpected data: %s", events[0].Data)
	}
}

func TestParseSSEEvents_MultipleEvents(t *testing.T) {
	input := "event: message\ndata: {\"id\":1}\n\nevent: message\ndata: {\"id\":2}\n\n"
	events, err := ParseSSEEvents(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEEvents failed: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(events))
	}
	if events[0].Data != `{"id":1}` {
		t.Errorf("Event 0 unexpected data: %s", events[0].Data)
	}
	if events[1].Data != `{"id":2}` {
		t.Errorf("Event 1 unexpected data: %s", events[1].Data)
	}
}

func TestParseSSEEvents_MultiLineData(t *testing.T) {
	// Multiple "data:" lines for one event are joined with newlines
	input := "event: message\ndata: line1\ndata: line2\ndata: line3\n\n"
	events, err := ParseSSEEvents(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	expected := "line1\nline2\nline3"
	if events[0].Data != expected {
		t.Errorf("Expected multi-line data %q, got %q", expected, events[0].Data)
	}
}

func TestParseSSEEvents_Comments(t *testing.T) {
	// Lines starting with ":" are comments and should be ignored
	input := ": this is a comment\nevent: message\ndata: hello\n\n"
	events, err := ParseSSEEvents(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	if events[0].Data != "hello" {
		t.Errorf("Expected data 'hello', got '%s'", events[0].Data)
	}
}

func TestParseSSEEvents_DefaultEventType(t *testing.T) {
	// If no "event:" field is specified, event type defaults to empty string
	input := "data: {\"id\":1}\n\n"
	events, err := ParseSSEEvents(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	if events[0].Event != "" {
		t.Errorf("Expected empty event type, got '%s'", events[0].Event)
	}
}

func TestParseSSEEvents_NoTrailingBlankLine(t *testing.T) {
	// Stream ends without trailing blank line -- event should still be emitted
	input := "event: message\ndata: last-event"
	events, err := ParseSSEEvents(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	if events[0].Data != "last-event" {
		t.Errorf("Expected data 'last-event', got '%s'", events[0].Data)
	}
}

func TestParseSSEEvents_EmptyStream(t *testing.T) {
	events, err := ParseSSEEvents(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseSSEEvents failed: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("Expected 0 events for empty stream, got %d", len(events))
	}
}

func TestParseSSEEvents_DataWithLeadingSpace(t *testing.T) {
	// Per SSE spec, a single leading space after colon is stripped
	input := "data: hello world\n\n"
	events, err := ParseSSEEvents(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	if events[0].Data != "hello world" {
		t.Errorf("Expected 'hello world', got '%s'", events[0].Data)
	}
}

func TestParseSSEEvents_DataNoLeadingSpace(t *testing.T) {
	// Colon with no space -- value includes everything after colon
	input := "data:nospace\n\n"
	events, err := ParseSSEEvents(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	if events[0].Data != "nospace" {
		t.Errorf("Expected 'nospace', got '%s'", events[0].Data)
	}
}

func TestParseSSEEvents_EmptyDataLine(t *testing.T) {
	// "data:" with nothing after colon -- empty data line (empty string)
	input := "data:\n\n"
	events, err := ParseSSEEvents(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	if events[0].Data != "" {
		t.Errorf("Expected empty data, got '%s'", events[0].Data)
	}
}

// --- SSE Response Parsing Tests ---

func TestParseSSEResponse_ValidSingleEvent(t *testing.T) {
	input := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"hello\"}]}}\n\n"
	resp, err := ParseSSEResponse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEResponse failed: %v", err)
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
}

func TestParseSSEResponse_DefaultEventType(t *testing.T) {
	// No explicit "event:" field -- defaults to "message" per SSE spec
	input := "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	resp, err := ParseSSEResponse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEResponse failed: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}
}

func TestParseSSEResponse_MultipleEvents_FirstMessageReturned(t *testing.T) {
	// Multiple events -- returns the first "message" type event
	input := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"first\":true}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"second\":true}}\n\n"
	resp, err := ParseSSEResponse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEResponse failed: %v", err)
	}
	if resp.ID != 1 {
		t.Errorf("Expected first event (id=1), got id=%d", resp.ID)
	}
}

func TestParseSSEResponse_SkipsNonMessageEvents(t *testing.T) {
	// Non-message events should be skipped
	input := "event: ping\ndata: keep-alive\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	resp, err := ParseSSEResponse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEResponse failed: %v", err)
	}
	if resp.ID != 1 {
		t.Errorf("Expected message event (id=1), got id=%d", resp.ID)
	}
}

func TestParseSSEResponse_EmptyStream_Error(t *testing.T) {
	_, err := ParseSSEResponse(strings.NewReader(""))
	if err == nil {
		t.Fatal("Expected error for empty stream")
	}
	if !strings.Contains(err.Error(), "no SSE events found") {
		t.Errorf("Expected 'no SSE events found' error, got: %v", err)
	}
}

func TestParseSSEResponse_MalformedJSON_Error(t *testing.T) {
	input := "event: message\ndata: this is not json\n\n"
	_, err := ParseSSEResponse(strings.NewReader(input))
	if err == nil {
		t.Fatal("Expected error for malformed JSON in SSE data")
	}
	if !strings.Contains(err.Error(), "failed to parse JSON-RPC") {
		t.Errorf("Expected JSON parse error, got: %v", err)
	}
}

func TestParseSSEResponse_NoMessageEvent_Error(t *testing.T) {
	// Only non-message events (e.g., "ping") -- should error
	input := "event: ping\ndata: keep-alive\n\n"
	_, err := ParseSSEResponse(strings.NewReader(input))
	if err == nil {
		t.Fatal("Expected error when no 'message' event found")
	}
	if !strings.Contains(err.Error(), "no SSE event with type 'message' found") {
		t.Errorf("Expected 'no message event' error, got: %v", err)
	}
}

func TestParseSSEResponse_MissingDataField(t *testing.T) {
	// Event with event: field but no data: field -- should have empty data, skip it
	input := "event: message\n\n"
	_, err := ParseSSEResponse(strings.NewReader(input))
	if err == nil {
		t.Fatal("Expected error when message event has no data")
	}
}

func TestParseSSEResponse_TruncatedStream(t *testing.T) {
	// Stream cuts off mid-event with no blank line delimiter
	input := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"
	resp, err := ParseSSEResponse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEResponse failed on truncated stream: %v", err)
	}
	// Should still parse the event from the final-event handler
	if resp.ID != 1 {
		t.Errorf("Expected id=1 from truncated stream, got %d", resp.ID)
	}
}

func TestParseSSEResponse_WithJSONRPCError(t *testing.T) {
	input := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}\n\n"
	resp, err := ParseSSEResponse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSSEResponse failed: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("Expected non-nil JSON-RPC error")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("Expected error code -32601, got %d", resp.Error.Code)
	}
	if resp.Error.Message != "Method not found" {
		t.Errorf("Expected 'Method not found', got '%s'", resp.Error.Message)
	}
}

// --- parseSSEField Tests ---

func TestParseSSEField_Standard(t *testing.T) {
	field, value := parseSSEField("event: message")
	if field != "event" || value != "message" {
		t.Errorf("Expected (event, message), got (%s, %s)", field, value)
	}
}

func TestParseSSEField_NoSpace(t *testing.T) {
	field, value := parseSSEField("data:nospace")
	if field != "data" || value != "nospace" {
		t.Errorf("Expected (data, nospace), got (%s, %s)", field, value)
	}
}

func TestParseSSEField_NoColon(t *testing.T) {
	field, value := parseSSEField("fieldonly")
	if field != "fieldonly" || value != "" {
		t.Errorf("Expected (fieldonly, ''), got (%s, %s)", field, value)
	}
}

func TestParseSSEField_EmptyValue(t *testing.T) {
	field, value := parseSSEField("data:")
	if field != "data" || value != "" {
		t.Errorf("Expected (data, ''), got (%s, %s)", field, value)
	}
}

func TestParseSSEField_ValueWithColons(t *testing.T) {
	// Only the first colon is the field separator
	field, value := parseSSEField("data: http://example.com:8080")
	if field != "data" || value != "http://example.com:8080" {
		t.Errorf("Expected (data, http://example.com:8080), got (%s, %s)", field, value)
	}
}

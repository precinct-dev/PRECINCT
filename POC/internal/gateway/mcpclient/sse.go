// SSE response parsing for MCP Streamable HTTP transport.
// RFA-8rd: When an MCP server responds with Content-Type: text/event-stream,
// the response body contains Server-Sent Events. Each SSE event has an
// "event:" field (type) and a "data:" field (payload). For MCP, the event
// type is "message" and the data field contains a JSON-RPC response.
//
// SSE format per https://html.spec.whatwg.org/multipage/server-sent-events.html:
//
//	event: message
//	data: {"jsonrpc":"2.0","id":1,"result":{...}}
//
//	(blank line separates events)
//
// Multiple data lines for the same event are concatenated with newlines.
// Lines starting with ":" are comments and are ignored.
// Lines with unrecognized fields are ignored per spec.
package mcpclient

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// SSEEvent represents a single parsed Server-Sent Event.
type SSEEvent struct {
	// Event is the event type (from "event:" field). Defaults to "message".
	Event string
	// Data is the event payload (from "data:" field(s), joined by newlines).
	Data string
}

// ParseSSEResponse reads a text/event-stream response body and extracts the
// first JSON-RPC response found in an SSE event with type "message".
//
// Per the MCP Streamable HTTP spec, the server sends one or more SSE events.
// Each event with type "message" contains a JSON-RPC response in its data field.
// This function returns the first such response, which is the reply to the
// request that triggered this SSE stream.
//
// Returns an error if:
//   - No events are found in the stream
//   - No event has type "message"
//   - The data field cannot be parsed as a JSON-RPC response
func ParseSSEResponse(body io.Reader) (*JSONRPCResponse, error) {
	events, err := ParseSSEEvents(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSE events: %w", err)
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("no SSE events found in response")
	}

	// Find the first "message" event (MCP spec event type for JSON-RPC responses)
	for _, ev := range events {
		if ev.Event == "message" || ev.Event == "" {
			// Default event type is "message" per SSE spec
			if ev.Data == "" {
				continue
			}
			var resp JSONRPCResponse
			if err := json.Unmarshal([]byte(ev.Data), &resp); err != nil {
				return nil, fmt.Errorf("failed to parse JSON-RPC from SSE data: %w", err)
			}
			return &resp, nil
		}
	}

	return nil, fmt.Errorf("no SSE event with type 'message' found")
}

// ParseSSEEvents parses a text/event-stream body into individual SSE events.
// Handles multi-line data fields, comments, and blank-line event delimiters.
func ParseSSEEvents(body io.Reader) ([]SSEEvent, error) {
	var events []SSEEvent
	scanner := bufio.NewScanner(body)

	var currentEvent SSEEvent
	var dataLines []string
	hasData := false

	for scanner.Scan() {
		line := scanner.Text()

		// Blank line signals end of current event
		if line == "" {
			if hasData {
				currentEvent.Data = strings.Join(dataLines, "\n")
				events = append(events, currentEvent)
			}
			// Reset for next event
			currentEvent = SSEEvent{}
			dataLines = nil
			hasData = false
			continue
		}

		// Comment lines start with ":"
		if strings.HasPrefix(line, ":") {
			continue
		}

		// Parse field:value
		field, value := parseSSEField(line)

		switch field {
		case "event":
			currentEvent.Event = value
		case "data":
			dataLines = append(dataLines, value)
			hasData = true
		// "id" and "retry" fields are valid SSE but not used by MCP transport;
		// we ignore them per spec (unknown fields are ignored).
		}
	}

	if err := scanner.Err(); err != nil {
		return events, fmt.Errorf("error reading SSE stream: %w", err)
	}

	// Handle final event if stream ends without trailing blank line
	if hasData {
		currentEvent.Data = strings.Join(dataLines, "\n")
		events = append(events, currentEvent)
	}

	return events, nil
}

// parseSSEField splits an SSE line into field name and value.
// Per spec: "field: value" where leading space after colon is stripped.
// If no colon, the entire line is the field name with empty value.
func parseSSEField(line string) (string, string) {
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		// No colon: entire line is field name, value is empty
		return line, ""
	}
	field := line[:idx]
	value := line[idx+1:]
	// Strip single leading space from value if present (per SSE spec)
	if len(value) > 0 && value[0] == ' ' {
		value = value[1:]
	}
	return field, value
}

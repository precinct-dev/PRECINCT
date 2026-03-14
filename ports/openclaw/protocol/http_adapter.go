package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	ResponsesPath   = "/v1/responses"
	ToolsInvokePath = "/tools/invoke"
)

var dangerousHTTPToolSet = map[string]struct{}{
	"sessions_spawn": {},
	"sessions_send":  {},
	"gateway":        {},
	"whatsapp_login": {},
	"exec":           {},
	"shell":          {},
	"bash":           {},
}

type ResponseMessage struct {
	Role    string
	Content string
}

type ResponsesRequest struct {
	Model           string
	Messages        []ResponseMessage
	Instructions    string
	Stream          bool
	User            string
	MaxOutputTokens int
}

type ToolsInvokeRequest struct {
	Tool          string
	Action        string
	Args          map[string]any
	SessionKey    string
	DryRun        bool
	ApprovalToken string
}

type ToolPolicyTarget struct {
	Action       string
	Resource     string
	CapabilityID string
	Adapter      string
}

func ParseResponsesRequest(raw []byte) (ResponsesRequest, error) {
	if len(raw) == 0 {
		return ResponsesRequest{}, errors.New("request body is empty")
	}

	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return ResponsesRequest{}, fmt.Errorf("invalid JSON: %w", err)
	}

	req := ResponsesRequest{
		Model:           strings.TrimSpace(stringField(body["model"])),
		Instructions:    strings.TrimSpace(stringField(body["instructions"])),
		Stream:          boolField(body["stream"]),
		User:            strings.TrimSpace(stringField(body["user"])),
		MaxOutputTokens: intField(body["max_output_tokens"], 0),
	}
	if req.Model == "" {
		return ResponsesRequest{}, errors.New("model is required")
	}

	messages, err := parseResponseInput(body["input"])
	if err != nil {
		return ResponsesRequest{}, err
	}
	if len(messages) == 0 {
		return ResponsesRequest{}, errors.New("input must include at least one message with text content")
	}
	req.Messages = messages

	return req, nil
}

func BuildOpenAIMessages(req ResponsesRequest) []map[string]any {
	out := make([]map[string]any, 0, len(req.Messages)+1)
	if strings.TrimSpace(req.Instructions) != "" {
		out = append(out, map[string]any{
			"role":    "system",
			"content": req.Instructions,
		})
	}
	for _, msg := range req.Messages {
		content := strings.TrimSpace(msg.Content)
		if content == "" {
			continue
		}
		role := normalizeRole(msg.Role)
		out = append(out, map[string]any{
			"role":    role,
			"content": content,
		})
	}
	return out
}

func ParseToolsInvokeRequest(raw []byte) (ToolsInvokeRequest, error) {
	if len(raw) == 0 {
		return ToolsInvokeRequest{}, errors.New("request body is empty")
	}

	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return ToolsInvokeRequest{}, fmt.Errorf("invalid JSON: %w", err)
	}

	args := map[string]any{}
	if rawArgs, ok := body["args"].(map[string]any); ok {
		args = rawArgs
	}

	tool := strings.TrimSpace(stringField(body["tool"]))
	if tool == "" {
		return ToolsInvokeRequest{}, errors.New("tool is required")
	}

	approvalToken := strings.TrimSpace(stringField(body["approval_capability_token"]))
	if approvalToken == "" {
		approvalToken = strings.TrimSpace(stringField(body["step_up_token"]))
	}
	if approvalToken == "" {
		approvalToken = strings.TrimSpace(stringField(body["approval_token"]))
	}
	if approvalToken == "" {
		approvalToken = strings.TrimSpace(stringField(args["approval_capability_token"]))
	}
	if approvalToken == "" {
		approvalToken = strings.TrimSpace(stringField(args["step_up_token"]))
	}
	if approvalToken == "" {
		approvalToken = strings.TrimSpace(stringField(args["approval_token"]))
	}

	return ToolsInvokeRequest{
		Tool:          tool,
		Action:        strings.TrimSpace(stringField(body["action"])),
		Args:          args,
		SessionKey:    strings.TrimSpace(stringField(body["sessionKey"])),
		DryRun:        boolField(body["dryRun"]),
		ApprovalToken: approvalToken,
	}, nil
}

func ResolveToolPolicyTarget(req ToolsInvokeRequest) ToolPolicyTarget {
	tool := strings.ToLower(strings.TrimSpace(req.Tool))
	target := ToolPolicyTarget{
		Action:       "tool.execute",
		Resource:     "tool/execute",
		CapabilityID: "tool.default.mcp",
		Adapter:      "mcp",
	}
	if action := strings.TrimSpace(req.Action); action != "" {
		target.Action = action
	}

	switch tool {
	case "read":
		target.Resource = "tool/read"
	case "tavily_search":
		target.Resource = "tool/search"
	case "bash", "exec", "shell":
		target.Resource = "tool/write"
		target.CapabilityID = "tool.highrisk.cli"
		target.Adapter = "cli"
	default:
		target.Resource = "tool/execute"
	}

	return target
}

func IsDangerousHTTPTool(tool string) bool {
	_, ok := dangerousHTTPToolSet[strings.ToLower(strings.TrimSpace(tool))]
	return ok
}

func parseResponseInput(input any) ([]ResponseMessage, error) {
	switch v := input.(type) {
	case string:
		content := strings.TrimSpace(v)
		if content == "" {
			return nil, errors.New("input string is empty")
		}
		return []ResponseMessage{{Role: "user", Content: content}}, nil
	case []any:
		out := make([]ResponseMessage, 0, len(v))
		for _, item := range v {
			msg, ok := item.(map[string]any)
			if !ok {
				continue
			}

			itemType := strings.ToLower(strings.TrimSpace(stringField(msg["type"])))
			switch itemType {
			case "function_call_output":
				content := strings.TrimSpace(stringField(msg["output"]))
				if content != "" {
					out = append(out, ResponseMessage{
						Role:    "tool",
						Content: content,
					})
				}
			case "", "message":
				role := normalizeRole(stringField(msg["role"]))
				content := extractMessageText(msg["content"])
				if content == "" {
					continue
				}
				out = append(out, ResponseMessage{
					Role:    role,
					Content: content,
				})
			}
		}
		if len(out) == 0 {
			return nil, errors.New("no supported message content found in input array")
		}
		return out, nil
	default:
		return nil, errors.New("input must be a string or message array")
	}
}

func extractMessageText(content any) string {
	switch v := content.(type) {
	case string:
		return strings.TrimSpace(v)
	case []any:
		parts := make([]string, 0, len(v))
		for _, raw := range v {
			part, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			partType := strings.ToLower(strings.TrimSpace(stringField(part["type"])))
			switch partType {
			case "input_text", "output_text":
				if text := strings.TrimSpace(stringField(part["text"])); text != "" {
					parts = append(parts, text)
				}
			}
		}
		return strings.TrimSpace(strings.Join(parts, "\n"))
	default:
		return ""
	}
}

func normalizeRole(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "system", "developer":
		return "system"
	case "assistant":
		return "assistant"
	case "tool", "function":
		return "tool"
	default:
		return "user"
	}
}

func stringField(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func boolField(v any) bool {
	switch vv := v.(type) {
	case bool:
		return vv
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(vv))
		return err == nil && parsed
	default:
		return false
	}
}

func intField(v any, fallback int) int {
	switch vv := v.(type) {
	case int:
		return vv
	case int32:
		return int(vv)
	case int64:
		return int(vv)
	case float64:
		return int(vv)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(vv))
		if err == nil {
			return n
		}
	}
	return fallback
}

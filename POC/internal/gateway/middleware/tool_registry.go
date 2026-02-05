package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// MCPRequest represents a simplified MCP JSON-RPC request
type MCPRequest struct {
	Jsonrpc string                 `json:"jsonrpc"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params"`
	ID      interface{}            `json:"id"`
}

// ToolRegistry manages tool verification with hash checking
type ToolRegistry struct {
	endpoint string
	// In-memory allowed tools for skeleton (would be fetched from registry)
	allowedTools map[string]string // tool_name -> hash
}

// NewToolRegistry creates a new tool registry client
func NewToolRegistry(endpoint string) *ToolRegistry {
	// Hardcoded allowed tools for skeleton
	// In production, these would be fetched from the tool registry service
	return &ToolRegistry{
		endpoint: endpoint,
		allowedTools: map[string]string{
			"file_read":       "abc123def456",
			"file_list":       "def456ghi789",
			"search":          "ghi789jkl012",
			"http_request":    "jkl012mno345",
			"database_query":  "mno345pqr678",
			"docker_exec":     "pqr678stu901",
			"llm_query":       "stu901vwx234",
		},
	}
}

// VerifyTool checks if a tool is allowed and matches expected hash
func (tr *ToolRegistry) VerifyTool(toolName string) (bool, string) {
	expectedHash, exists := tr.allowedTools[toolName]
	if !exists {
		return false, "tool_not_found"
	}

	// In skeleton, we just check presence
	// In production, would verify actual hash of tool implementation
	return true, expectedHash
}

// ComputeHash computes SHA-256 hash of tool name (placeholder for actual tool hash)
func ComputeHash(toolName string) string {
	hash := sha256.Sum256([]byte(toolName))
	return hex.EncodeToString(hash[:])
}

// ToolRegistryVerify middleware verifies tool authorization
func ToolRegistryVerify(next http.Handler, registry *ToolRegistry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get request body from context
		body := GetRequestBody(r.Context())
		if len(body) == 0 {
			// No body to verify, pass through
			next.ServeHTTP(w, r)
			return
		}

		// Parse MCP request to extract tool name
		var mcpReq MCPRequest
		if err := json.Unmarshal(body, &mcpReq); err != nil {
			// Not a valid MCP request, pass through
			next.ServeHTTP(w, r)
			return
		}

		// Extract tool name from method or params
		toolName := mcpReq.Method
		if toolName == "" {
			// Try to get from params
			if tn, ok := mcpReq.Params["tool"]; ok {
				if toolNameStr, ok := tn.(string); ok {
					toolName = toolNameStr
				}
			}
		}

		// Verify tool if we extracted a name
		if toolName != "" {
			allowed, hash := registry.VerifyTool(toolName)
			if !allowed {
				http.Error(w, "Tool not authorized", http.StatusForbidden)
				return
			}
			// Log verification (hash would be checked in production)
			_ = hash // Suppress unused warning
		}

		next.ServeHTTP(w, r)
	})
}

package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

// MCPRequest represents a simplified MCP JSON-RPC request
type MCPRequest struct {
	Jsonrpc string                 `json:"jsonrpc"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params"`
	ID      interface{}            `json:"id"`
}

// ToolDefinition represents a tool from the registry config
type ToolDefinition struct {
	Name                string                 `yaml:"name"`
	Description         string                 `yaml:"description"`
	Hash                string                 `yaml:"hash"`
	InputSchema         map[string]interface{} `yaml:"input_schema"`
	AllowedDestinations []string               `yaml:"allowed_destinations"`
	AllowedPaths        []string               `yaml:"allowed_paths"`
	RiskLevel           string                 `yaml:"risk_level"`
	RequiresStepUp      bool                   `yaml:"requires_step_up"`
}

// ToolRegistryConfig represents the tool registry configuration file
type ToolRegistryConfig struct {
	Tools []ToolDefinition `yaml:"tools"`
}

// ToolRegistry manages tool verification with hash checking
type ToolRegistry struct {
	endpoint string
	tools    map[string]ToolDefinition // tool_name -> definition
}

// NewToolRegistry creates a new tool registry client
func NewToolRegistry(endpoint string, configPath string) (*ToolRegistry, error) {
	registry := &ToolRegistry{
		endpoint: endpoint,
		tools:    make(map[string]ToolDefinition),
	}

	// Load configuration from file
	if configPath != "" {
		if err := registry.loadConfig(configPath); err != nil {
			return nil, fmt.Errorf("failed to load tool registry config: %w", err)
		}
	}

	return registry, nil
}

// loadConfig loads tool definitions from YAML config file
func (tr *ToolRegistry) loadConfig(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config ToolRegistryConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Load tools into map
	for _, tool := range config.Tools {
		tr.tools[tool.Name] = tool
	}

	return nil
}

// VerifyTool checks if a tool is allowed and matches expected hash
func (tr *ToolRegistry) VerifyTool(toolName string, providedHash string) (bool, string) {
	toolDef, exists := tr.tools[toolName]
	if !exists {
		return false, "tool_not_found"
	}

	// Verify hash if provided
	if providedHash != "" && providedHash != toolDef.Hash {
		return false, "hash_mismatch"
	}

	return true, toolDef.Hash
}

// GetToolDefinition returns the tool definition for a given tool name
func (tr *ToolRegistry) GetToolDefinition(toolName string) (ToolDefinition, bool) {
	toolDef, exists := tr.tools[toolName]
	return toolDef, exists
}

// ComputeHash computes SHA-256 hash of tool description + input schema
// This is the canonical hash computation for tool verification
func ComputeHash(description string, inputSchema map[string]interface{}) string {
	// Serialize input schema to canonical JSON (sorted keys, no whitespace)
	schemaJSON, err := json.Marshal(inputSchema)
	if err != nil {
		// If schema can't be marshaled, use empty string
		schemaJSON = []byte("{}")
	}

	// Compute hash over description + schema
	content := description + string(schemaJSON)
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// ToolRegistryVerify middleware verifies tool authorization with hash checking
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
			// Extract provided hash from params if present
			providedHash := ""
			if hash, ok := mcpReq.Params["tool_hash"]; ok {
				if hashStr, ok := hash.(string); ok {
					providedHash = hashStr
				}
			}

			allowed, reason := registry.VerifyTool(toolName, providedHash)
			if !allowed {
				http.Error(w, fmt.Sprintf("Tool not authorized: %s", reason), http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

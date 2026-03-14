// Story RFA-qq0.6 - Helper script to compute tool hashes
// Computes SHA-256 hashes for Docker MCP tools (Tavily, read, grep, bash)
// Usage: go run scripts/compute_tool_hashes.go
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ComputeHash computes SHA-256 hash of tool description + input schema
func ComputeHash(description string, inputSchema map[string]interface{}) string {
	// Serialize input schema to canonical JSON (sorted keys, no whitespace)
	schemaJSON, err := json.Marshal(inputSchema)
	if err != nil {
		schemaJSON = []byte("{}")
	}

	// Compute hash over description + schema
	content := description + string(schemaJSON)
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

func main() {
	// Define tools with their descriptions and schemas from tool-registry.yaml
	tools := []struct {
		name        string
		description string
		inputSchema map[string]interface{}
	}{
		{
			name:        "tavily_search",
			description: "Search the web using Tavily API",
			inputSchema: map[string]interface{}{
				"type":     "object",
				"required": []interface{}{"query"},
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "Search query",
					},
					"max_results": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum results to return",
						"default":     5,
					},
				},
			},
		},
		{
			name:        "read",
			description: "Read file contents from filesystem",
			inputSchema: map[string]interface{}{
				"type":     "object",
				"required": []interface{}{"file_path"},
				"properties": map[string]interface{}{
					"file_path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to file",
					},
					"offset": map[string]interface{}{
						"type":        "integer",
						"description": "Line number to start reading",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Number of lines to read",
					},
				},
			},
		},
		{
			name:        "grep",
			description: "Search for patterns in files",
			inputSchema: map[string]interface{}{
				"type":     "object",
				"required": []interface{}{"pattern", "path"},
				"properties": map[string]interface{}{
					"pattern": map[string]interface{}{
						"type":        "string",
						"description": "Regular expression pattern",
					},
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Directory or file path to search",
					},
					"glob": map[string]interface{}{
						"type":        "string",
						"description": "Glob pattern to filter files",
					},
					"output_mode": map[string]interface{}{
						"type": "string",
						"enum": []interface{}{"content", "files_with_matches", "count"},
					},
				},
			},
		},
		{
			name:        "bash",
			description: "Execute shell commands",
			inputSchema: map[string]interface{}{
				"type":     "object",
				"required": []interface{}{"command"},
				"properties": map[string]interface{}{
					"command": map[string]interface{}{
						"type":        "string",
						"description": "Shell command to execute",
					},
					"timeout": map[string]interface{}{
						"type":        "integer",
						"description": "Timeout in milliseconds",
					},
					"run_in_background": map[string]interface{}{
						"type":        "boolean",
						"description": "Run command in background",
					},
				},
			},
		},
	}

	fmt.Println("# Tool Hashes for RFA-qq0.6 - Docker MCP Server Integration")
	fmt.Println("# Computed using SHA-256(description + canonical_json(input_schema))")
	fmt.Println()

	for _, tool := range tools {
		hash := ComputeHash(tool.description, tool.inputSchema)
		fmt.Printf("Tool: %s\n", tool.name)
		fmt.Printf("Hash: %s\n", hash)
		fmt.Println()
	}
}

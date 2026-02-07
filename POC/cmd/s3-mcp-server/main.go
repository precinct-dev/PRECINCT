// S3 MCP Tool Server - RFA-9fv.5
//
// Go microservice implementing the MCP JSON-RPC protocol for S3 access.
// Provides two tools:
//   - s3_list_objects: List objects in an allowed S3 bucket/prefix
//   - s3_get_object: Read object content from an allowed S3 bucket/prefix
//
// Security: Enforces a destination allowlist of bucket/prefix pairs.
// Requests for buckets or prefixes not in the allowlist are rejected.
//
// SPIFFE-aware: Mounts SPIRE agent socket for workload identity.
// AWS credentials: Via IRSA (IAM Roles for Service Accounts) in EKS.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// AllowlistEntry defines an allowed bucket and prefix combination.
type AllowlistEntry struct {
	Bucket string `json:"bucket" yaml:"bucket"`
	Prefix string `json:"prefix" yaml:"prefix"`
}

// ServerConfig holds the S3 MCP server configuration.
type ServerConfig struct {
	Port      int              `json:"port"`
	Allowlist []AllowlistEntry `json:"allowlist"`
	AWSRegion string           `json:"aws_region"`
}

// S3Client abstracts the S3 operations for testing.
type S3Client interface {
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// MCPServer implements the MCP JSON-RPC protocol for S3 tools.
type MCPServer struct {
	s3Client  S3Client
	allowlist []AllowlistEntry
}

// JSONRPCRequest represents an incoming MCP JSON-RPC request.
type JSONRPCRequest struct {
	Jsonrpc string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

// JSONRPCResponse represents an outgoing MCP JSON-RPC response.
type JSONRPCResponse struct {
	Jsonrpc string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC error.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ToolDefinition describes an MCP tool for tools/list.
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// ToolCallParams holds the parameters for tools/call.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// ContentItem represents an MCP content item in a tool result.
type ContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolResult represents the result of a tool call.
type ToolResult struct {
	Content []ContentItem `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// S3ListObjectsDescription is the tool description for s3_list_objects.
const S3ListObjectsDescription = "List objects in an S3 bucket with allowed prefix"

// S3GetObjectDescription is the tool description for s3_get_object.
const S3GetObjectDescription = "Read an object from an S3 bucket with allowed prefix"

// S3ListObjectsSchema returns the input schema for s3_list_objects.
func S3ListObjectsSchema() map[string]interface{} {
	return map[string]interface{}{
		"type":     "object",
		"required": []interface{}{"bucket", "prefix"},
		"properties": map[string]interface{}{
			"bucket": map[string]interface{}{
				"type":        "string",
				"description": "S3 bucket name",
			},
			"prefix": map[string]interface{}{
				"type":        "string",
				"description": "Object key prefix",
			},
			"max_keys": map[string]interface{}{
				"type":        "integer",
				"description": "Max objects to return",
				"default":     100,
			},
		},
	}
}

// S3GetObjectSchema returns the input schema for s3_get_object.
func S3GetObjectSchema() map[string]interface{} {
	return map[string]interface{}{
		"type":     "object",
		"required": []interface{}{"bucket", "key"},
		"properties": map[string]interface{}{
			"bucket": map[string]interface{}{
				"type":        "string",
				"description": "S3 bucket name",
			},
			"key": map[string]interface{}{
				"type":        "string",
				"description": "Object key",
			},
		},
	}
}

// toolDefinitions returns the list of tools this server provides.
func toolDefinitions() []ToolDefinition {
	return []ToolDefinition{
		{
			Name:        "s3_list_objects",
			Description: S3ListObjectsDescription,
			InputSchema: S3ListObjectsSchema(),
		},
		{
			Name:        "s3_get_object",
			Description: S3GetObjectDescription,
			InputSchema: S3GetObjectSchema(),
		},
	}
}

// NewMCPServer creates a new MCPServer with the given S3 client and allowlist.
func NewMCPServer(client S3Client, allowlist []AllowlistEntry) *MCPServer {
	return &MCPServer{
		s3Client:  client,
		allowlist: allowlist,
	}
}

// IsAllowed checks whether the given bucket and key/prefix are permitted
// by the allowlist. A request is allowed if the bucket matches and the
// key/prefix starts with the allowed prefix.
func (m *MCPServer) IsAllowed(bucket, keyOrPrefix string) bool {
	for _, entry := range m.allowlist {
		if entry.Bucket == bucket && strings.HasPrefix(keyOrPrefix, entry.Prefix) {
			return true
		}
	}
	return false
}

// HandleToolsList handles the MCP tools/list method.
func (m *MCPServer) HandleToolsList(id interface{}) JSONRPCResponse {
	return JSONRPCResponse{
		Jsonrpc: "2.0",
		ID:      id,
		Result: map[string]interface{}{
			"tools": toolDefinitions(),
		},
	}
}

// HandleToolsCall handles the MCP tools/call method.
func (m *MCPServer) HandleToolsCall(ctx context.Context, id interface{}, params ToolCallParams) JSONRPCResponse {
	switch params.Name {
	case "s3_list_objects":
		return m.handleListObjects(ctx, id, params.Arguments)
	case "s3_get_object":
		return m.handleGetObject(ctx, id, params.Arguments)
	default:
		return JSONRPCResponse{
			Jsonrpc: "2.0",
			ID:      id,
			Error:   &RPCError{Code: -32601, Message: fmt.Sprintf("unknown tool: %s", params.Name)},
		}
	}
}

// handleListObjects implements the s3_list_objects tool.
func (m *MCPServer) handleListObjects(ctx context.Context, id interface{}, args map[string]interface{}) JSONRPCResponse {
	bucket, _ := args["bucket"].(string)
	prefix, _ := args["prefix"].(string)
	maxKeys := int32(100)
	if mk, ok := args["max_keys"].(float64); ok {
		maxKeys = int32(mk)
	}

	if bucket == "" || prefix == "" {
		return JSONRPCResponse{
			Jsonrpc: "2.0",
			ID:      id,
			Result: &ToolResult{
				Content: []ContentItem{{Type: "text", Text: "error: bucket and prefix are required"}},
				IsError: true,
			},
		}
	}

	if !m.IsAllowed(bucket, prefix) {
		return JSONRPCResponse{
			Jsonrpc: "2.0",
			ID:      id,
			Result: &ToolResult{
				Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("error: access denied - bucket=%q prefix=%q not in allowlist", bucket, prefix)}},
				IsError: true,
			},
		}
	}

	output, err := m.s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int32(maxKeys),
	})
	if err != nil {
		return JSONRPCResponse{
			Jsonrpc: "2.0",
			ID:      id,
			Result: &ToolResult{
				Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("error: S3 ListObjectsV2 failed: %v", err)}},
				IsError: true,
			},
		}
	}

	// Build text listing
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Objects in s3://%s/%s (count: %d):\n", bucket, prefix, len(output.Contents)))
	for _, obj := range output.Contents {
		sb.WriteString(fmt.Sprintf("  %s  (size: %d, modified: %s)\n",
			aws.ToString(obj.Key),
			aws.ToInt64(obj.Size),
			obj.LastModified.Format(time.RFC3339)))
	}

	return JSONRPCResponse{
		Jsonrpc: "2.0",
		ID:      id,
		Result: &ToolResult{
			Content: []ContentItem{{Type: "text", Text: sb.String()}},
		},
	}
}

// handleGetObject implements the s3_get_object tool.
func (m *MCPServer) handleGetObject(ctx context.Context, id interface{}, args map[string]interface{}) JSONRPCResponse {
	bucket, _ := args["bucket"].(string)
	key, _ := args["key"].(string)

	if bucket == "" || key == "" {
		return JSONRPCResponse{
			Jsonrpc: "2.0",
			ID:      id,
			Result: &ToolResult{
				Content: []ContentItem{{Type: "text", Text: "error: bucket and key are required"}},
				IsError: true,
			},
		}
	}

	if !m.IsAllowed(bucket, key) {
		return JSONRPCResponse{
			Jsonrpc: "2.0",
			ID:      id,
			Result: &ToolResult{
				Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("error: access denied - bucket=%q key=%q not in allowlist", bucket, key)}},
				IsError: true,
			},
		}
	}

	output, err := m.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return JSONRPCResponse{
			Jsonrpc: "2.0",
			ID:      id,
			Result: &ToolResult{
				Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("error: S3 GetObject failed: %v", err)}},
				IsError: true,
			},
		}
	}
	defer output.Body.Close()

	// Read up to 1MB of content (safety limit for POC)
	const maxReadBytes = 1 << 20
	limitedReader := io.LimitReader(output.Body, maxReadBytes)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return JSONRPCResponse{
			Jsonrpc: "2.0",
			ID:      id,
			Result: &ToolResult{
				Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("error: reading S3 object body: %v", err)}},
				IsError: true,
			},
		}
	}

	text := string(data)
	if int64(len(data)) >= maxReadBytes {
		text += "\n[truncated at 1MB]"
	}

	return JSONRPCResponse{
		Jsonrpc: "2.0",
		ID:      id,
		Result: &ToolResult{
			Content: []ContentItem{{Type: "text", Text: text}},
		},
	}
}

// ServeHTTP implements the http.Handler interface for JSON-RPC requests.
func (m *MCPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONRPCError(w, nil, -32700, "failed to read request body")
		return
	}
	defer r.Body.Close()

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONRPCError(w, nil, -32700, "parse error")
		return
	}

	var resp JSONRPCResponse

	switch req.Method {
	case "tools/list":
		resp = m.HandleToolsList(req.ID)

	case "tools/call":
		var params ToolCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			writeJSONRPCError(w, req.ID, -32602, "invalid params")
			return
		}
		resp = m.HandleToolsCall(r.Context(), req.ID, params)

	default:
		resp = JSONRPCResponse{
			Jsonrpc: "2.0",
			ID:      req.ID,
			Error:   &RPCError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)},
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// writeJSONRPCError writes a JSON-RPC error response.
func writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONRPCResponse{
		Jsonrpc: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: message},
	})
}

// parseAllowlist parses the ALLOWED_BUCKETS environment variable.
// Format: "bucket1:prefix1,bucket2:prefix2"
func parseAllowlist(raw string) []AllowlistEntry {
	var entries []AllowlistEntry
	if raw == "" {
		return entries
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Split on first colon only (prefix may contain colons)
		idx := strings.Index(part, ":")
		if idx < 0 {
			// Bucket only, empty prefix (allow entire bucket)
			entries = append(entries, AllowlistEntry{Bucket: part, Prefix: ""})
			continue
		}
		entries = append(entries, AllowlistEntry{
			Bucket: part[:idx],
			Prefix: part[idx+1:],
		})
	}
	return entries
}

func main() {
	// Health check subcommand for Docker HEALTHCHECK in distroless images
	if len(os.Args) > 1 && os.Args[1] == "health" {
		port := os.Getenv("PORT")
		if port == "" {
			port = "8082"
		}
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(fmt.Sprintf("http://localhost:%s/health", port))
		if err != nil {
			os.Exit(1)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Configuration from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	allowedBuckets := os.Getenv("ALLOWED_BUCKETS")
	allowlist := parseAllowlist(allowedBuckets)

	if len(allowlist) == 0 {
		log.Fatal("ALLOWED_BUCKETS is empty or not set. Format: bucket1:prefix1,bucket2:prefix2")
	}

	log.Printf("S3 MCP server starting on port %s", port)
	log.Printf("AWS region: %s", region)
	log.Printf("Allowlist entries: %d", len(allowlist))
	for _, e := range allowlist {
		log.Printf("  - bucket=%q prefix=%q", e.Bucket, e.Prefix)
	}

	// Initialize AWS SDK
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	s3Client := s3.NewFromConfig(cfg)
	server := NewMCPServer(s3Client, allowlist)

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      server,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("S3 MCP server listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down S3 MCP server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("S3 MCP server forced to shutdown: %v", err)
	}

	log.Println("S3 MCP server stopped")
}

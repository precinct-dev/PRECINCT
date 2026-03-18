// S3 MCP Tool Server
//
// MCP server for S3 access, built on the mcpserver framework.
// Provides two tools: s3_list_objects and s3_get_object.
// Security: enforces a destination allowlist of bucket/prefix pairs.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/precinct-dev/precinct/cmd/s3-mcp-server/s3adapter"
	"github.com/precinct-dev/precinct/pkg/mcpserver"
)

func main() {
	// Health check subcommand for Docker HEALTHCHECK in distroless images.
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
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Parse allowlist from environment.
	allowlist := s3adapter.ParseAllowlist(os.Getenv("ALLOWED_BUCKETS"))
	if len(allowlist) == 0 {
		log.Fatal("ALLOWED_BUCKETS is empty or not set. Format: bucket1:prefix1,bucket2:prefix2")
	}

	// Initialize AWS SDK.
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Create adapter and register tools with the framework.
	adapter := s3adapter.New(s3.NewFromConfig(cfg), allowlist)

	server := mcpserver.New("s3-mcp-server",
		mcpserver.WithPort(8082),
	)
	server.Tool("s3_list_objects", s3adapter.ListObjectsDescription, s3adapter.ListObjectsSchema(), adapter.ListObjects)
	server.Tool("s3_get_object", s3adapter.GetObjectDescription, s3adapter.GetObjectSchema(), adapter.GetObject)

	if err := server.Run(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

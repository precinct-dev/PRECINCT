// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// Package s3adapter provides S3 MCP tool handlers for the mcpserver framework.
//
// It extracts the S3-specific business logic (allowlist enforcement, object
// listing, object retrieval) from the hand-rolled MCP server into reusable
// ToolHandler functions compatible with [mcpserver.ToolHandler].
package s3adapter

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/precinct-dev/precinct/pkg/mcpserver"
)

// S3Client abstracts the S3 operations used by this adapter for testing.
type S3Client interface {
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// AllowlistEntry defines an allowed bucket and prefix combination.
type AllowlistEntry struct {
	Bucket string `json:"bucket" yaml:"bucket"`
	Prefix string `json:"prefix" yaml:"prefix"`
}

// maxReadBytes is the safety limit for reading S3 object bodies (1 MB).
const maxReadBytes = 1 << 20

// Adapter holds the S3 client and allowlist, providing MCP tool handlers
// for s3_list_objects and s3_get_object.
type Adapter struct {
	client    S3Client
	allowlist []AllowlistEntry
}

// New creates an Adapter with the given S3 client and allowlist.
func New(client S3Client, allowlist []AllowlistEntry) *Adapter {
	return &Adapter{
		client:    client,
		allowlist: allowlist,
	}
}

// IsAllowed checks whether the given bucket and key/prefix are permitted by
// the allowlist. A request is allowed if the bucket matches and the
// key/prefix starts with the allowed prefix.
func (a *Adapter) IsAllowed(bucket, keyOrPrefix string) bool {
	for _, entry := range a.allowlist {
		if entry.Bucket == bucket && strings.HasPrefix(keyOrPrefix, entry.Prefix) {
			return true
		}
	}
	return false
}

// ListObjects is an mcpserver.ToolHandler for the s3_list_objects tool.
func (a *Adapter) ListObjects(ctx context.Context, args map[string]any) (any, error) {
	bucket, _ := args["bucket"].(string)
	prefix, _ := args["prefix"].(string)
	maxKeys := int32(100)
	if mk, ok := args["max_keys"].(float64); ok {
		maxKeys = int32(mk)
	}

	if bucket == "" || prefix == "" {
		return nil, fmt.Errorf("bucket and prefix are required")
	}

	if !a.IsAllowed(bucket, prefix) {
		return nil, fmt.Errorf("access denied - bucket=%q prefix=%q not in allowlist", bucket, prefix)
	}

	output, err := a.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int32(maxKeys),
	})
	if err != nil {
		return nil, fmt.Errorf("S3 ListObjectsV2 failed: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Objects in s3://%s/%s (count: %d):\n", bucket, prefix, len(output.Contents))
	for _, obj := range output.Contents {
		fmt.Fprintf(&sb, "  %s  (size: %d, modified: %s)\n",
			aws.ToString(obj.Key),
			aws.ToInt64(obj.Size),
			obj.LastModified.Format(time.RFC3339))
	}

	return sb.String(), nil
}

// GetObject is an mcpserver.ToolHandler for the s3_get_object tool.
func (a *Adapter) GetObject(ctx context.Context, args map[string]any) (any, error) {
	bucket, _ := args["bucket"].(string)
	key, _ := args["key"].(string)

	if bucket == "" || key == "" {
		return nil, fmt.Errorf("bucket and key are required")
	}

	if !a.IsAllowed(bucket, key) {
		return nil, fmt.Errorf("access denied - bucket=%q key=%q not in allowlist", bucket, key)
	}

	output, err := a.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("S3 GetObject failed: %w", err)
	}
	defer func() {
		_ = output.Body.Close()
	}()

	limitedReader := io.LimitReader(output.Body, maxReadBytes)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("reading S3 object body: %w", err)
	}

	text := string(data)
	if int64(len(data)) >= maxReadBytes {
		text += "\n[truncated at 1MB]"
	}

	return text, nil
}

// ListObjectsSchema returns the mcpserver.Schema for s3_list_objects.
func ListObjectsSchema() mcpserver.Schema {
	return mcpserver.Schema{
		Type:     "object",
		Required: []string{"bucket", "prefix"},
		Properties: map[string]mcpserver.Property{
			"bucket":   {Type: "string", Description: "S3 bucket name"},
			"prefix":   {Type: "string", Description: "Object key prefix"},
			"max_keys": {Type: "integer", Description: "Max objects to return"},
		},
	}
}

// GetObjectSchema returns the mcpserver.Schema for s3_get_object.
func GetObjectSchema() mcpserver.Schema {
	return mcpserver.Schema{
		Type:     "object",
		Required: []string{"bucket", "key"},
		Properties: map[string]mcpserver.Property{
			"bucket": {Type: "string", Description: "S3 bucket name"},
			"key":    {Type: "string", Description: "Object key"},
		},
	}
}

// ListObjectsDescription is the tool description for s3_list_objects.
const ListObjectsDescription = "List objects in an S3 bucket with allowed prefix"

// GetObjectDescription is the tool description for s3_get_object.
const GetObjectDescription = "Read an object from an S3 bucket with allowed prefix"

// ParseAllowlist parses the ALLOWED_BUCKETS environment variable.
// Format: "bucket1:prefix1,bucket2:prefix2"
func ParseAllowlist(raw string) []AllowlistEntry {
	var entries []AllowlistEntry
	if raw == "" {
		return entries
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, ":")
		if idx < 0 {
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

// LegacyInputSchema returns the tool input schema as map[string]interface{}
// for backwards compatibility with the tool registry hash computation.
func LegacyInputSchema(tool string) map[string]interface{} {
	switch tool {
	case "s3_list_objects":
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
	case "s3_get_object":
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
	default:
		return nil
	}
}

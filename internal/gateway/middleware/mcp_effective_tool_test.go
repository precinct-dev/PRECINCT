// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import "testing"

func TestParsedMCPRequest_EffectiveToolNameAndParams_ToolsCall(t *testing.T) {
	r := &ParsedMCPRequest{
		RPCMethod: "tools/call",
		Params: map[string]interface{}{
			"name": "tavily_search",
			"arguments": map[string]interface{}{
				"query": "hi",
			},
		},
	}

	name, err := r.EffectiveToolName()
	if err != nil {
		t.Fatalf("Expected nil error, got %v", err)
	}
	if name != "tavily_search" {
		t.Fatalf("Expected tavily_search, got %q", name)
	}

	if !r.IsToolsCall() {
		t.Fatalf("Expected IsToolsCall=true")
	}

	args := r.EffectiveToolParams()
	if args == nil {
		t.Fatalf("Expected args map, got nil")
	}
	if args["query"] != "hi" {
		t.Fatalf("Expected args.query=hi, got %v", args["query"])
	}
}

func TestParsedMCPRequest_EffectiveToolName_ToolsCallMissingName(t *testing.T) {
	r := &ParsedMCPRequest{
		RPCMethod: "tools/call",
		Params: map[string]interface{}{
			"arguments": map[string]interface{}{},
		},
	}
	if _, err := r.EffectiveToolName(); err == nil {
		t.Fatalf("Expected error for missing params.name, got nil")
	}
}

func TestParsedMCPRequest_EffectiveToolName_LegacyDirectMethod(t *testing.T) {
	r := &ParsedMCPRequest{
		RPCMethod: "file_read",
		Params: map[string]interface{}{
			"path": "/tmp/a.txt",
		},
	}

	name, err := r.EffectiveToolName()
	if err != nil {
		t.Fatalf("Expected nil error, got %v", err)
	}
	if name != "file_read" {
		t.Fatalf("Expected file_read, got %q", name)
	}

	params := r.EffectiveToolParams()
	if params["path"] != "/tmp/a.txt" {
		t.Fatalf("Expected params.path=/tmp/a.txt, got %v", params["path"])
	}
}

func TestParsedMCPRequest_RequestTypeFlags(t *testing.T) {
	r := &ParsedMCPRequest{RPCMethod: "tools/list"}
	if !r.IsToolsList() {
		t.Fatalf("Expected IsToolsList=true")
	}
	if r.IsToolsCall() {
		t.Fatalf("Expected IsToolsCall=false")
	}

	r = &ParsedMCPRequest{RPCMethod: "notifications/initialized"}
	if !r.IsNotification() {
		t.Fatalf("Expected IsNotification=true")
	}
}

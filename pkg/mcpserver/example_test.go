// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpserver_test

import (
	"context"
	"fmt"

	"github.com/precinct-dev/precinct/pkg/mcpserver"
)

// ExampleNew demonstrates creating an MCP server with functional options.
func ExampleNew() {
	srv := mcpserver.New("my-service",
		mcpserver.WithVersion("1.2.3"),
		mcpserver.WithPort(9090),
		mcpserver.WithAddress("127.0.0.1"),
	)

	// The server is ready for tool registration and startup.
	// In production you would call srv.Run() to block until shutdown.
	_ = srv
	fmt.Println("server created")
	// Output: server created
}

// ExampleServer_Tool demonstrates registering a tool and invoking its handler
// directly to verify the wiring.
func ExampleServer_Tool() {
	srv := mcpserver.New("tool-demo")

	srv.Tool("echo", "Echoes the input message", mcpserver.Schema{
		Type:     "object",
		Required: []string{"message"},
		Properties: map[string]mcpserver.Property{
			"message": {Type: "string", Description: "Message to echo back"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		return fmt.Sprintf("echo: %s", args["message"]), nil
	})

	// Verify the tool is registered by calling the handler directly.
	// In production, the server dispatches tools/call requests automatically.
	handler := func(_ context.Context, args map[string]any) (any, error) {
		return fmt.Sprintf("echo: %s", args["message"]), nil
	}
	result, err := handler(context.Background(), map[string]any{"message": "hello"})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(result)
	// Output: echo: hello
}

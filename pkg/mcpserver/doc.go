// Package mcpserver provides a minimal MCP (Model Context Protocol) server
// framework for PRECINCT. It exposes a JSON-RPC 2.0 interface over HTTP,
// implementing the core MCP handshake (initialize / notifications/initialized)
// and tool dispatch (tools/list, tools/call).
//
// MCP protocol version: 2025-03-26.
//
// # Quick Start
//
// Create a server, register tools, and run it:
//
//	srv := mcpserver.New("echo-server",
//	    mcpserver.WithPort(9090),
//	    mcpserver.WithVersion("1.0.0"),
//	)
//
//	srv.Tool("echo", "Echoes the input message", mcpserver.Schema{
//	    Type:     "object",
//	    Required: []string{"message"},
//	    Properties: map[string]mcpserver.Property{
//	        "message": {Type: "string", Description: "Message to echo back"},
//	    },
//	}, func(ctx context.Context, args map[string]any) (any, error) {
//	    return args["message"], nil
//	})
//
//	log.Fatal(srv.Run())  // blocks until SIGINT/SIGTERM
//
// # Functional Options
//
// Pass options to [New] to override defaults:
//
//	| Option              | Default        | Description                          |
//	|---------------------|----------------|--------------------------------------|
//	| WithVersion         | "0.0.0-dev"    | Server version in initialize & /health |
//	| WithPort            | 8080           | TCP listen port                       |
//	| WithAddress         | "" (all)       | Bind address                          |
//	| WithLogger          | slog.Default() | Structured logger                     |
//	| WithShutdownTimeout | 10s            | Graceful shutdown deadline             |
//	| WithReadTimeout     | 30s            | HTTP server read timeout               |
//	| WithWriteTimeout    | 30s            | HTTP server write timeout              |
//
// # Tool Registration
//
// Register tools with [Server.Tool]. Each tool needs a name, description,
// input [Schema], and a [ToolHandler] callback. Tools can be registered
// before or after [Server.Run]; tools added after startup appear on the
// next tools/list request.
//
//	srv.Tool("greet", "Greet a user by name", mcpserver.Schema{
//	    Type:     "object",
//	    Required: []string{"name"},
//	    Properties: map[string]mcpserver.Property{
//	        "name": {Type: "string", Description: "User to greet"},
//	    },
//	}, func(ctx context.Context, args map[string]any) (any, error) {
//	    return fmt.Sprintf("Hello, %s!", args["name"]), nil
//	})
//
// # BackendAdapter Pattern
//
// [BackendAdapter] is a convenience interface for callers who want to bridge
// MCP tool calls to an existing HTTP or gRPC backend. The server does NOT
// import or use BackendAdapter internally -- it dispatches tools exclusively
// through [ToolHandler] callbacks. BackendAdapter standardises the bridging
// code so consumers don't reinvent it per project.
//
// Typical usage wraps a BackendAdapter in a ToolHandler closure:
//
//	var backend mcpserver.BackendAdapter = newHTTPBackend("http://api:8080")
//
//	srv.Tool("get_user", "Fetch a user", schema, func(ctx context.Context, args map[string]any) (any, error) {
//	    return backend.Call(ctx, "GET", "/users/"+args["id"].(string), nil)
//	})
//
// # Environment Variables
//
// The server itself does not read environment variables. Configuration is
// done exclusively through functional options. Callers are free to wire
// environment variables to options in their own main() functions:
//
//	port, _ := strconv.Atoi(os.Getenv("MCP_PORT"))
//	if port == 0 { port = 8080 }
//	srv := mcpserver.New("my-server", mcpserver.WithPort(port))
//
// # HTTP Endpoints
//
//	| Method | Path    | Purpose                                |
//	|--------|---------|----------------------------------------|
//	| POST   | /       | JSON-RPC 2.0 (MCP messages)             |
//	| GET    | /health | Readiness probe (returns server status)  |
//
// # Session Management
//
// The server manages sessions via the Mcp-Session-Id header. An initialize
// request creates a new session; all subsequent requests must include the
// session ID. Requests without a valid session receive HTTP 404.
package mcpserver

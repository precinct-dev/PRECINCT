// Package mcpserver provides a minimal MCP (Model Context Protocol) server
// framework for PRECINCT. It exposes a JSON-RPC 2.0 interface over HTTP,
// implementing the core MCP handshake (initialize / notifications/initialized)
// and tool dispatch (tools/list, tools/call).
//
// The server manages sessions via the Mcp-Session-Id header, enforces
// JSON-RPC 2.0 framing, and includes a /health endpoint for readiness
// probes.
//
// Create a server with New, register tools with Tool, and start it with Run
// (blocks until SIGINT/SIGTERM) or RunContext (blocks until context
// cancellation).
package mcpserver

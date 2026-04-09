# Mock MCP Server

Minimal MCP server implementing the Streamable HTTP transport. Returns canned
tool results for deterministic E2E testing.

Used by `make demo-compose` as the upstream MCP server behind the gateway.

## Endpoints

- `POST /mcp` -- MCP JSON-RPC 2.0 endpoint (tools/list, tools/call)

## Usage

Built and deployed automatically by the Docker Compose stack.

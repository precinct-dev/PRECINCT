# Tavily MCP Server

MCP server (Streamable HTTP transport) that calls the real Tavily search API.
Demonstrates how to wrap an external API as an MCP tool behind the PRECINCT
gateway.

## Prerequisites

Requires a `TAVILY_API_KEY` environment variable.

## Endpoints

- `POST /mcp` -- MCP JSON-RPC 2.0 endpoint (tools/list, tools/call)

## Usage

```bash
export TAVILY_API_KEY=your-key
go build -o tavily-mcp-server .
./tavily-mcp-server
```

Or via Docker Compose with the Tavily profile enabled.

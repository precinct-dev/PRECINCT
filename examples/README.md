# Examples

Starter examples and test fixtures for the PRECINCT gateway.

| Directory | Description |
|-----------|-------------|
| [go/](go/) | Go E2E demo exercising every gateway middleware layer via the Go SDK |
| [python/](python/) | Python E2E demo exercising every gateway middleware layer via the Python SDK |
| [content-scanner/](content-scanner/) | HTTP extension sidecar implementing the pluggable content scanner interface |
| [mock-mcp-server/](mock-mcp-server/) | Minimal MCP server (Streamable HTTP) returning canned results for testing |
| [mock-guard-model/](mock-guard-model/) | Mock OpenAI-compatible guard model for deterministic deep-scan testing |
| [mock-oauth-issuer/](mock-oauth-issuer/) | Test OAuth issuer with JWKS, token, and introspection endpoints |
| [tavily-mcp-server/](tavily-mcp-server/) | MCP server that calls the real Tavily search API |

## Running

Most examples are used automatically by `make demo-compose` and `make demo-k8s`.
They are built as Docker images by the Compose stack and do not need to be run
independently.

To build and run an individual example locally:

```bash
cd examples/go
go build -o demo .
./demo --gateway http://localhost:9090
```

See the top-level [README](../README.md) for full quickstart instructions.

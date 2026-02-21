# Docker MCP Server Setup Guide (Story RFA-qq0.6)

This guide explains how to configure and run the Docker MCP server to provide tools (Tavily, read, grep, bash) to the security gateway.

## Overview

The Docker MCP server is managed externally by Docker Desktop's MCP Toolkit and runs **outside** of docker-compose. The gateway connects to it via JSON-RPC at `http://localhost:8081/mcp`.

## Architecture

```
┌─────────────────────────────────────┐
│  PRECINCT Gateway                │
│  (docker-compose)                   │
│  http://localhost:9090              │
└────────────┬────────────────────────┘
             │ JSON-RPC
             ▼
┌─────────────────────────────────────┐
│  Docker MCP Gateway                 │
│  (Docker Desktop managed)           │
│  http://localhost:8081/mcp          │
└────────────┬────────────────────────┘
             │
    ┌────────┴────────┬───────┬───────┐
    ▼                 ▼       ▼       ▼
┌────────┐      ┌────────┐ ┌──────┐ ┌──────┐
│Tavily  │      │  Read  │ │ Grep │ │ Bash │
│  MCP   │      │  MCP   │ │ MCP  │ │ MCP  │
└────────┘      └────────┘ └──────┘ └──────┘
```

## Prerequisites

1. **Docker Desktop 4.30+** with MCP Toolkit enabled
2. **Tavily API Key** - Get from https://tavily.com
3. **Project Workspace** - Set `$POC_DIR` to the absolute path of the project directory (e.g., `export POC_DIR=$(pwd)`)

## Step 1: Configure Docker MCP Server

Create the configuration directory:

```bash
mkdir -p ~/.docker/mcp
```

### 1.1 Create `docker-mcp.yaml`

```bash
cat > ~/.docker/mcp/docker-mcp.yaml << 'EOF'
# Tavily - Web search API
tavily:
  command: docker
  args:
    - run
    - -i
    - --rm
    - -e
    - TAVILY_API_KEY
    - mcp/tavily
  env:
    TAVILY_API_KEY: ${TAVILY_API_KEY}

# Filesystem - Read, grep, list operations
filesystem:
  command: docker
  args:
    - run
    - -i
    - --rm
    - -v
    - $POC_DIR:/workspace
    - mcp/filesystem
    - /workspace
  env: {}
EOF
```

### 1.2 Create `registry.yaml`

```bash
cat > ~/.docker/mcp/registry.yaml << 'EOF'
enabled_servers:
  - tavily
  - filesystem
EOF
```

### 1.3 Set Tavily API Key

```bash
# Via Docker CLI (preferred)
docker mcp config write tavily TAVILY_API_KEY "your-api-key-here"

# OR via environment variable
export TAVILY_API_KEY="your-api-key-here"
```

## Step 2: Start Docker MCP Gateway

Start the gateway in streaming mode (HTTP/JSON-RPC):

```bash
docker mcp gateway run --port 8081 --transport streaming
```

This starts the gateway at `http://localhost:8081/mcp`.

**Verify it's running:**

```bash
curl http://localhost:8081/health
# Expected: HTTP 200 OK
```

## Step 3: Start Gateway Stack

Start the docker-compose stack:

```bash
cd $POC_DIR
docker-compose up -d
```

**Verify gateway is running:**

```bash
curl http://localhost:9090/health
# Expected: HTTP 200 OK
```

## Step 4: Test Tool Integration

### Test Tavily Search

```bash
curl -X POST http://localhost:9090 \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/gateways/mcp-security-gateway/dev" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "tavily_search",
      "arguments": {
        "query": "Docker MCP integration",
        "max_results": 2
      }
    },
    "id": "test-001"
  }'
```

### Test Read Tool (Within Project Workspace)

```bash
curl -X POST http://localhost:9090 \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/agents/mcp-client/dspy-researcher/dev" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "read",
      "arguments": {
        "file_path": "$POC_DIR/README.md"
      }
    },
    "id": "test-002"
  }'
```

### Test Grep Tool

```bash
curl -X POST http://localhost:9090 \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/agents/mcp-client/dspy-researcher/dev" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "grep",
      "arguments": {
        "pattern": "TODO",
        "path": "$POC_DIR"
      }
    },
    "id": "test-003"
  }'
```

### Test Bash Tool (Requires Step-Up)

```bash
curl -X POST http://localhost:9090 \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/gateways/mcp-security-gateway/dev" \
  -H "X-Step-Up-Token: valid-step-up-token-12345" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "bash",
      "arguments": {
        "command": "ls $POC_DIR"
      }
    },
    "id": "test-004"
  }'
```

## Security Boundaries

### Workspace Scope

The following tools are **restricted to the project workspace only**:

- `read` - Can only read files in `$POC_DIR/**`
- `grep` - Can only search in `$POC_DIR/**`
- `bash` - Commands restricted by policy (enforcement varies)

**Attempts to access files outside the workspace will be denied with HTTP 403.**

### Step-Up Authentication

The `bash` tool requires step-up authentication via `X-Step-Up-Token` header. Without this token, bash commands are denied regardless of other permissions.

### Tool Hash Verification

All tools are verified against SHA-256 hashes of their description + input schema:

| Tool | Hash |
|------|------|
| tavily_search | `76c6b3d8a7ddbc387ca87aa784e99354feeda1ff438768cd99232a6772cceac0` |
| read | `c4fbe869591f047985cd812915ed87d2c9c77de445089dcbc507416a86491453` |
| grep | `8bf71be3abae46b7ac610d92913c20e5f8d46bdbde9144c1c7e9798d92518cec` |
| bash | `ada241bb834f0737fd259606208f5d8ba2aeb2adbefa5ddc9df8f59b7c152c9f` |

Requests with mismatched hashes are rejected with HTTP 403.

## Running Integration Tests

```bash
cd $POC_DIR

# Ensure both gateways are running:
# 1. Docker MCP Gateway at http://localhost:8081/mcp
# 2. PRECINCT Gateway at http://localhost:9090

# Run Docker MCP integration tests
go test -tags=integration ./tests/integration -v -run TestDockerMCP
```

**Test Coverage:**
- Tavily tool callable through gateway
- Read/grep tools restricted to project workspace
- Bash tool requires step-up authentication
- Tool hash verification for all tools

## Troubleshooting

### Gateway Not Responding

```bash
# Check Docker MCP Gateway status
docker ps | grep mcp

# Restart Docker MCP Gateway
docker mcp gateway run --port 8081 --transport streaming
```

### Tavily Returns 401

```bash
# Verify API key is set
docker mcp config read tavily

# Re-set API key
docker mcp config write tavily TAVILY_API_KEY "your-key-here"
```

### Filesystem Can't Read Files

```bash
# Verify volume mount in docker-mcp.yaml
cat ~/.docker/mcp/docker-mcp.yaml | grep -A2 filesystem

# Ensure path matches:
# -v $POC_DIR:/workspace
```

### Tool Not Found

```bash
# Check enabled servers
cat ~/.docker/mcp/registry.yaml

# Enable server if missing
docker mcp server enable tavily
docker mcp server enable filesystem
```

## References

- [Docker MCP Integration Plan](./docker-mcp-integration.md) - Full integration research
- [Tool Registry Config](../config/tool-registry.yaml) - Tool definitions with hashes
- [OPA Policy](../config/opa/mcp_policy.rego) - Authorization rules

# Docker MCP Server Integration Plan

## Executive Summary

This document provides a comprehensive integration plan for using Docker's MCP (Model Context Protocol) server as a tool proxy for the POC gateway. It covers configuration, tool registration (Tavily, filesystem read/grep/bash), and the JSON-RPC communication protocol.

**Last Updated:** 2026-02-05
**Status:** Research Complete - Ready for Implementation

---

## 1. Docker MCP Architecture Overview

### 1.1 Core Components

Docker's MCP infrastructure consists of three main components:

1. **MCP Toolkit**: Management interface integrated into Docker Desktop for setting up, managing, and running containerized MCP servers
2. **MCP Gateway**: Core process that acts as a centralized proxy, unifying which MCP servers are exposed to which clients
3. **MCP Catalog**: Trusted registry on Docker Hub for discovering and sharing MCP-compatible tools

### 1.2 How Docker MCP Server Works

- **Managed by Docker**: MCP servers run as Docker containers managed by Docker Desktop
- **No Standalone Images Required**: Docker Desktop's MCP Toolkit handles container lifecycle
- **Centralized Configuration**: All configuration stored in `~/.docker/mcp/`
- **Automatic Discovery**: Gateway discovers servers via configuration files

### 1.3 Reference Architecture

```
┌─────────────────┐
│   AI Client     │
│  (Claude, etc)  │
└────────┬────────┘
         │ JSON-RPC 2.0
         ▼
┌─────────────────┐
│  MCP Gateway    │  (Docker-managed proxy)
│  ~/.docker/mcp/ │
└────────┬────────┘
         │
    ┌────┴────┬────────┬──────────┐
    ▼         ▼        ▼          ▼
┌────────┐ ┌──────┐ ┌──────┐ ┌────────┐
│ Tavily │ │ Read │ │ Grep │ │  Bash  │
│  MCP   │ │ MCP  │ │ MCP  │ │  MCP   │
└────────┘ └──────┘ └──────┘ └────────┘
```

---

## 2. Configuration & Discovery

### 2.1 Configuration File Locations

Docker MCP Gateway uses four primary configuration files in `~/.docker/mcp/`:

| File | Purpose | Format |
|------|---------|--------|
| `docker-mcp.yaml` | Server definitions (command, args, env) | YAML |
| `registry.yaml` | List of enabled server names | YAML |
| `config.yaml` | Per-server configuration key-value pairs | YAML |
| `tools.yaml` | Per-server tool filtering rules | YAML |

### 2.2 Server Discovery Mechanism

1. **Docker Desktop Integration**: MCP Toolkit scans `~/.docker/mcp/` on startup
2. **Registry Loading**: `registry.yaml` contains list of enabled servers
3. **Server Instantiation**: Gateway reads `docker-mcp.yaml` to start containers
4. **Configuration Injection**: `config.yaml` provides runtime parameters
5. **Tool Filtering**: `tools.yaml` restricts which tools are exposed

### 2.3 Environment Variables

Key environment variables for MCP servers:

- **API Keys**: `TAVILY_API_KEY`, service-specific keys
- **Server Config**: `DEFAULT_PARAMETERS`, `MAX_RESULTS`, etc.
- **OAuth Tokens**: Managed automatically by Docker Desktop for remote servers

### 2.4 Gateway Endpoints

The MCP Gateway can be run with:

- **stdio transport** (default): `docker mcp gateway run`
- **streaming transport**: `docker mcp gateway run --port 8080 --transport streaming`

**Typical endpoint for streaming:** `http://localhost:8080/mcp`

---

## 3. Tool Registration

### 3.1 Tavily Search Tool

**Official Docker Image:** `mcp/tavily` ([Docker Hub](https://hub.docker.com/mcp/server/tavily/overview))

#### Configuration

**docker-mcp.yaml entry:**
```yaml
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
```

**registry.yaml entry:**
```yaml
enabled_servers:
  - tavily
```

**config.yaml entry (optional):**
```yaml
tavily:
  DEFAULT_PARAMETERS:
    max_results: 10
    search_depth: "advanced"
```

#### Available Tools

1. **tavily-search**: Real-time web search
   - Input: `query` (string), `max_results` (int, optional)
   - Output: Array of search results with title, URL, snippet, score

2. **tavily-extract**: Intelligent data extraction from web pages
   - Input: `url` (string)
   - Output: Extracted structured data

3. **tavily-map**: Map website structure
4. **tavily-crawl**: Crawl website content

#### Running Directly

```bash
docker run -i --rm -e TAVILY_API_KEY mcp/tavily
```

### 3.2 Filesystem Tools (Read, Grep, Bash)

**Official Docker Image:** `mcp/filesystem` ([Docker Hub](https://hub.docker.com/mcp/server/filesystem/overview))

#### Configuration

**docker-mcp.yaml entry:**
```yaml
filesystem:
  command: docker
  args:
    - run
    - -i
    - --rm
    - -v
    - /local-directory:/local-directory
    - mcp/filesystem
    - /local-directory
  env: {}
```

**registry.yaml entry:**
```yaml
enabled_servers:
  - filesystem
```

**tools.yaml entry (optional - to restrict tools):**
```yaml
filesystem:
  allowed_tools:
    - read_file
    - read_multiple_files
    - search_files
    - list_directory
```

#### Available Tools

1. **read_file**: Read complete contents of a file
   - Input: `path` (string)
   - Output: File content as string
   - Handles various text encodings

2. **read_multiple_files**: Read multiple files in one call
   - Input: `paths` (array of strings)
   - Output: Array of file contents

3. **search_files**: Recursively search for files matching a pattern (grep-like)
   - Input: `path` (string), `pattern` (string), `case_sensitive` (bool, optional)
   - Output: Array of matching file paths
   - Case-insensitive matching by default
   - Returns full paths to all matching items

4. **list_directory**: List directory contents
   - Input: `path` (string)
   - Output: Array of file/directory names

5. **directory_tree**: Get directory structure as tree
   - Input: `path` (string)
   - Output: Hierarchical directory structure

6. **get_file_info**: Get file metadata
   - Input: `path` (string)
   - Output: File size, modified time, permissions, etc.

7. **write_file**: Write content to file (if enabled)
8. **edit_file**: Edit file content (if enabled)
9. **create_directory**: Create directory (if enabled)
10. **move_file**: Move/rename file (if enabled)

#### Volume Mounting for Filesystem Access

**Critical**: Filesystem MCP server requires volume mounts to access host files:

```bash
docker run -i --rm \
  -v /path/to/workspace:/workspace \
  mcp/filesystem /workspace
```

The final argument (`/workspace`) specifies the allowed directory inside the container.

#### Bash Integration via MCP CLI

For bash-like operations, use `mcp-cli` tool:

```bash
# Call read_file via stdin
echo '{"path": "./file.txt"}' | mcp-cli call filesystem read_file

# Search (grep-like)
mcp-cli call filesystem search_files '{"path": "/workspace", "pattern": "TODO"}'
```

### 3.3 Tools Summary Table

| Tool Category | Docker Image | Key Tools | Volume Mount Required |
|---------------|--------------|-----------|----------------------|
| Web Search | `mcp/tavily` | tavily-search, tavily-extract | No |
| Filesystem | `mcp/filesystem` | read_file, search_files, list_directory | Yes |
| Bash/CLI | Use `mcp-cli` or filesystem tools | Via mcp-cli wrapper | N/A |

---

## 4. JSON-RPC Protocol Specification

### 4.1 Protocol Overview

All messages between MCP clients and servers **MUST** follow JSON-RPC 2.0 specification.

**Key Requirements:**
- Requests MUST include a string or integer ID (NOT null)
- ID MUST be unique within session
- Responses MUST include same ID as request
- Either `result` or `error` MUST be set (not both)

### 4.2 Request Format

**Structure:**
```json
{
  "jsonrpc": "2.0",
  "id": "unique-request-id",
  "method": "method_name",
  "params": {
    "parameter1": "value1",
    "parameter2": "value2"
  }
}
```

**Example: Tavily Search Request**
```json
{
  "jsonrpc": "2.0",
  "id": "search-001",
  "method": "tools/call",
  "params": {
    "name": "tavily-search",
    "arguments": {
      "query": "Docker MCP integration",
      "max_results": 5
    }
  }
}
```

**Example: Filesystem Read Request**
```json
{
  "jsonrpc": "2.0",
  "id": "read-001",
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {
      "path": "/workspace/README.md"
    }
  }
}
```

### 4.3 Response Format

**Success Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "search-001",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Search result content here..."
      }
    ]
  }
}
```

**Error Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "search-001",
  "error": {
    "code": -32601,
    "message": "Method not found",
    "data": {
      "method": "unknown/method"
    }
  }
}
```

### 4.4 Tool Schema Format

Tools are discovered via `tools/list` method:

**Discovery Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "list-001",
  "method": "tools/list"
}
```

**Discovery Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "list-001",
  "result": {
    "tools": [
      {
        "name": "tavily-search",
        "description": "Search the web using Tavily API",
        "inputSchema": {
          "type": "object",
          "properties": {
            "query": {
              "type": "string",
              "description": "Search query"
            },
            "max_results": {
              "type": "integer",
              "description": "Maximum number of results",
              "default": 10
            }
          },
          "required": ["query"]
        }
      }
    ]
  }
}
```

### 4.5 Additional Message Types

**Progress Updates:**
```json
{
  "jsonrpc": "2.0",
  "method": "progress",
  "params": {
    "progressToken": "operation-123",
    "progress": 75,
    "total": 100,
    "message": "Processing files..."
  }
}
```

**Cancellation:**
```json
{
  "jsonrpc": "2.0",
  "method": "cancelled",
  "params": {
    "requestId": "long-running-request-id",
    "reason": "User requested cancellation"
  }
}
```

**Batching:**
MCP implementations MAY support sending JSON-RPC batches (array of requests), but MUST support receiving them.

---

## 5. Authentication & Security

### 5.1 API Key Management

**Docker Desktop Secrets Management:**
- API keys stored securely in Docker Desktop keychain
- Injected as environment variables at container runtime
- Never stored in plaintext configuration files

**Example: Tavily API Key**
```bash
# Set via Docker Desktop UI or CLI
docker mcp config write tavily TAVILY_API_KEY "tvly-xxxxxxxxxxxxx"
```

### 5.2 OAuth Integration

For remote MCP servers (GitHub, Notion, Linear):
- Docker Desktop provides built-in OAuth flows
- User authenticates via browser
- Tokens managed automatically by Gateway
- Refresh tokens handled transparently

### 5.3 Container Isolation

- Each MCP server runs in isolated Docker container
- Network isolation by default
- Volume mounts must be explicitly granted
- Resource limits enforced by Docker

---

## 6. Gateway Routing & Management

### 6.1 Server Lifecycle Management

**Commands:**
```bash
# List enabled servers
docker mcp server ls

# Enable a server
docker mcp server enable tavily

# Disable a server
docker mcp server disable tavily

# Inspect server details
docker mcp server inspect tavily

# Read configuration
docker mcp config read tavily

# Reset configuration
docker mcp config reset tavily
```

### 6.2 Tool Routing

**Gateway Routing Logic:**
1. Client sends request to Gateway
2. Gateway parses tool name from request
3. Gateway looks up which server provides that tool
4. Gateway forwards request to appropriate server container
5. Server processes and responds
6. Gateway forwards response back to client

**Tool Namespace Collision Handling:**
- Tools are prefixed with server name if collision detected
- Example: `filesystem/read_file` vs `alternative/read_file`

### 6.3 Connection Types

| Transport | Use Case | Endpoint |
|-----------|----------|----------|
| stdio | Single-process, embedded | stdin/stdout pipes |
| streaming | Multi-client, networked | HTTP/WebSocket on port |

---

## 7. Integration Plan

### 7.1 Phase 1: Gateway Setup (Story RFA-qq0.2)

**Objective:** Configure Docker MCP Gateway and validate connectivity

**Tasks:**
1. Verify Docker Desktop with MCP Toolkit installed
2. Configure `~/.docker/mcp/` directory structure
3. Start Gateway in streaming mode: `docker mcp gateway run --port 8080 --transport streaming`
4. Validate Gateway is reachable: `curl http://localhost:8080/mcp`

**Acceptance Criteria:**
- Gateway responds to health checks
- Configuration files created in `~/.docker/mcp/`
- Gateway logs show successful startup

### 7.2 Phase 2: Tavily Integration (Story RFA-qq0.3)

**Objective:** Register Tavily search tool and validate JSON-RPC communication

**Tasks:**
1. Add Tavily configuration to `docker-mcp.yaml`
2. Set `TAVILY_API_KEY` via Docker Desktop secrets
3. Enable Tavily server: `docker mcp server enable tavily`
4. Send test search request via JSON-RPC
5. Validate response format matches specification

**Test Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "test-001",
  "method": "tools/call",
  "params": {
    "name": "tavily-search",
    "arguments": {
      "query": "test query",
      "max_results": 1
    }
  }
}
```

**Acceptance Criteria:**
- Tavily container starts successfully
- Search returns valid results
- Response includes proper JSON-RPC structure

### 7.3 Phase 3: Filesystem Tools Integration (Story RFA-qq0.4)

**Objective:** Register filesystem read/grep tools and validate file access

**Tasks:**
1. Add filesystem configuration to `docker-mcp.yaml` with volume mounts
2. Mount POC workspace: `-v /Users/ramirosalas/workspace/agentic_reference_architecture/POC:/workspace`
3. Enable filesystem server: `docker mcp server enable filesystem`
4. Test `read_file` tool with known file
5. Test `search_files` tool (grep functionality)
6. Validate permissions and security boundaries

**Test Requests:**
```json
// Read test
{
  "jsonrpc": "2.0",
  "id": "read-001",
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {
      "path": "/workspace/README.md"
    }
  }
}

// Search test (grep)
{
  "jsonrpc": "2.0",
  "id": "search-001",
  "method": "tools/call",
  "params": {
    "name": "search_files",
    "arguments": {
      "path": "/workspace",
      "pattern": "TODO"
    }
  }
}
```

**Acceptance Criteria:**
- Filesystem container starts with volume mounts
- Can read files from mounted workspace
- Search returns matching file paths
- Cannot access files outside mounted volumes

### 7.4 Phase 4: POC Gateway Integration (Story RFA-qq0.5)

**Objective:** Connect POC gateway to Docker MCP Gateway via JSON-RPC

**Tasks:**
1. Implement JSON-RPC client in POC gateway
2. Configure gateway to connect to `http://localhost:8080/mcp`
3. Implement tool discovery via `tools/list`
4. Implement tool calling via `tools/call`
5. Add error handling for MCP error codes
6. Add integration tests for all tools

**Architecture:**
```
POC Gateway (Python/Go)
    ↓ HTTP/JSON-RPC
Docker MCP Gateway (localhost:8080)
    ↓
Docker Containers (Tavily, Filesystem)
```

**Acceptance Criteria:**
- POC gateway successfully discovers all registered tools
- Can invoke Tavily search and receive results
- Can read files and search file contents
- Error responses properly handled
- Integration tests pass

### 7.5 Phase 5: Production Readiness (Story RFA-qq0.6)

**Objective:** Harden integration for production use

**Tasks:**
1. Implement connection pooling for MCP Gateway
2. Add retry logic with exponential backoff
3. Implement request timeout handling
4. Add logging and observability
5. Configure resource limits for Docker containers
6. Document operational procedures

**Acceptance Criteria:**
- Gateway handles connection failures gracefully
- Timeouts configured appropriately
- All operations logged
- Performance meets requirements (< 500ms for most operations)

---

## 8. Operational Considerations

### 8.1 Docker Desktop Requirements

- **Minimum Version:** Docker Desktop 4.30+ (for MCP Toolkit support)
- **Platforms:** macOS, Windows, Linux
- **Resources:** Recommend 4GB RAM, 2 CPU cores for MCP Gateway

### 8.2 Configuration Backup

Configuration stored in `~/.docker/mcp/` should be:
- Version controlled (excluding secrets)
- Backed up regularly
- Documented for disaster recovery

### 8.3 Monitoring

**Key Metrics to Monitor:**
- Gateway uptime and restarts
- Tool invocation success rate
- Request latency (p50, p95, p99)
- Container resource usage
- API rate limit consumption (Tavily)

### 8.4 Troubleshooting

**Common Issues:**

| Issue | Diagnosis | Resolution |
|-------|-----------|------------|
| Gateway not responding | `docker ps` shows no mcp-gateway | Restart Gateway: `docker mcp gateway run` |
| Tavily returns 401 | API key not set or invalid | Check: `docker mcp config read tavily` |
| Filesystem can't read files | Volume mount missing | Verify mount in `docker-mcp.yaml` |
| Tool not found | Server not enabled | Run: `docker mcp server enable <name>` |

**Debug Commands:**
```bash
# Check Gateway logs
docker logs $(docker ps -q --filter "ancestor=mcp-gateway")

# Test tool manually
docker run -i --rm -e TAVILY_API_KEY mcp/tavily

# Verify configuration
cat ~/.docker/mcp/docker-mcp.yaml
cat ~/.docker/mcp/registry.yaml
```

---

## 9. References

### Official Documentation

- [Docker MCP Catalog and Toolkit](https://docs.docker.com/ai/mcp-catalog-and-toolkit/)
- [MCP Gateway Documentation](https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/)
- [MCP Toolkit Guide](https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/)
- [Get Started with Docker MCP](https://docs.docker.com/ai/mcp-catalog-and-toolkit/get-started/)

### Docker Hub Images

- [Tavily MCP Server](https://hub.docker.com/mcp/server/tavily/overview)
- [Filesystem MCP Server](https://hub.docker.com/mcp/server/filesystem/overview)

### GitHub Repositories

- [docker/mcp-gateway](https://github.com/docker/mcp-gateway) - Official Docker MCP Gateway
- [docker/mcp-registry](https://github.com/docker/mcp-registry) - Official Docker MCP Registry
- [tavily-ai/tavily-mcp](https://github.com/tavily-ai/tavily-mcp) - Tavily MCP Server

### Protocol Specifications

- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification/2025-03-26/basic)
- [MCP JSON-RPC Reference Guide](https://portkey.ai/blog/mcp-message-types-complete-json-rpc-reference-guide/)
- [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification)

### Additional Resources

- [Docker Blog: MCP Toolkit and Gateway Explained](https://www.docker.com/blog/mcp-toolkit-gateway-explained/)
- [Docker Blog: MCP Servers That Just Work](https://www.docker.com/blog/mcp-toolkit-mcp-servers-that-just-work/)
- [Docker Blog: MCP Servers with Docker](https://www.docker.com/blog/mcp-servers-docker-toolkit-cagent-gateway/)

---

## 10. Conclusion

Docker's MCP Gateway provides a robust, production-ready solution for tool proxy integration. Key advantages:

1. **Managed Infrastructure**: Docker Desktop handles container lifecycle
2. **Secure by Default**: API keys managed in keychain, container isolation enforced
3. **Standardized Protocol**: JSON-RPC 2.0 provides clear contract
4. **Rich Ecosystem**: Growing catalog of pre-built MCP servers on Docker Hub
5. **Developer Friendly**: Simple configuration, good documentation, active community

**Next Steps:**
- Proceed with Phase 1 (Story RFA-qq0.2): Gateway setup and validation
- Allocate Tavily API key for testing
- Determine workspace volume mount paths for filesystem tools

**Estimated Timeline:**
- Phase 1: 1 day
- Phase 2: 1 day
- Phase 3: 1 day
- Phase 4: 2-3 days
- Phase 5: 1-2 days

**Total:** ~6-8 days for complete integration

---

**Document Status:** ✅ Complete - Ready for Implementation

**Author:** Developer Agent (Pivotal Developer)
**Story:** RFA-qq0.1
**Epic:** RFA-qq0 - POC Docker Compose Setup

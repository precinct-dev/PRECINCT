# PydanticAI Research Agent (RFA-qq0.8)

A PydanticAI-based Q&A agent that demonstrates security gateway integration with
structured output. The agent answers questions by searching with Tavily and reading
local files via the MCP security gateway, then produces a structured Pydantic model
answer with citations and confidence scores.

## Architecture

All tool calls are routed through the MCP Security Gateway -- no direct tool access.

```
Agent -> Gateway (9090) -> [13-step middleware chain] -> Docker MCP Server (8081)
         |                                                  |
         +-- X-SPIFFE-ID header                            +-- Tavily API
         +-- Audit logging                                 +-- File system
         +-- OPA policy check
         +-- DLP scanning
         +-- Tool registry hash verification
```

**SPIFFE ID**: `spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev`

## Pydantic Output Models

| Model | Purpose |
|-------|---------|
| `Citation` | Source reference with title, URL, and excerpt |
| `GroundedAnswer` | Structured answer with citations, confidence score, key points |

The `GroundedAnswer` model includes:
- `question`: The original question asked
- `answer`: Comprehensive answer grounded in sources
- `citations`: List of `Citation` objects supporting the answer
- `confidence_score`: Float 0.0-1.0 indicating source support quality
- `key_points`: Extracted key points
- `sources_consulted`: Count of sources successfully queried
- `limitations`: Any caveats or gaps

## PydanticAI Tools

| Tool | Purpose |
|------|---------|
| `tavily_search` | Web search via gateway MCP endpoint |
| `file_read` | File read via gateway MCP endpoint |
| `list_reference_files` | List available reference docs |

## Prerequisites

1. Docker compose stack running:
   ```bash
   cd POC && make up
   ```

2. Docker MCP Gateway running:
   ```bash
   docker mcp gateway run --port 8081 --transport streaming
   ```

3. Python virtual environment:
   ```bash
   cd agents/pydantic_researcher
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

4. LLM API key. Set one of:
   ```bash
   export GROQ_API_KEY=<your-key>   # Default: groq:llama-3.3-70b-versatile
   # Or override the model:
   export LLM_MODEL=openai:gpt-4    # Uses OPENAI_API_KEY
   ```

## Running the Agent

```bash
# Default question
python agent.py

# Custom question
python agent.py "What are the key differences between SPIFFE and traditional OAuth for agent identity?"
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_URL` | `http://localhost:9090` | MCP Security Gateway URL |
| `SPIFFE_ID` | `spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev` | Agent SPIFFE identity |
| `OTEL_ENDPOINT` | `http://localhost:4317` | OpenTelemetry collector gRPC endpoint |
| `LLM_MODEL` | `groq:llama-3.3-70b-versatile` | PydanticAI model identifier |
| `SESSION_ID` | auto-generated UUID | Session ID for trace correlation |
| `POC_DIR` | `/Users/ramirosalas/workspace/agentic_reference_architecture/POC` | POC directory path |

## Running Tests

```bash
# Unit tests (no compose stack needed)
pytest test_agent.py -v -k "not integration"

# Integration tests (requires compose stack)
pytest test_agent.py -v -m integration

# All tests
pytest test_agent.py -v
```

## Gateway Denial Handling

The agent handles gateway denials gracefully:

- **HTTP 403** (policy denial): Logs reason, does NOT retry, marks tool as denied,
  continues with available information
- **HTTP 503** (guard unavailable): Logs reason, retries with exponential backoff
  (up to 3 retries), then degrades gracefully
- **HTTP 401** (auth failure): Logs error, does not retry

The agent never crashes, hangs, or retries indefinitely on denials.

## Observability

Traces are exported via OpenTelemetry to the collector, which forwards to Phoenix.
View traces at: http://localhost:6006

Instrumentation:
- `openinference-instrumentation-pydantic-ai`: Auto-instruments PydanticAI LLM calls
- Manual spans for gateway tool calls (`gateway.tool_call.<method>`)
- Resource attributes: `service.name`, `spiffe.id`, `session.id`

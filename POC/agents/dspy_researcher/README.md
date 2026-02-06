# DSPy Research Agent (RFA-qq0.7)

A DSPy-based research agent that demonstrates security gateway integration. The agent
performs research by searching with Tavily and reading local files via the MCP security
gateway, then synthesizes findings into a structured report.

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

**SPIFFE ID**: `spiffe://poc.local/agents/mcp-client/dspy-researcher/dev`

## DSPy Signatures and Modules

| Signature | Purpose |
|-----------|---------|
| `ResearchPlan` | Generate search queries and file paths from a topic |
| `SearchSynthesis` | Synthesize Tavily web search results |
| `FileSynthesis` | Extract relevant context from local files |
| `ReportSynthesis` | Produce final structured research report |

| Module | Purpose |
|--------|---------|
| `GatewayWebSearch` | Tavily search via gateway MCP endpoint |
| `GatewayFileRead` | File read via gateway MCP endpoint |
| `ResearchAgent` | Orchestrates the full research workflow |

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
   cd agents/dspy_researcher
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

4. LLM API key (for DSPy). Set one of:
   ```bash
   export GROQ_API_KEY=<your-key>   # Default: groq/llama-3.3-70b-versatile
   # Or override the model:
   export LLM_MODEL=openai/gpt-4    # Uses OPENAI_API_KEY
   ```

## Running the Agent

```bash
# Default topic
python agent.py

# Custom topic
python agent.py "zero trust architecture for AI agents"
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_URL` | `http://localhost:9090` | MCP Security Gateway URL |
| `SPIFFE_ID` | `spiffe://poc.local/agents/mcp-client/dspy-researcher/dev` | Agent SPIFFE identity |
| `OTEL_ENDPOINT` | `http://localhost:4317` | OpenTelemetry collector gRPC endpoint |
| `LLM_MODEL` | `groq/llama-3.3-70b-versatile` | DSPy LLM model identifier |
| `SESSION_ID` | auto-generated UUID | Session ID for trace correlation |

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
- `openinference-instrumentation-dspy`: Auto-instruments DSPy LLM calls
- Manual spans for gateway tool calls (`gateway.tool_call.<method>`)
- Resource attributes: `service.name`, `spiffe.id`, `session.id`

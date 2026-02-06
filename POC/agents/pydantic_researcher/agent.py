"""
PydanticAI Research Agent - RFA-qq0.8
A PydanticAI-based Q&A agent that demonstrates security gateway integration
with structured output using Pydantic models.

Performs Q&A by searching with Tavily and reading local files via the
MCP security gateway, then produces a structured answer with citations
and confidence scores.

All tool calls are routed through the gateway MCP endpoint.
Identity: spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev
"""

import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Optional

import httpx
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.instrumented import InstrumentationSettings

# OpenInference span processor for PydanticAI -> Phoenix
from openinference.instrumentation.pydantic_ai import OpenInferenceSpanProcessor

logger = logging.getLogger("pydantic_researcher")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:9090")
SPIFFE_ID = os.environ.get(
    "SPIFFE_ID",
    "spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev",
)
OTEL_ENDPOINT = os.environ.get("OTEL_ENDPOINT", "http://localhost:4317")
LLM_MODEL = os.environ.get("LLM_MODEL", "groq:llama-3.3-70b-versatile")
SESSION_ID = os.environ.get("SESSION_ID", str(uuid.uuid4()))

# Retry configuration for 503 (guard unavailable) responses
MAX_503_RETRIES = 3
RETRY_BACKOFF_BASE = 1.0  # seconds

# POC directory for file reads
POC_DIR = os.environ.get(
    "POC_DIR",
    "/Users/ramirosalas/workspace/agentic_reference_architecture/POC",
)


# ---------------------------------------------------------------------------
# Observability setup
# ---------------------------------------------------------------------------

def setup_observability() -> trace.Tracer:
    """Configure OpenTelemetry tracing with OTLP export to collector/Phoenix."""
    resource = Resource.create(
        {
            "service.name": "pydantic-researcher",
            "service.version": "0.1.0",
            "spiffe.id": SPIFFE_ID,
            "session.id": SESSION_ID,
        }
    )
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=OTEL_ENDPOINT, insecure=True)
    # OpenInference processor enhances PydanticAI spans with AI-specific attributes
    provider.add_span_processor(OpenInferenceSpanProcessor())
    # Batch exporter sends spans to the OTLP collector
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    return trace.get_tracer("pydantic_researcher")


# ---------------------------------------------------------------------------
# Gateway MCP client (same pattern as DSPy agent - RFA-qq0.7)
# ---------------------------------------------------------------------------

@dataclass
class GatewayDenial:
    """Represents a gateway denial (HTTP 403 or 503)."""
    status_code: int
    reason: str
    retryable: bool


@dataclass
class ToolCallResult:
    """Result of a tool call through the gateway."""
    success: bool
    data: Optional[dict] = None
    error: Optional[str] = None
    denial: Optional[GatewayDenial] = None
    raw_status: int = 0


class GatewayClient:
    """HTTP client for MCP JSON-RPC calls through the security gateway.

    All tool calls go through the gateway at GATEWAY_URL.
    Authenticates with X-SPIFFE-ID header (dev mode).
    Handles HTTP 403 (policy denial) and 503 (guard unavailable) gracefully.
    """

    def __init__(
        self,
        gateway_url: str = GATEWAY_URL,
        spiffe_id: str = SPIFFE_ID,
        tracer: Optional[trace.Tracer] = None,
    ):
        self.gateway_url = gateway_url
        self.spiffe_id = spiffe_id
        self.tracer = tracer
        self._request_id = 0
        self._client = httpx.Client(timeout=30.0)

    def close(self):
        self._client.close()

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def call_tool(self, method: str, params: dict) -> ToolCallResult:
        """Call a tool through the gateway MCP endpoint.

        Args:
            method: MCP tool name (e.g. 'tavily_search', 'read')
            params: Tool parameters

        Returns:
            ToolCallResult with success/failure info and data or denial details.
        """
        span_ctx = None
        if self.tracer:
            span_ctx = self.tracer.start_span(
                f"gateway.tool_call.{method}",
                attributes={
                    "mcp.method": method,
                    "mcp.params": json.dumps(params),
                    "spiffe.id": self.spiffe_id,
                    "session.id": SESSION_ID,
                },
            )

        try:
            result = self._call_with_retry(method, params)
            if span_ctx:
                span_ctx.set_attribute("mcp.result.success", result.success)
                span_ctx.set_attribute("mcp.result.status", result.raw_status)
                if result.denial:
                    span_ctx.set_attribute(
                        "mcp.denial.reason", result.denial.reason
                    )
                    span_ctx.set_attribute(
                        "mcp.denial.status", result.denial.status_code
                    )
            return result
        except Exception as exc:
            if span_ctx:
                span_ctx.set_attribute("mcp.result.success", False)
                span_ctx.set_attribute("mcp.error", str(exc))
            logger.error("Tool call %s failed with exception: %s", method, exc)
            return ToolCallResult(
                success=False,
                error=f"Exception calling {method}: {exc}",
                raw_status=0,
            )
        finally:
            if span_ctx:
                span_ctx.end()

    def _call_with_retry(self, method: str, params: dict) -> ToolCallResult:
        """Execute tool call with retry logic for 503 responses."""
        last_result = None
        for attempt in range(MAX_503_RETRIES + 1):
            result = self._do_call(method, params)
            last_result = result

            # If not a retryable denial, return immediately
            if not result.denial or not result.denial.retryable:
                return result

            # Retryable (503) -- backoff and retry
            if attempt < MAX_503_RETRIES:
                backoff = RETRY_BACKOFF_BASE * (2 ** attempt)
                logger.warning(
                    "Tool %s returned 503 (attempt %d/%d). "
                    "Retrying in %.1fs. Reason: %s",
                    method,
                    attempt + 1,
                    MAX_503_RETRIES + 1,
                    backoff,
                    result.denial.reason,
                )
                time.sleep(backoff)
            else:
                logger.error(
                    "Tool %s returned 503 after %d attempts. Giving up. "
                    "Reason: %s",
                    method,
                    MAX_503_RETRIES + 1,
                    result.denial.reason,
                )

        return last_result  # type: ignore[return-value]

    def _do_call(self, method: str, params: dict) -> ToolCallResult:
        """Execute a single MCP JSON-RPC call to the gateway."""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._next_id(),
        }
        headers = {
            "Content-Type": "application/json",
            "X-SPIFFE-ID": self.spiffe_id,
            "X-Session-ID": SESSION_ID,
        }

        try:
            resp = self._client.post(
                self.gateway_url, json=payload, headers=headers
            )
        except httpx.ConnectError as exc:
            return ToolCallResult(
                success=False,
                error=f"Connection to gateway failed: {exc}",
                raw_status=0,
            )

        # Handle HTTP-level denials BEFORE parsing JSON-RPC
        if resp.status_code == 403:
            reason = self._extract_denial_reason(resp)
            logger.warning(
                "DENIAL [403] Tool=%s Reason=%s (permanent, will not retry)",
                method,
                reason,
            )
            return ToolCallResult(
                success=False,
                error=f"Policy denial: {reason}",
                denial=GatewayDenial(
                    status_code=403, reason=reason, retryable=False
                ),
                raw_status=403,
            )

        if resp.status_code == 503:
            reason = self._extract_denial_reason(resp)
            logger.warning(
                "DENIAL [503] Tool=%s Reason=%s (retryable)",
                method,
                reason,
            )
            return ToolCallResult(
                success=False,
                error=f"Service unavailable: {reason}",
                denial=GatewayDenial(
                    status_code=503, reason=reason, retryable=True
                ),
                raw_status=503,
            )

        if resp.status_code == 401:
            reason = resp.text.strip()
            logger.error("AUTH FAILURE [401] Tool=%s Reason=%s", method, reason)
            return ToolCallResult(
                success=False,
                error=f"Authentication failure: {reason}",
                raw_status=401,
            )

        # Parse JSON-RPC response
        try:
            body = resp.json()
        except Exception:
            return ToolCallResult(
                success=False,
                error=f"Invalid JSON response (HTTP {resp.status_code}): {resp.text[:200]}",
                raw_status=resp.status_code,
            )

        if "error" in body:
            err = body["error"]
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            return ToolCallResult(
                success=False,
                error=f"JSON-RPC error: {msg}",
                raw_status=resp.status_code,
            )

        return ToolCallResult(
            success=True,
            data=body.get("result", body),
            raw_status=resp.status_code,
        )

    @staticmethod
    def _extract_denial_reason(resp: httpx.Response) -> str:
        """Extract denial reason from gateway error response."""
        try:
            body = resp.json()
            if isinstance(body, dict):
                return body.get("reason", body.get("error", resp.text[:200]))
            return str(body)
        except Exception:
            return resp.text[:200] if resp.text else f"HTTP {resp.status_code}"


# ---------------------------------------------------------------------------
# Pydantic output models (structured agent output)
# ---------------------------------------------------------------------------

class Citation(BaseModel):
    """A citation for a piece of information in the answer."""
    source: str = Field(description="URL or file path of the source")
    title: str = Field(description="Title or name of the source")
    relevant_excerpt: str = Field(
        description="Brief excerpt from the source supporting the claim"
    )


class GroundedAnswer(BaseModel):
    """A structured, grounded answer to a question with citations and confidence."""
    question: str = Field(description="The original question asked")
    answer: str = Field(
        description="Comprehensive answer to the question, grounded in sources"
    )
    citations: list[Citation] = Field(
        description="List of citations supporting the answer"
    )
    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Confidence score from 0.0 to 1.0 indicating how well-supported "
            "the answer is by the sources"
        ),
    )
    key_points: list[str] = Field(
        description="Key points extracted from the answer"
    )
    sources_consulted: int = Field(
        description="Total number of sources successfully consulted"
    )
    limitations: str = Field(
        description=(
            "Any limitations, caveats, or gaps in the answer "
            "(e.g., denied sources, missing data)"
        ),
    )


# ---------------------------------------------------------------------------
# PydanticAI agent definition
# ---------------------------------------------------------------------------

# The agent uses dependency injection to pass the GatewayClient
# and question context to tools.

@dataclass
class AgentDeps:
    """Dependencies injected into the PydanticAI agent at runtime."""
    gateway: GatewayClient
    question: str
    poc_dir: str = POC_DIR


# Create the PydanticAI agent with structured output and instrumentation.
# defer_model_check=True allows importing the module without an API key
# (the key is only needed at runtime when actually calling the LLM).
qa_agent = Agent(
    LLM_MODEL,
    deps_type=AgentDeps,
    output_type=GroundedAnswer,
    instrument=InstrumentationSettings(),
    defer_model_check=True,
    system_prompt=(
        "You are a research assistant specializing in AI security topics. "
        "When given a question, use the available tools to search for "
        "information and read reference files. Then synthesize your findings "
        "into a well-structured, grounded answer with citations.\n\n"
        "Guidelines:\n"
        "- Use tavily_search to find relevant web information\n"
        "- Use file_read to read local reference documents from the docs/ directory\n"
        "- Cite your sources with specific excerpts\n"
        "- Assign a confidence score based on source quality and coverage\n"
        "- Note any limitations (e.g., if a source was denied or unavailable)\n"
        "- Provide actionable key points\n"
    ),
)


@qa_agent.tool
def tavily_search(
    ctx: RunContext[AgentDeps], query: str, max_results: int = 5
) -> str:
    """Search the web using Tavily for relevant information.

    Args:
        query: Search query string
        max_results: Maximum number of results to return (default 5)

    Returns:
        JSON string of search results, or error message if denied/failed.
    """
    result = ctx.deps.gateway.call_tool(
        "tavily_search",
        {"query": query, "max_results": max_results},
    )

    if result.success:
        return json.dumps(result.data, indent=2)
    else:
        denial_info = ""
        if result.denial:
            denial_info = (
                f" [Denial: {result.denial.status_code} - "
                f"{result.denial.reason}]"
            )
        return f"[SEARCH FAILED: {result.error}{denial_info}]"


@qa_agent.tool
def file_read(ctx: RunContext[AgentDeps], file_path: str) -> str:
    """Read a local reference file through the security gateway.

    Args:
        file_path: Path to the file to read (should be under POC/docs/)

    Returns:
        File contents as a string, or error message if denied/failed.
    """
    result = ctx.deps.gateway.call_tool(
        "read",
        {"file_path": file_path},
    )

    if result.success:
        content = result.data
        if isinstance(content, dict):
            content = content.get("content", content.get("text", json.dumps(content)))
        elif isinstance(content, list):
            content = "\n".join(str(item) for item in content)
        # Truncate very long files to avoid context overflow
        text = str(content)
        if len(text) > 5000:
            text = text[:5000] + "\n[... truncated ...]"
        return text
    else:
        denial_info = ""
        if result.denial:
            denial_info = (
                f" [Denial: {result.denial.status_code} - "
                f"{result.denial.reason}]"
            )
        return f"[FILE READ FAILED: {result.error}{denial_info}]"


@qa_agent.tool
def list_reference_files(ctx: RunContext[AgentDeps]) -> str:
    """List available reference files in the POC/docs/ directory.

    Returns:
        JSON list of available file paths.
    """
    docs_dir = f"{ctx.deps.poc_dir}/docs"
    result = ctx.deps.gateway.call_tool(
        "read",
        {"file_path": docs_dir},
    )

    if result.success:
        return json.dumps(result.data, indent=2)
    else:
        # Fallback: return known reference files
        known_files = [
            f"{docs_dir}/docker-mcp-integration.md",
            f"{docs_dir}/docker-mcp-setup.md",
            f"{docs_dir}/spiffe-setup.md",
            f"{docs_dir}/spike-token-substitution.md",
            f"{docs_dir}/supply-chain-images.md",
        ]
        return json.dumps(known_files, indent=2)


# ---------------------------------------------------------------------------
# Agent runner
# ---------------------------------------------------------------------------

def run_qa(
    question: str,
    gateway_url: str = GATEWAY_URL,
    spiffe_id: str = SPIFFE_ID,
    enable_tracing: bool = True,
) -> GroundedAnswer:
    """Run the PydanticAI Q&A agent on a given question.

    Args:
        question: Question to answer
        gateway_url: MCP security gateway URL
        spiffe_id: SPIFFE identity for authentication
        enable_tracing: Whether to enable OpenTelemetry tracing

    Returns:
        GroundedAnswer Pydantic model with structured answer, citations,
        and confidence score.
    """
    # Setup observability
    tracer = None
    if enable_tracing:
        try:
            tracer = setup_observability()
            logger.info("OpenTelemetry tracing enabled (endpoint: %s)", OTEL_ENDPOINT)
        except Exception as exc:
            logger.warning("Failed to setup tracing (continuing without): %s", exc)

    # Create gateway client
    gateway_client = GatewayClient(
        gateway_url=gateway_url,
        spiffe_id=spiffe_id,
        tracer=tracer,
    )

    try:
        deps = AgentDeps(
            gateway=gateway_client,
            question=question,
            poc_dir=POC_DIR,
        )

        # Execute agent with tracing span
        if tracer:
            with tracer.start_as_current_span(
                "pydantic_researcher.run",
                attributes={
                    "research.question": question,
                    "spiffe.id": spiffe_id,
                    "session.id": SESSION_ID,
                },
            ):
                result = qa_agent.run_sync(question, deps=deps)
        else:
            result = qa_agent.run_sync(question, deps=deps)

        logger.info("Q&A complete. Answer generated successfully.")
        return result.output
    finally:
        gateway_client.close()
        # Flush traces
        if enable_tracing:
            provider = trace.get_tracer_provider()
            if hasattr(provider, "force_flush"):
                provider.force_flush(timeout_millis=5000)


def format_answer(answer: GroundedAnswer) -> str:
    """Format a GroundedAnswer into a readable string."""
    lines = [
        "=" * 72,
        f"Q&A RESULT",
        "=" * 72,
        "",
        f"QUESTION: {answer.question}",
        "",
        "ANSWER",
        "-" * 40,
        answer.answer,
        "",
        "KEY POINTS",
        "-" * 40,
    ]
    for i, point in enumerate(answer.key_points, 1):
        lines.append(f"  {i}. {point}")

    lines.extend([
        "",
        "CITATIONS",
        "-" * 40,
    ])
    for i, citation in enumerate(answer.citations, 1):
        lines.append(f"  [{i}] {citation.title}")
        lines.append(f"      Source: {citation.source}")
        lines.append(f"      Excerpt: {citation.relevant_excerpt}")

    lines.extend([
        "",
        f"CONFIDENCE: {answer.confidence_score:.2f}",
        f"SOURCES CONSULTED: {answer.sources_consulted}",
        f"LIMITATIONS: {answer.limitations}",
        "=" * 72,
    ])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

def main():
    """CLI entrypoint."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    question = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "What are the key differences between SPIFFE and traditional OAuth for agent identity?"
    )

    logger.info("Starting PydanticAI Research Agent")
    logger.info("Gateway: %s", GATEWAY_URL)
    logger.info("SPIFFE ID: %s", SPIFFE_ID)
    logger.info("Question: %s", question)
    logger.info("Session ID: %s", SESSION_ID)

    answer = run_qa(question)
    print(format_answer(answer))
    print("\nStructured JSON output:")
    print(answer.model_dump_json(indent=2))


if __name__ == "__main__":
    main()

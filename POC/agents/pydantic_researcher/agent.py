"""
PydanticAI Research Agent - RFA-qq0.8, refactored with mcp-gateway-sdk (RFA-tj9.3)

A PydanticAI-based Q&A agent that demonstrates security gateway integration
with structured output using Pydantic models.

Performs Q&A by searching with Tavily and reading local files via the
MCP security gateway, then produces a structured answer with citations
and confidence scores.

All tool calls are routed through the gateway MCP endpoint via the shared SDK.
Identity: spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev
"""

import json
import logging
import os
import pathlib
import sys
import uuid
from dataclasses import dataclass

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

# Shared SDK -- replaces ~120 lines of inline GatewayClient boilerplate
from mcp_gateway_sdk import GatewayClient, GatewayError

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

# POC directory for file reads.
POC_DIR = os.environ.get(
    "POC_DIR",
    str(pathlib.Path(__file__).resolve().parent.parent.parent),
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

@dataclass
class AgentDeps:
    """Dependencies injected into the PydanticAI agent at runtime."""
    gateway: GatewayClient
    question: str
    poc_dir: str = POC_DIR


# Create the PydanticAI agent with structured output and instrumentation.
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
    """Search the web using Tavily for relevant information."""
    try:
        result = ctx.deps.gateway.call("tavily_search", query=query, max_results=max_results)
        return json.dumps(result, indent=2)
    except GatewayError as e:
        return f"[SEARCH FAILED: {e.code} - {e.message} (remediation: {e.remediation})]"


@qa_agent.tool
def file_read(ctx: RunContext[AgentDeps], file_path: str) -> str:
    """Read a local reference file through the security gateway."""
    try:
        result = ctx.deps.gateway.call("read", file_path=file_path)
        content = result
        if isinstance(content, dict):
            content = content.get("content", content.get("text", json.dumps(content)))
        elif isinstance(content, list):
            content = "\n".join(str(item) for item in content)
        text = str(content)
        if len(text) > 5000:
            text = text[:5000] + "\n[... truncated ...]"
        return text
    except GatewayError as e:
        return f"[FILE READ FAILED: {e.code} - {e.message}]"


@qa_agent.tool
def list_reference_files(ctx: RunContext[AgentDeps]) -> str:
    """List available reference files in the POC/docs/ directory."""
    docs_dir = f"{ctx.deps.poc_dir}/docs"
    try:
        result = ctx.deps.gateway.call("read", file_path=docs_dir)
        return json.dumps(result, indent=2)
    except GatewayError:
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
    """Run the PydanticAI Q&A agent on a given question."""
    tracer = None
    if enable_tracing:
        try:
            tracer = setup_observability()
            logger.info("OpenTelemetry tracing enabled (endpoint: %s)", OTEL_ENDPOINT)
        except Exception as exc:
            logger.warning("Failed to setup tracing (continuing without): %s", exc)

    gateway_client = GatewayClient(
        url=gateway_url,
        spiffe_id=spiffe_id,
        session_id=SESSION_ID,
        tracer=tracer,
    )

    try:
        deps = AgentDeps(
            gateway=gateway_client,
            question=question,
            poc_dir=POC_DIR,
        )

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
        if enable_tracing:
            provider = trace.get_tracer_provider()
            if hasattr(provider, "force_flush"):
                provider.force_flush(timeout_millis=5000)


def format_answer(answer: GroundedAnswer) -> str:
    """Format a GroundedAnswer into a readable string."""
    lines = [
        "=" * 72,
        "Q&A RESULT",
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

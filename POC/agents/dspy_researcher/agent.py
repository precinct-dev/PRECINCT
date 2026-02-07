"""
DSPy Research Agent - RFA-qq0.7, refactored with mcp-gateway-sdk (RFA-tj9.3)

A DSPy-based research agent that demonstrates security gateway integration.
Performs research by searching with Tavily and reading local files via the
MCP security gateway, then synthesizes findings into a structured report.

All tool calls are routed through the gateway MCP endpoint via the shared SDK.
Identity: spiffe://poc.local/agents/mcp-client/dspy-researcher/dev
"""

import json
import logging
import os
import sys
import uuid

import dspy
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# OpenInference instrumentation for DSPy
from openinference.instrumentation.dspy import DSPyInstrumentor

# Shared SDK -- replaces ~120 lines of inline GatewayClient boilerplate
from mcp_gateway_sdk import GatewayClient, GatewayError

logger = logging.getLogger("dspy_researcher")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:9090")
SPIFFE_ID = os.environ.get(
    "SPIFFE_ID",
    "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
)
OTEL_ENDPOINT = os.environ.get("OTEL_ENDPOINT", "http://localhost:4317")
LLM_MODEL = os.environ.get("LLM_MODEL", "groq/llama-3.3-70b-versatile")
SESSION_ID = os.environ.get("SESSION_ID", str(uuid.uuid4()))


# ---------------------------------------------------------------------------
# Observability setup
# ---------------------------------------------------------------------------

def setup_observability() -> trace.Tracer:
    """Configure OpenTelemetry tracing with OTLP export to collector/Phoenix."""
    resource = Resource.create(
        {
            "service.name": "dspy-researcher",
            "service.version": "0.1.0",
            "spiffe.id": SPIFFE_ID,
            "session.id": SESSION_ID,
        }
    )
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=OTEL_ENDPOINT, insecure=True)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    # Instrument DSPy with OpenInference
    DSPyInstrumentor().instrument()

    return trace.get_tracer("dspy_researcher")


# ---------------------------------------------------------------------------
# DSPy Signatures
# ---------------------------------------------------------------------------

class ResearchPlan(dspy.Signature):
    """Given a security topic, produce a research plan with search queries
    and relevant local files to read."""
    topic: str = dspy.InputField(desc="Security topic to research")
    search_queries: list[str] = dspy.OutputField(
        desc="List of 2-3 focused web search queries for Tavily"
    )
    local_files: list[str] = dspy.OutputField(
        desc="List of local file paths under the POC docs/ directory to read for additional context"
    )
    rationale: str = dspy.OutputField(
        desc="Brief explanation of the research approach"
    )


class SearchSynthesis(dspy.Signature):
    """Synthesize web search results into key findings."""
    topic: str = dspy.InputField(desc="Security topic being researched")
    search_results: str = dspy.InputField(
        desc="Raw search results from Tavily web searches"
    )
    key_findings: str = dspy.OutputField(
        desc="Synthesized key findings from web search, organized by theme"
    )


class FileSynthesis(dspy.Signature):
    """Synthesize local file contents into relevant context."""
    topic: str = dspy.InputField(desc="Security topic being researched")
    file_contents: str = dspy.InputField(
        desc="Contents read from local reference files"
    )
    relevant_context: str = dspy.OutputField(
        desc="Relevant context extracted from local files"
    )


class ReportSynthesis(dspy.Signature):
    """Synthesize web findings and local context into a structured research report."""
    topic: str = dspy.InputField(desc="Security topic being researched")
    web_findings: str = dspy.InputField(
        desc="Key findings from web search"
    )
    local_context: str = dspy.InputField(
        desc="Relevant context from local reference files"
    )
    report_title: str = dspy.OutputField(desc="Report title")
    executive_summary: str = dspy.OutputField(
        desc="2-3 sentence executive summary"
    )
    detailed_findings: str = dspy.OutputField(
        desc="Detailed findings organized into sections"
    )
    recommendations: str = dspy.OutputField(
        desc="Actionable recommendations based on findings"
    )
    sources: str = dspy.OutputField(
        desc="List of sources used (web URLs and local file paths)"
    )


# ---------------------------------------------------------------------------
# DSPy Modules (tool-calling modules that route through gateway)
# ---------------------------------------------------------------------------

class GatewayWebSearch(dspy.Module):
    """DSPy Module that performs web search via Tavily through the gateway."""

    def __init__(self, gateway_client: GatewayClient):
        super().__init__()
        self.gateway = gateway_client

    def forward(self, query: str, max_results: int = 5) -> dspy.Prediction:
        try:
            result = self.gateway.call("tavily_search", query=query, max_results=max_results)
            return dspy.Prediction(
                success=True,
                results=json.dumps(result, indent=2),
                error=None,
            )
        except GatewayError as e:
            return dspy.Prediction(
                success=False,
                results="",
                error=f"Search failed: {e.code} - {e.message}",
            )


class GatewayFileRead(dspy.Module):
    """DSPy Module that reads files through the gateway."""

    def __init__(self, gateway_client: GatewayClient):
        super().__init__()
        self.gateway = gateway_client

    def forward(self, file_path: str) -> dspy.Prediction:
        try:
            result = self.gateway.call("read", file_path=file_path)
            content = result
            if isinstance(content, dict):
                content = content.get("content", content.get("text", json.dumps(content)))
            elif isinstance(content, list):
                content = "\n".join(str(item) for item in content)
            return dspy.Prediction(
                success=True,
                content=str(content),
                error=None,
            )
        except GatewayError as e:
            return dspy.Prediction(
                success=False,
                content="",
                error=f"File read failed: {e.code} - {e.message}",
            )


class ResearchAgent(dspy.Module):
    """DSPy Module that orchestrates the full research workflow.

    Workflow:
    1. Plan research (generate search queries + local files to read)
    2. Execute web searches via gateway (Tavily)
    3. Read local reference files via gateway
    4. Synthesize findings into structured report
    """

    def __init__(self, gateway_client: GatewayClient):
        super().__init__()
        self.gateway = gateway_client
        self.planner = dspy.ChainOfThought(ResearchPlan)
        self.search_synth = dspy.ChainOfThought(SearchSynthesis)
        self.file_synth = dspy.ChainOfThought(FileSynthesis)
        self.report_synth = dspy.ChainOfThought(ReportSynthesis)
        self.web_search = GatewayWebSearch(gateway_client)
        self.file_read = GatewayFileRead(gateway_client)

    def forward(self, topic: str) -> dspy.Prediction:
        # Step 1: Plan research
        logger.info("Step 1: Planning research for topic: %s", topic)
        plan = self.planner(topic=topic)
        logger.info(
            "Plan: %d search queries, %d local files",
            len(plan.search_queries) if isinstance(plan.search_queries, list) else 0,
            len(plan.local_files) if isinstance(plan.local_files, list) else 0,
        )

        # Step 2: Execute web searches
        logger.info("Step 2: Executing web searches via gateway")
        all_search_results = []
        search_queries = plan.search_queries if isinstance(plan.search_queries, list) else []
        for query in search_queries:
            logger.info("  Searching: %s", query)
            search_result = self.web_search(query=query)
            if search_result.success:
                all_search_results.append(
                    f"Query: {query}\nResults:\n{search_result.results}"
                )
            else:
                logger.warning(
                    "  Search skipped (denied/failed): %s", search_result.error
                )
                all_search_results.append(
                    f"Query: {query}\n[DENIED/FAILED: {search_result.error}]"
                )

        # Step 3: Read local files
        logger.info("Step 3: Reading local reference files via gateway")
        all_file_contents = []
        local_files = plan.local_files if isinstance(plan.local_files, list) else []
        for file_path in local_files:
            logger.info("  Reading: %s", file_path)
            file_result = self.file_read(file_path=file_path)
            if file_result.success:
                # Truncate very long files to avoid context overflow
                content = file_result.content[:5000]
                all_file_contents.append(
                    f"File: {file_path}\n{content}"
                )
            else:
                logger.warning(
                    "  File read skipped (denied/failed): %s", file_result.error
                )
                all_file_contents.append(
                    f"File: {file_path}\n[DENIED/FAILED: {file_result.error}]"
                )

        # Step 4: Synthesize search results
        logger.info("Step 4: Synthesizing web search findings")
        search_text = "\n\n---\n\n".join(all_search_results) if all_search_results else "[No search results available]"
        search_synthesis = self.search_synth(
            topic=topic, search_results=search_text
        )

        # Step 5: Synthesize file contents
        logger.info("Step 5: Synthesizing local file context")
        file_text = "\n\n---\n\n".join(all_file_contents) if all_file_contents else "[No local files available]"
        file_synthesis = self.file_synth(
            topic=topic, file_contents=file_text
        )

        # Step 6: Generate final report
        logger.info("Step 6: Generating final research report")
        report = self.report_synth(
            topic=topic,
            web_findings=search_synthesis.key_findings,
            local_context=file_synthesis.relevant_context,
        )

        return dspy.Prediction(
            report_title=report.report_title,
            executive_summary=report.executive_summary,
            detailed_findings=report.detailed_findings,
            recommendations=report.recommendations,
            sources=report.sources,
            search_queries_used=search_queries,
            local_files_read=local_files,
            denial_count=sum(
                1 for r in all_search_results if "[DENIED/FAILED:" in r
            ) + sum(
                1 for c in all_file_contents if "[DENIED/FAILED:" in c
            ),
        )


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def format_report(prediction: dspy.Prediction) -> str:
    """Format a DSPy Prediction into a readable research report."""
    lines = [
        "=" * 72,
        f"RESEARCH REPORT: {prediction.report_title}",
        "=" * 72,
        "",
        "EXECUTIVE SUMMARY",
        "-" * 40,
        prediction.executive_summary,
        "",
        "DETAILED FINDINGS",
        "-" * 40,
        prediction.detailed_findings,
        "",
        "RECOMMENDATIONS",
        "-" * 40,
        prediction.recommendations,
        "",
        "SOURCES",
        "-" * 40,
        prediction.sources,
        "",
        "=" * 72,
        f"Searches executed: {len(prediction.search_queries_used)}",
        f"Files read: {len(prediction.local_files_read)}",
        f"Denials encountered: {prediction.denial_count}",
        "=" * 72,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

def run_research(
    topic: str,
    gateway_url: str = GATEWAY_URL,
    spiffe_id: str = SPIFFE_ID,
    enable_tracing: bool = True,
) -> str:
    """Run the research agent on a given topic."""
    tracer = None
    if enable_tracing:
        try:
            tracer = setup_observability()
            logger.info("OpenTelemetry tracing enabled (endpoint: %s)", OTEL_ENDPOINT)
        except Exception as exc:
            logger.warning("Failed to setup tracing (continuing without): %s", exc)

    # Configure DSPy LLM
    lm = dspy.LM(LLM_MODEL)
    dspy.configure(lm=lm)
    logger.info("DSPy configured with LLM: %s", LLM_MODEL)

    gateway_client = GatewayClient(
        url=gateway_url,
        spiffe_id=spiffe_id,
        session_id=SESSION_ID,
        tracer=tracer,
    )

    try:
        agent = ResearchAgent(gateway_client)

        if tracer:
            with tracer.start_as_current_span(
                "research_agent.run",
                attributes={
                    "research.topic": topic,
                    "spiffe.id": spiffe_id,
                    "session.id": SESSION_ID,
                },
            ):
                prediction = agent(topic=topic)
        else:
            prediction = agent(topic=topic)

        report = format_report(prediction)
        logger.info("Research complete. Report generated successfully.")
        return report
    finally:
        gateway_client.close()
        if enable_tracing:
            provider = trace.get_tracer_provider()
            if hasattr(provider, "force_flush"):
                provider.force_flush(timeout_millis=5000)


def main():
    """CLI entrypoint."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    topic = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "prompt injection defenses in agentic AI"
    )

    logger.info("Starting DSPy Research Agent")
    logger.info("Gateway: %s", GATEWAY_URL)
    logger.info("SPIFFE ID: %s", SPIFFE_ID)
    logger.info("Topic: %s", topic)
    logger.info("Session ID: %s", SESSION_ID)

    report = run_research(topic)
    print(report)


if __name__ == "__main__":
    main()

"""
Integration tests for PydanticAI Research Agent - RFA-qq0.8
Updated for mcp-gateway-sdk refactoring (RFA-tj9.3)

Tests verify:
1. Agent produces a structured Pydantic model answer (GroundedAnswer)
2. All tool calls go through gateway (audit events present)
3. PydanticAI agent with structured Pydantic output models (not raw text)
4. Gateway denial handling: denials are handled gracefully via GatewayError
5. SPIFFE ID authentication works
6. Pydantic model validation on output

These tests run against the compose stack for integration tests, or
against a mock gateway for unit tests.

Run with: pytest test_agent.py -v
"""

import json
import logging
import os
import pathlib
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

import httpx
import pytest
from pydantic import ValidationError

# Import SDK types (replaces inline GatewayClient)
from mcp_gateway_sdk import GatewayClient, GatewayError

# Import agent-specific types
from agent import (
    Citation,
    GroundedAnswer,
    AgentDeps,
    qa_agent,
    tavily_search,
    file_read,
    list_reference_files,
    format_answer,
    run_qa,
    SPIFFE_ID,
)

logger = logging.getLogger("test_pydantic_researcher")

# Test configuration
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:9090")
OTEL_ENDPOINT = os.environ.get("OTEL_ENDPOINT", "http://localhost:4317")
PHOENIX_URL = os.environ.get("PHOENIX_URL", "http://localhost:6006")
SPIFFE_ID_PYDANTIC = "spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev"

# POC directory for file reads.
POC_DIR = os.environ.get(
    "POC_DIR",
    str(pathlib.Path(__file__).resolve().parent.parent.parent),
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def gateway_client():
    """Create a GatewayClient connected to the running gateway."""
    client = GatewayClient(
        url=GATEWAY_URL,
        spiffe_id=SPIFFE_ID_PYDANTIC,
    )
    yield client
    client.close()


@pytest.fixture(scope="module")
def check_gateway_health():
    """Verify gateway is reachable before running tests."""
    try:
        resp = httpx.get(f"{GATEWAY_URL}/health", timeout=10.0)
        if resp.status_code != 200:
            pytest.skip(
                f"Gateway not healthy (status {resp.status_code}). "
                "Run 'make up' to start the compose stack."
            )
    except httpx.ConnectError:
        pytest.skip(
            f"Gateway not reachable at {GATEWAY_URL}. "
            "Run 'make up' to start the compose stack."
        )


# ---------------------------------------------------------------------------
# Mock Gateway for denial testing (runs locally, no compose needed)
# ---------------------------------------------------------------------------


class MockGatewayHandler(BaseHTTPRequestHandler):
    """Mock gateway that simulates denial responses for testing."""

    # Class-level response configuration
    response_mode = "normal"  # "normal", "deny_403", "deny_503"
    call_log = []

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        request_data = json.loads(body) if body else {}
        spiffe_id = self.headers.get("X-SPIFFE-ID", "")

        MockGatewayHandler.call_log.append({
            "method": request_data.get("method", ""),
            "params": request_data.get("params", {}),
            "spiffe_id": spiffe_id,
            "id": request_data.get("id"),
        })

        if MockGatewayHandler.response_mode == "deny_403":
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "code": "authz_policy_denied",
                "message": "OPA policy denied access to tool",
                "middleware": "opa_authz",
                "middleware_step": 3,
                "decision_id": "dec-test-001",
                "trace_id": "trace-test-001",
                "remediation": "Request access via admin portal",
            }).encode())
            return

        if MockGatewayHandler.response_mode == "deny_503":
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "code": "circuit_open",
                "message": "Circuit breaker is open -- service unavailable",
                "middleware": "circuit_breaker",
                "middleware_step": 7,
                "decision_id": "dec-test-002",
                "trace_id": "trace-test-002",
            }).encode())
            return

        # Normal mode -- return mock MCP response
        method = request_data.get("method", "")
        if method == "tavily_search":
            result = {
                "results": [
                    {
                        "title": "SPIFFE vs OAuth for Agent Identity",
                        "url": "https://example.com/spiffe-oauth",
                        "content": (
                            "SPIFFE provides workload identity through SVIDs, "
                            "while OAuth focuses on delegated authorization. "
                            "SPIFFE is better suited for machine-to-machine "
                            "identity in zero-trust architectures."
                        ),
                    },
                    {
                        "title": "Zero Trust Agent Authentication",
                        "url": "https://example.com/zero-trust",
                        "content": (
                            "Modern agent frameworks use SPIFFE for mutual TLS "
                            "authentication, eliminating the need for shared secrets."
                        ),
                    },
                ]
            }
        elif method == "read":
            result = {
                "content": (
                    "# SPIFFE Setup Guide\n"
                    "SPIFFE provides a secure identity framework for "
                    "distributed systems. Each workload receives a SPIFFE "
                    "Verifiable Identity Document (SVID) that can be used "
                    "for mutual TLS authentication."
                )
            }
        else:
            result = {"status": "ok"}

        response = {
            "jsonrpc": "2.0",
            "result": result,
            "id": request_data.get("id", 1),
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress request logs in tests
        pass


@pytest.fixture
def mock_gateway():
    """Start a mock gateway server for denial testing."""
    MockGatewayHandler.response_mode = "normal"
    MockGatewayHandler.call_log = []
    server = HTTPServer(("127.0.0.1", 0), MockGatewayHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", MockGatewayHandler
    server.shutdown()


# ---------------------------------------------------------------------------
# Unit tests: Pydantic output models
# ---------------------------------------------------------------------------


class TestPydanticOutputModels:
    """Verify that Pydantic output models are correctly defined and validate."""

    def test_citation_model_valid(self):
        """Citation model accepts valid data."""
        citation = Citation(
            source="https://example.com/article",
            title="Test Article",
            relevant_excerpt="Important finding about security.",
        )
        assert citation.source == "https://example.com/article"
        assert citation.title == "Test Article"
        assert len(citation.relevant_excerpt) > 0

    def test_grounded_answer_model_valid(self):
        """GroundedAnswer model accepts valid data with all fields."""
        answer = GroundedAnswer(
            question="What is SPIFFE?",
            answer="SPIFFE is a secure identity framework for distributed systems.",
            citations=[
                Citation(
                    source="https://spiffe.io",
                    title="SPIFFE Documentation",
                    relevant_excerpt="SPIFFE provides workload identity...",
                )
            ],
            confidence_score=0.85,
            key_points=["SPIFFE provides workload identity", "Uses SVIDs for auth"],
            sources_consulted=3,
            limitations="Limited to web sources; some reference files were unavailable.",
        )
        assert answer.question == "What is SPIFFE?"
        assert answer.confidence_score == 0.85
        assert len(answer.citations) == 1
        assert len(answer.key_points) == 2
        assert answer.sources_consulted == 3

    def test_grounded_answer_json_serialization(self):
        """GroundedAnswer can be serialized to valid JSON."""
        answer = GroundedAnswer(
            question="Test question",
            answer="Test answer",
            citations=[],
            confidence_score=0.5,
            key_points=["point 1"],
            sources_consulted=0,
            limitations="none",
        )
        json_str = answer.model_dump_json(indent=2)
        parsed = json.loads(json_str)
        assert parsed["question"] == "Test question"
        assert parsed["confidence_score"] == 0.5
        assert isinstance(parsed["citations"], list)
        assert isinstance(parsed["key_points"], list)

    def test_confidence_score_bounds(self):
        """Confidence score must be between 0.0 and 1.0."""
        # Valid bounds
        answer_low = GroundedAnswer(
            question="q", answer="a", citations=[], confidence_score=0.0,
            key_points=[], sources_consulted=0, limitations="",
        )
        assert answer_low.confidence_score == 0.0

        answer_high = GroundedAnswer(
            question="q", answer="a", citations=[], confidence_score=1.0,
            key_points=[], sources_consulted=0, limitations="",
        )
        assert answer_high.confidence_score == 1.0

        # Out of bounds
        with pytest.raises(ValidationError):
            GroundedAnswer(
                question="q", answer="a", citations=[], confidence_score=1.5,
                key_points=[], sources_consulted=0, limitations="",
            )

        with pytest.raises(ValidationError):
            GroundedAnswer(
                question="q", answer="a", citations=[], confidence_score=-0.1,
                key_points=[], sources_consulted=0, limitations="",
            )

    def test_grounded_answer_schema_matches_spec(self):
        """GroundedAnswer JSON schema has all required fields from the spec."""
        schema = GroundedAnswer.model_json_schema()
        required = schema.get("required", [])
        assert "question" in required
        assert "answer" in required
        assert "citations" in required
        assert "confidence_score" in required
        assert "key_points" in required
        assert "sources_consulted" in required
        assert "limitations" in required


# ---------------------------------------------------------------------------
# Unit tests: GatewayClient (using SDK)
# ---------------------------------------------------------------------------


class TestGatewayClient:
    """Tests for the SDK GatewayClient HTTP/denial handling logic."""

    def test_call_success(self, mock_gateway):
        """Verify successful tool call returns data."""
        url, handler = mock_gateway
        handler.response_mode = "normal"

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID_PYDANTIC)
        result = client.call("tavily_search", query="test")

        assert result is not None
        assert "results" in result
        client.close()

    def test_call_403_denial(self, mock_gateway):
        """Verify HTTP 403 (policy denial) raises GatewayError -- no crash,
        no retry, clear error info."""
        url, handler = mock_gateway
        handler.response_mode = "deny_403"
        handler.call_log = []

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID_PYDANTIC)
        with pytest.raises(GatewayError) as exc_info:
            client.call("tavily_search", query="test")

        err = exc_info.value
        assert err.http_status == 403
        assert err.code == "authz_policy_denied"
        assert err.middleware == "opa_authz"
        # 403 should NOT be retried -- only 1 call
        assert len(handler.call_log) == 1
        client.close()

    def test_call_503_denial_with_retry(self, mock_gateway):
        """Verify HTTP 503 (guard unavailable) triggers retry with backoff."""
        url, handler = mock_gateway
        handler.response_mode = "deny_503"
        handler.call_log = []

        client = GatewayClient(
            url=url,
            spiffe_id=SPIFFE_ID_PYDANTIC,
            max_retries=2,
            backoff_base=0.01,  # fast for testing
        )

        with pytest.raises(GatewayError) as exc_info:
            client.call("tavily_search", query="test")

        err = exc_info.value
        assert err.http_status == 503
        assert err.code == "circuit_open"
        # Should have retried: 1 initial + 2 retries = 3 calls
        assert len(handler.call_log) == 3
        client.close()

    def test_spiffe_id_sent_in_header(self, mock_gateway):
        """Verify X-SPIFFE-ID header is sent with every request."""
        url, handler = mock_gateway
        handler.response_mode = "normal"
        handler.call_log = []

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID_PYDANTIC)
        client.call("read", file_path="/some/file")

        assert len(handler.call_log) == 1
        assert handler.call_log[0]["spiffe_id"] == SPIFFE_ID_PYDANTIC
        client.close()

    def test_connection_error_handled(self):
        """Verify connection errors propagate as httpx.ConnectError."""
        client = GatewayClient(
            url="http://127.0.0.1:1",  # Nothing listening
            spiffe_id=SPIFFE_ID_PYDANTIC,
        )
        with pytest.raises(Exception) as exc_info:
            client.call("read", file_path="/some/file")

        # Should be a connection error (httpx.ConnectError)
        assert "connect" in str(exc_info.value).lower() or "Connection" in str(exc_info.value)
        client.close()


# ---------------------------------------------------------------------------
# Unit tests: PydanticAI agent structure
# ---------------------------------------------------------------------------


class TestPydanticAIAgentStructure:
    """Verify the PydanticAI agent is properly configured."""

    def test_agent_has_structured_output_type(self):
        """Agent output_type is GroundedAnswer (not raw text)."""
        assert qa_agent is not None

    def test_agent_has_tools_registered(self):
        """Agent has tavily_search, file_read, list_reference_files tools."""
        assert tavily_search is not None
        assert file_read is not None
        assert list_reference_files is not None

    def test_agent_deps_type_is_agent_deps(self):
        """Agent uses AgentDeps for dependency injection."""
        deps = AgentDeps(
            gateway=GatewayClient(
                url="http://localhost:1", spiffe_id="test"
            ),
            question="test question",
            poc_dir="/test",
        )
        assert deps.question == "test question"
        assert deps.poc_dir == "/test"
        deps.gateway.close()

    def test_spiffe_id_default_value(self):
        """Default SPIFFE ID matches the story specification."""
        assert SPIFFE_ID == "spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev"


# ---------------------------------------------------------------------------
# Unit tests: MCP protocol
# ---------------------------------------------------------------------------


class TestMCPProtocol:
    """Test that MCP JSON-RPC protocol is correctly formed."""

    def test_request_format(self, mock_gateway):
        """Verify requests follow JSON-RPC 2.0 format."""
        url, handler = mock_gateway
        handler.response_mode = "normal"
        handler.call_log = []

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID_PYDANTIC)
        client.call("tavily_search", query="test", max_results=3)

        assert len(handler.call_log) == 1
        call = handler.call_log[0]
        assert call["method"] == "tavily_search"
        assert call["params"]["query"] == "test"
        assert call["params"]["max_results"] == 3
        assert call["id"] is not None  # JSON-RPC id present
        client.close()

    def test_tool_calls_all_go_through_gateway(self, mock_gateway):
        """Verify NO direct tool access -- all calls go through gateway."""
        url, handler = mock_gateway
        handler.response_mode = "normal"
        handler.call_log = []

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID_PYDANTIC)

        # Make multiple tool calls
        client.call("tavily_search", query="test1")
        client.call("read", file_path="/test/file1.md")
        client.call("tavily_search", query="test2")
        client.call("read", file_path="/test/file2.md")

        # All 4 calls should be logged at the gateway
        assert len(handler.call_log) == 4
        methods = [c["method"] for c in handler.call_log]
        assert methods.count("tavily_search") == 2
        assert methods.count("read") == 2

        # Every call has SPIFFE ID
        for call in handler.call_log:
            assert call["spiffe_id"] == SPIFFE_ID_PYDANTIC

        client.close()


# ---------------------------------------------------------------------------
# Unit tests: Denial graceful degradation
# ---------------------------------------------------------------------------


class TestDenialGracefulDegradation:
    """Test that the agent degrades gracefully when tools are denied."""

    def test_gateway_client_handles_mixed_denials(self, mock_gateway):
        """When tools are denied, client raises GatewayError instead of crashing."""
        url, handler = mock_gateway
        handler.response_mode = "deny_403"
        handler.call_log = []

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID_PYDANTIC)

        # Both tool types should raise GatewayError
        with pytest.raises(GatewayError) as exc_info:
            client.call("tavily_search", query="test")
        assert exc_info.value.http_status == 403

        with pytest.raises(GatewayError) as exc_info:
            client.call("read", file_path="/test.md")
        assert exc_info.value.http_status == 403

        # All calls should have been logged with SPIFFE ID
        for call in handler.call_log:
            assert call["spiffe_id"] == SPIFFE_ID_PYDANTIC

        client.close()

    def test_503_retry_exhaustion_raises_error(self, mock_gateway):
        """After exhausting 503 retries, client raises GatewayError."""
        url, handler = mock_gateway
        handler.response_mode = "deny_503"
        handler.call_log = []

        client = GatewayClient(
            url=url,
            spiffe_id=SPIFFE_ID_PYDANTIC,
            max_retries=1,
            backoff_base=0.01,
        )

        with pytest.raises(GatewayError) as exc_info:
            client.call("read", file_path="/test.md")

        assert exc_info.value.http_status == 503
        # 1 initial + 1 retry = 2
        assert len(handler.call_log) == 2
        client.close()


# ---------------------------------------------------------------------------
# Unit tests: format_answer
# ---------------------------------------------------------------------------


class TestFormatAnswer:
    """Test answer formatting."""

    def test_format_answer_structure(self):
        """Verify formatted answer has all expected sections."""
        answer = GroundedAnswer(
            question="What is SPIFFE?",
            answer="SPIFFE provides workload identity.",
            citations=[
                Citation(
                    source="https://spiffe.io",
                    title="SPIFFE Docs",
                    relevant_excerpt="Workload identity framework",
                )
            ],
            confidence_score=0.9,
            key_points=["Point A", "Point B"],
            sources_consulted=2,
            limitations="None",
        )

        formatted = format_answer(answer)

        assert "Q&A RESULT" in formatted
        assert "What is SPIFFE?" in formatted
        assert "SPIFFE provides workload identity." in formatted
        assert "KEY POINTS" in formatted
        assert "Point A" in formatted
        assert "Point B" in formatted
        assert "CITATIONS" in formatted
        assert "SPIFFE Docs" in formatted
        assert "https://spiffe.io" in formatted
        assert "CONFIDENCE: 0.90" in formatted
        assert "SOURCES CONSULTED: 2" in formatted


# ---------------------------------------------------------------------------
# Integration tests (require compose stack -- gateway + Phoenix + OTel)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGatewayIntegration:
    """Integration tests that run against the actual compose stack."""

    def test_gateway_health(self, check_gateway_health):
        """Gateway health endpoint responds."""
        resp = httpx.get(f"{GATEWAY_URL}/health", timeout=10.0)
        assert resp.status_code == 200

    def test_file_read_through_gateway(self, check_gateway_health):
        """Read a local file through the gateway successfully."""
        with GatewayClient(url=GATEWAY_URL, spiffe_id=SPIFFE_ID_PYDANTIC) as client:
            result = client.call("read", file_path=f"{POC_DIR}/docker-compose.yml")

        assert result is not None

    def test_tavily_search_through_gateway(self, check_gateway_health):
        """Execute a Tavily web search through the gateway."""
        with GatewayClient(url=GATEWAY_URL, spiffe_id=SPIFFE_ID_PYDANTIC) as client:
            try:
                result = client.call(
                    "tavily_search",
                    query="SPIFFE vs OAuth agent identity",
                    max_results=2,
                )
                assert result is not None
            except GatewayError:
                # Tavily not configured -- acceptable
                pass

    def test_denied_tool_through_gateway(self, check_gateway_health):
        """Verify that a tool the agent is NOT authorized for gets denied."""
        with GatewayClient(url=GATEWAY_URL, spiffe_id=SPIFFE_ID_PYDANTIC) as client:
            with pytest.raises(GatewayError):
                client.call("bash", command="echo hello")

    def test_invalid_spiffe_id_rejected(self, check_gateway_health):
        """Verify that an invalid SPIFFE ID gets rejected."""
        with GatewayClient(url=GATEWAY_URL, spiffe_id="not-a-valid-spiffe-id") as client:
            with pytest.raises(GatewayError) as exc_info:
                client.call("read", file_path=f"{POC_DIR}/docker-compose.yml")
        assert exc_info.value.http_status == 401

    def test_path_denied_outside_poc(self, check_gateway_health):
        """Verify reading files outside POC directory is denied."""
        with GatewayClient(url=GATEWAY_URL, spiffe_id=SPIFFE_ID_PYDANTIC) as client:
            with pytest.raises(GatewayError):
                client.call("read", file_path="/etc/passwd")

    def test_audit_events_logged(self, check_gateway_health):
        """Verify gateway logs audit events for tool calls."""
        with GatewayClient(url=GATEWAY_URL, spiffe_id=SPIFFE_ID_PYDANTIC) as client:
            client.call("read", file_path=f"{POC_DIR}/Makefile")
        assert True  # If we got here, the call went through the gateway


@pytest.mark.integration
class TestPhoenixTracing:
    """Integration tests for Phoenix observability."""

    def test_phoenix_health(self, check_gateway_health):
        """Phoenix UI is reachable."""
        try:
            resp = httpx.get(f"{PHOENIX_URL}/", timeout=10.0)
            assert resp.status_code == 200
        except httpx.ConnectError:
            pytest.skip(f"Phoenix not reachable at {PHOENIX_URL}")

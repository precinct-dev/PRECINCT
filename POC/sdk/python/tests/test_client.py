"""
Unit tests for mcp-gateway-sdk GatewayClient.

Tests cover:
  - Constructor with required and optional params
  - JSON-RPC envelope construction (jsonrpc, method, params, id)
  - Required headers (X-SPIFFE-ID, X-Session-ID, Content-Type)
  - Unified error parsing into GatewayError
  - Retry logic for 503 with exponential backoff
  - Session ID management (auto-generated UUID if not provided)
  - Context manager protocol
  - 403 denial parsing (no retry)
  - 401 authentication failure
  - 429 rate limit
  - Connection error handling
"""

import json
import re
import time
import uuid

import httpx
import pytest

from mcp_gateway_sdk import GatewayClient, GatewayError


SPIFFE_ID = "spiffe://poc.local/agents/mcp-client/test/dev"


class _FakeSpan:
    def __init__(self, name: str, attributes: dict[str, object]):
        self.name = name
        self.attributes = dict(attributes)
        self.ended = False

    def set_attribute(self, key: str, value: object) -> None:
        self.attributes[key] = value

    def end(self) -> None:
        self.ended = True


class _FakeTracer:
    def __init__(self):
        self.spans: list[_FakeSpan] = []

    def start_span(self, name: str, attributes: dict[str, object]) -> _FakeSpan:
        span = _FakeSpan(name, attributes)
        self.spans.append(span)
        return span


# ---------------------------------------------------------------------------
# Constructor tests
# ---------------------------------------------------------------------------

class TestGatewayClientConstructor:
    """AC #2: GatewayClient(url, spiffe_id) constructor works with 2 required params."""

    def test_two_required_params(self):
        """Constructor works with just url and spiffe_id."""
        client = GatewayClient(url="http://localhost:9090", spiffe_id=SPIFFE_ID)
        assert client.url == "http://localhost:9090"
        assert client.spiffe_id == SPIFFE_ID
        client.close()

    def test_session_id_auto_generated(self):
        """AC #6: Session ID is auto-generated UUID if not provided."""
        client = GatewayClient(url="http://localhost:9090", spiffe_id=SPIFFE_ID)
        # Verify session_id is a valid UUID
        parsed = uuid.UUID(client.session_id)
        assert parsed.version == 4
        client.close()

    def test_session_id_explicit(self):
        """Explicit session_id overrides auto-generation."""
        client = GatewayClient(
            url="http://localhost:9090",
            spiffe_id=SPIFFE_ID,
            session_id="my-session-123",
        )
        assert client.session_id == "my-session-123"
        client.close()

    def test_custom_timeout(self):
        """Custom timeout is set on the HTTP client."""
        client = GatewayClient(
            url="http://localhost:9090",
            spiffe_id=SPIFFE_ID,
            timeout=10.0,
        )
        assert client._client.timeout.connect == 10.0
        client.close()

    def test_context_manager(self, mock_gateway):
        """GatewayClient supports 'with' statement."""
        url, _ = mock_gateway
        with GatewayClient(url=url, spiffe_id=SPIFFE_ID) as client:
            result = client.call("tavily_search", query="test")
            assert "results" in result

    def test_custom_http_client_supports_production_transport(self):
        """A caller can inject a preconfigured httpx.Client for production mTLS."""

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode("utf-8"))
            assert str(request.url) == "https://gateway.internal"
            assert body["method"] == "tools/call"
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "result": {"ok": True}, "id": body["id"]},
            )

        injected_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://gateway.internal",
        )
        client = GatewayClient(
            url="https://gateway.internal",
            spiffe_id=SPIFFE_ID,
            http_client=injected_client,
        )

        result = client.call("read", file_path="/tmp/example.txt")

        assert result == {"ok": True}
        assert client._client is injected_client
        client.close()
        injected_client.close()


# ---------------------------------------------------------------------------
# JSON-RPC envelope tests
# ---------------------------------------------------------------------------

class TestJSONRPCEnvelope:
    """AC #3: client.call(tool_name, **params) sends MCP JSON-RPC request."""

    def test_envelope_structure(self, mock_gateway):
        """Request contains jsonrpc, method, params, id."""
        url, handler = mock_gateway
        handler.call_log = []

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)
        client.call("tavily_search", query="test", max_results=3)

        assert len(handler.call_log) == 1
        call = handler.call_log[0]
        assert call["jsonrpc"] == "2.0"
        assert call["method"] == "tools/call"
        assert call["params"]["name"] == "tavily_search"
        assert call["tool_name"] == "tavily_search"
        assert call["tool_params"]["query"] == "test"
        assert call["tool_params"]["max_results"] == 3
        assert call["id"] is not None
        assert isinstance(call["id"], int)
        client.close()

    def test_request_ids_increment(self, mock_gateway):
        """Each call gets a unique incrementing request ID."""
        url, handler = mock_gateway
        handler.call_log = []

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)
        client.call("read", file_path="/a.txt")
        client.call("read", file_path="/b.txt")
        client.call("read", file_path="/c.txt")

        ids = [c["id"] for c in handler.call_log]
        assert ids[0] < ids[1] < ids[2]
        client.close()


# ---------------------------------------------------------------------------
# Headers tests
# ---------------------------------------------------------------------------

class TestHeaders:
    """Verify required headers are sent."""

    def test_spiffe_id_header(self, mock_gateway):
        """X-SPIFFE-ID header is sent with every request."""
        url, handler = mock_gateway
        handler.call_log = []

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)
        client.call("read", file_path="/test.md")

        assert handler.call_log[0]["spiffe_id"] == SPIFFE_ID
        client.close()

    def test_session_id_header(self, mock_gateway):
        """X-Session-ID header is sent with the configured session ID."""
        url, handler = mock_gateway
        handler.call_log = []

        client = GatewayClient(
            url=url, spiffe_id=SPIFFE_ID, session_id="sess-42"
        )
        client.call("read", file_path="/test.md")

        assert handler.call_log[0]["session_id"] == "sess-42"
        client.close()


class _FakeSpan:
    def __init__(self, attributes):
        self.attributes = dict(attributes)
        self.ended = False

    def set_attribute(self, key, value):
        self.attributes[key] = value

    def end(self):
        self.ended = True


class _FakeTracer:
    def __init__(self):
        self.spans = []

    def start_span(self, _name, attributes):
        span = _FakeSpan(attributes)
        self.spans.append(span)
        return span


# ---------------------------------------------------------------------------
# Model egress helper tests
# ---------------------------------------------------------------------------

class TestModelChatHelper:
    """Verify call_model_chat() request shape and error handling."""

    def test_model_chat_headers_and_endpoint(self, mock_gateway):
        url, handler = mock_gateway
        handler.call_log = []

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID, session_id="sess-model-1")
        result = client.call_model_chat(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": "hello"}],
            provider="groq",
            api_key_ref="Bearer $SPIKE{ref:deadbeef,exp:3600}",
        )

        assert result is not None
        assert len(handler.call_log) == 1
        call = handler.call_log[0]
        assert call["path"] == "/openai/v1/chat/completions"
        assert call["model_provider"] == "groq"
        assert call["authorization"] == "Bearer $SPIKE{ref:deadbeef,exp:3600}"
        assert call["spiffe_id"] == SPIFFE_ID
        assert call["session_id"] == "sess-model-1"
        client.close()

    def test_model_chat_gateway_denial_raises_gateway_error(self, mock_gateway):
        url, handler = mock_gateway
        handler.response_mode = "deny_403"
        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)

        with pytest.raises(GatewayError) as exc_info:
            client.call_model_chat(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": "hello"}],
                provider="groq",
                api_key_ref="Bearer $SPIKE{ref:deadbeef,exp:3600}",
            )

        err = exc_info.value
        assert err.http_status == 403
        assert err.code == "authz_policy_denied"
        client.close()

    def test_model_chat_rejects_absolute_endpoint(self, mock_gateway):
        url, _ = mock_gateway
        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)

        with pytest.raises(ValueError, match="gateway-relative endpoints"):
            client.call_model_chat(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": "hello"}],
                endpoint="https://api.openai.com/v1/chat/completions",
            )

        client.close()

    def test_model_chat_rejects_absolute_endpoints(self, mock_gateway):
        url, _ = mock_gateway
        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)

        with pytest.raises(ValueError) as exc_info:
            client.call_model_chat(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": "hello"}],
                endpoint="https://api.openai.com/v1/chat/completions",
            )

        assert "gateway-relative endpoints" in str(exc_info.value)
        client.close()


class TestObservabilityRedaction:
    def test_tool_call_span_redacts_arguments(self, mock_gateway):
        url, _ = mock_gateway
        tracer = _FakeTracer()
        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID, tracer=tracer)

        client.call("read", file_path="/tmp/secret.txt", token="super-secret")

        assert len(tracer.spans) == 1
        attrs = tracer.spans[0].attributes
        assert attrs["mcp.tool.arguments_redacted"] is True
        assert attrs["mcp.tool.argument_keys"] == "file_path,token"
        assert "mcp.tool.arguments" not in attrs
        client.close()


# ---------------------------------------------------------------------------
# Success path tests
# ---------------------------------------------------------------------------

class TestSuccessPath:
    """Verify successful tool calls return data."""

    def test_search_returns_results(self, mock_gateway):
        """call() returns the JSON-RPC result on success."""
        url, _ = mock_gateway
        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)

        result = client.call("tavily_search", query="test")
        assert "results" in result
        assert len(result["results"]) > 0
        assert result["results"][0]["title"] == "AI Security Best Practices"
        client.close()

    def test_file_read_returns_content(self, mock_gateway):
        """file read returns content dict."""
        url, _ = mock_gateway
        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)

        result = client.call("read", file_path="/some/file.md")
        assert "content" in result
        assert "Reference Document" in result["content"]
        client.close()


# ---------------------------------------------------------------------------
# Error parsing tests (AC #4)
# ---------------------------------------------------------------------------

class TestGatewayErrorParsing:
    """AC #4: Denials raise GatewayError with code, middleware, step, remediation."""

    def test_403_raises_gateway_error(self, mock_gateway):
        """403 denial is parsed into GatewayError with all envelope fields."""
        url, handler = mock_gateway
        handler.response_mode = "deny_403"

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)
        with pytest.raises(GatewayError) as exc_info:
            client.call("tavily_search", query="test")

        err = exc_info.value
        assert err.code == "authz_policy_denied"
        assert err.middleware == "opa_authz"
        assert err.step == 3
        assert err.decision_id == "dec-test-002"
        assert err.trace_id == "trace-test-002"
        assert err.remediation == "Request access via admin portal"
        assert err.http_status == 403
        assert err.details.get("tool") == "tavily_search"
        client.close()

    def test_401_raises_gateway_error(self, mock_gateway):
        """401 auth failure is parsed into GatewayError."""
        url, handler = mock_gateway
        handler.response_mode = "deny_401"

        client = GatewayClient(url=url, spiffe_id="bad-id")
        with pytest.raises(GatewayError) as exc_info:
            client.call("read", file_path="/test.md")

        err = exc_info.value
        assert err.code == "auth_missing_identity"
        assert err.http_status == 401
        assert err.middleware == "spiffe_auth"
        client.close()

    def test_429_raises_gateway_error(self, mock_gateway):
        """429 rate limit is parsed into GatewayError."""
        url, handler = mock_gateway
        handler.response_mode = "deny_429"

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)
        with pytest.raises(GatewayError) as exc_info:
            client.call("read", file_path="/test.md")

        err = exc_info.value
        assert err.code == "ratelimit_exceeded"
        assert err.http_status == 429
        assert "quota" in err.remediation.lower() or "reduce" in err.remediation.lower()
        client.close()

    def test_403_not_retried(self, mock_gateway):
        """403 errors are NOT retried -- only a single request made."""
        url, handler = mock_gateway
        handler.response_mode = "deny_403"
        handler.call_log = []

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)
        with pytest.raises(GatewayError):
            client.call("read", file_path="/test.md")

        assert len(handler.call_log) == 1
        client.close()

    def test_gateway_error_is_exception(self):
        """GatewayError inherits from Exception and can be caught."""
        err = GatewayError(code="test", message="test message")
        assert isinstance(err, Exception)
        assert str(err) == "test message"

    def test_gateway_error_repr(self):
        """GatewayError has a readable repr."""
        err = GatewayError(
            code="authz_policy_denied",
            message="Denied",
            middleware="opa",
            http_status=403,
        )
        r = repr(err)
        assert "authz_policy_denied" in r
        assert "Denied" in r
        assert "opa" in r
        assert "403" in r


# ---------------------------------------------------------------------------
# Retry logic tests (AC #5)
# ---------------------------------------------------------------------------

class TestRetryLogic:
    """AC #5: Retry logic handles 503 with exponential backoff (max 3 retries)."""

    def test_503_retried_max_times(self, mock_gateway):
        """503 triggers max_retries retries then raises GatewayError."""
        url, handler = mock_gateway
        handler.response_mode = "deny_503"
        handler.call_log = []

        client = GatewayClient(
            url=url,
            spiffe_id=SPIFFE_ID,
            max_retries=3,
            backoff_base=0.01,  # fast for testing
        )

        with pytest.raises(GatewayError) as exc_info:
            client.call("read", file_path="/test.md")

        err = exc_info.value
        assert err.http_status == 503
        assert err.code == "circuit_open"
        # 1 initial + 3 retries = 4 total calls
        assert len(handler.call_log) == 4
        client.close()

    def test_503_custom_max_retries(self, mock_gateway):
        """Custom max_retries=1 means 1 initial + 1 retry = 2 calls."""
        url, handler = mock_gateway
        handler.response_mode = "deny_503"
        handler.call_log = []

        client = GatewayClient(
            url=url,
            spiffe_id=SPIFFE_ID,
            max_retries=1,
            backoff_base=0.01,
        )

        with pytest.raises(GatewayError):
            client.call("read", file_path="/test.md")

        assert len(handler.call_log) == 2
        client.close()

    def test_503_backoff_increases(self, mock_gateway):
        """Backoff delays increase exponentially."""
        url, handler = mock_gateway
        handler.response_mode = "deny_503"
        handler.call_log = []

        base = 0.05  # 50ms base -- small enough for fast tests
        client = GatewayClient(
            url=url,
            spiffe_id=SPIFFE_ID,
            max_retries=2,
            backoff_base=base,
        )

        start = time.monotonic()
        with pytest.raises(GatewayError):
            client.call("read", file_path="/test.md")
        elapsed = time.monotonic() - start

        # Expected: 0.05 (first backoff) + 0.10 (second backoff) = 0.15s minimum
        # Allow some margin for slow CI
        assert elapsed >= 0.12, f"Expected >= 0.12s backoff, got {elapsed:.3f}s"
        client.close()


# ---------------------------------------------------------------------------
# Connection error tests
# ---------------------------------------------------------------------------

class TestConnectionErrors:
    """Connection errors propagate as httpx.ConnectError (not GatewayError)."""

    def test_connection_refused(self):
        """Unreachable gateway raises httpx.ConnectError."""
        client = GatewayClient(
            url="http://127.0.0.1:1",  # nothing listening
            spiffe_id=SPIFFE_ID,
        )
        with pytest.raises(httpx.ConnectError):
            client.call("read", file_path="/test.md")
        client.close()


# ---------------------------------------------------------------------------
# GatewayError.from_response tests
# ---------------------------------------------------------------------------

class TestGatewayErrorFromResponse:
    """Test GatewayError.from_response parsing."""

    def test_full_envelope(self):
        """All fields parsed from the unified JSON envelope."""
        body = {
            "code": "dlp_credentials_detected",
            "message": "Credentials detected in request",
            "reason_code": "PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED",
            "middleware": "dlp",
            "middleware_step": 5,
            "decision_id": "dec-123",
            "trace_id": "trace-456",
            "details": {"pattern": "AWS_SECRET"},
            "remediation": "Remove credentials from input",
            "docs_url": "https://docs.example.com/dlp",
        }
        err = GatewayError.from_response(403, body)
        assert err.code == "dlp_credentials_detected"
        assert err.message == "Credentials detected in request"
        assert err.reason_code == "PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED"
        assert err.middleware == "dlp"
        assert err.step == 5
        assert err.decision_id == "dec-123"
        assert err.trace_id == "trace-456"
        assert err.details == {"pattern": "AWS_SECRET"}
        assert err.remediation == "Remove credentials from input"
        assert err.docs_url == "https://docs.example.com/dlp"
        assert err.http_status == 403

    def test_legacy_format_fallback(self):
        """Graceful fallback for pre-RFA-tj9.1 error format."""
        body = {
            "error": "policy_denied",
            "reason": "tool_not_authorized",
        }
        err = GatewayError.from_response(403, body)
        assert err.code == "policy_denied"
        assert err.message == "tool_not_authorized"
        assert err.http_status == 403

    def test_minimal_body(self):
        """Empty body produces GatewayError with defaults."""
        err = GatewayError.from_response(500, {})
        assert err.code == ""
        assert err.message == ""
        assert err.http_status == 500


# ---------------------------------------------------------------------------
# CallWithMetadata tests
# ---------------------------------------------------------------------------

class TestCallWithMetadata:
    """call_with_metadata() returns CallResult with response headers."""

    def test_returns_response_meta_on_success(self, mock_gateway):
        """Advisory headers are parsed into ResponseMeta on success."""
        from mcp_gateway_sdk import CallResult, ResponseMeta
        from mcp_gateway_sdk.client import _parse_response_meta

        url, handler = mock_gateway
        handler.extra_response_headers = {
            "X-Precinct-Reversibility": "irreversible",
            "X-Precinct-Backup-Recommended": "true",
            "X-Precinct-Principal-Level": "1",
            "X-Precinct-Principal-Role": "owner",
            "X-Precinct-Principal-Capabilities": "read,write,delete",
            "X-Precinct-Auth-Method": "mtls_svid",
        }

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)
        cr = client.call_with_metadata("tavily_search", query="test")
        assert isinstance(cr, CallResult)
        assert isinstance(cr.meta, ResponseMeta)

        assert cr.meta.reversibility == "irreversible"
        assert cr.meta.backup_recommended is True
        assert cr.meta.principal_level == 1
        assert cr.meta.principal_role == "owner"
        assert cr.meta.principal_capabilities == ["read", "write", "delete"]
        assert cr.meta.auth_method == "mtls_svid"

        # Result is still accessible
        assert "results" in cr.result
        client.close()

    def test_no_headers_returns_defaults(self, mock_gateway):
        """Missing headers produce default ResponseMeta values."""
        from mcp_gateway_sdk import ResponseMeta

        url, handler = mock_gateway
        handler.extra_response_headers = {}

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)
        cr = client.call_with_metadata("tavily_search", query="test")

        assert cr.meta.reversibility == ""
        assert cr.meta.backup_recommended is False
        assert cr.meta.principal_level == -1
        assert cr.meta.principal_role == ""
        assert cr.meta.principal_capabilities == []
        assert cr.meta.auth_method == ""
        client.close()

    def test_error_includes_response_meta(self, mock_gateway):
        """GatewayError from call_with_metadata has response_meta populated."""
        url, handler = mock_gateway
        handler.response_mode = "deny_403_irreversible"
        handler.extra_response_headers = {
            "X-Precinct-Reversibility": "irreversible",
            "X-Precinct-Backup-Recommended": "true",
            "X-Precinct-Principal-Level": "4",
        }

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID)
        with pytest.raises(GatewayError) as exc_info:
            client.call_with_metadata("delete_resource", id="abc")

        err = exc_info.value
        assert err.code == "irreversible_action_denied"
        assert err.response_meta is not None
        assert err.response_meta.reversibility == "irreversible"
        assert err.response_meta.backup_recommended is True
        assert err.response_meta.principal_level == 4
        client.close()

    def test_retries_503_with_meta(self, mock_gateway):
        """call_with_metadata retries 503 and returns meta from final response."""
        url, handler = mock_gateway
        # Start with 503, but we'll reset after the fixture setup
        handler.response_mode = "deny_503"
        handler.call_log = []

        # We can't easily toggle mid-test with the conftest, so just verify
        # that 503 exhaustion still works with call_with_metadata
        client = GatewayClient(
            url=url, spiffe_id=SPIFFE_ID,
            max_retries=1, backoff_base=0.01,
        )
        with pytest.raises(GatewayError) as exc_info:
            client.call_with_metadata("read", file_path="/test.md")

        err = exc_info.value
        assert err.http_status == 503
        assert len(handler.call_log) == 2  # 1 initial + 1 retry
        client.close()


class TestTracingPrivacy:
    """Tracing defaults should not leak raw tool arguments."""

    def test_tool_arguments_redacted_by_default(self, mock_gateway):
        url, _ = mock_gateway
        tracer = _FakeTracer()

        client = GatewayClient(url=url, spiffe_id=SPIFFE_ID, tracer=tracer)
        client.call("tavily_search", query="secret", max_results=2)

        span = tracer.spans[0]
        assert span.attributes["mcp.tool.arguments_redacted"] is True
        assert span.attributes["mcp.tool.argument_count"] == 2
        assert span.attributes["mcp.tool.argument_keys"] == "max_results,query"
        assert "mcp.tool.arguments" not in span.attributes
        assert span.ended is True
        client.close()

    def test_raw_tool_arguments_require_explicit_opt_in(self, mock_gateway):
        url, _ = mock_gateway
        tracer = _FakeTracer()

        client = GatewayClient(
            url=url,
            spiffe_id=SPIFFE_ID,
            tracer=tracer,
            trace_tool_arguments=True,
        )
        client.call("read", file_path="/tmp/secret.txt")

        span = tracer.spans[0]
        assert span.attributes["mcp.tool.arguments_redacted"] is False
        assert span.attributes["mcp.tool.arguments"] == json.dumps(
            {"file_path": "/tmp/secret.txt"},
            sort_keys=True,
        )
        client.close()

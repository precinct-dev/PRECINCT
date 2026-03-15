"""
GatewayClient -- MCP JSON-RPC client for the security gateway.

Consolidates the ~120 lines of duplicated boilerplate from the DSPy and
PydanticAI agents into a single reusable library (RFA-tj9.3).

Usage:
    from mcp_gateway_sdk import GatewayClient, GatewayError

    client = GatewayClient(url="http://localhost:9090",
                           spiffe_id="spiffe://poc.local/agents/example/dev")
    try:
        result = client.call("tavily_search", query="AI security", max_results=5)
        print(result)  # raw MCP JSON-RPC result dict
    except GatewayError as e:
        print(f"Denied: {e.code} - {e.message} (remediation: {e.remediation})")
    finally:
        client.close()
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from .errors import GatewayError

logger = logging.getLogger("mcp_gateway_sdk")

# Defaults for retry logic
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF_BASE = 1.0  # seconds
_DEFAULT_TIMEOUT = 30.0  # seconds


def _is_local_gateway_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").strip().lower()
    return host in {"", "localhost", "127.0.0.1", "::1"}


@dataclass
class ResponseMeta:
    """Security-relevant metadata from gateway response headers.

    These headers are set by the gateway middleware chain and provide
    advisory signals that agent frameworks can use for safer decisions.

    Example::

        result = client.call_with_metadata("delete_resource", id="abc")
        if result.meta.backup_recommended:
            snapshot_state()  # take backup before irreversible action
        print(f"reversibility: {result.meta.reversibility}")
    """

    #: Action classification: "reversible", "costly_reversible",
    #: "partially_reversible", or "irreversible". Empty if not classified.
    reversibility: str = ""

    #: True when the gateway recommends a state snapshot before proceeding.
    backup_recommended: bool = False

    #: Numeric hierarchy level (0=system .. 5=anonymous). -1 if not set.
    principal_level: int = -1

    #: Resolved role name (e.g. "owner", "agent", "external_user").
    principal_role: str = ""

    #: Capabilities granted to this principal.
    principal_capabilities: list[str] = field(default_factory=list)

    #: How the caller was authenticated (e.g. "mtls_svid", "header_declared").
    auth_method: str = ""

    #: All response headers for forward-compatibility.
    raw_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class CallResult:
    """Wraps a successful tool call result together with response metadata.

    Returned by :meth:`GatewayClient.call_with_metadata`.
    """

    #: The JSON-RPC result (same value returned by :meth:`GatewayClient.call`).
    result: Any = None

    #: Security-relevant response headers from the gateway.
    meta: ResponseMeta = field(default_factory=ResponseMeta)


def _parse_response_meta(headers: httpx.Headers) -> ResponseMeta:
    """Extract gateway advisory headers from an HTTP response."""
    caps_raw = headers.get("x-precinct-principal-capabilities", "")
    caps = [c.strip() for c in caps_raw.split(",") if c.strip()] if caps_raw else []

    level = -1
    level_raw = headers.get("x-precinct-principal-level", "")
    if level_raw:
        try:
            level = int(level_raw)
        except ValueError:
            pass

    return ResponseMeta(
        reversibility=headers.get("x-precinct-reversibility", ""),
        backup_recommended=headers.get("x-precinct-backup-recommended", "") == "true",
        principal_level=level,
        principal_role=headers.get("x-precinct-principal-role", ""),
        principal_capabilities=caps,
        auth_method=headers.get("x-precinct-auth-method", ""),
        raw_headers=dict(headers),
    )


class GatewayClient:
    """HTTP client for MCP JSON-RPC calls through the security gateway.

    All tool calls go through the gateway. The ``X-SPIFFE-ID`` header is a
    dev-mode identity assertion; production authentication must come from the
    underlying HTTP transport, such as an mTLS-configured ``httpx.Client``.

    Handles:
      - MCP JSON-RPC envelope construction
      - Required headers (X-SPIFFE-ID, X-Session-ID, Content-Type)
      - Unified error parsing into :class:`GatewayError`
      - Retry logic for 503 with exponential backoff
      - Session ID management (auto-generated UUID if not provided)
      - Optional OTel span creation via ``tracer`` kwarg
    """

    def __init__(
        self,
        url: str,
        spiffe_id: str,
        *,
        session_id: Optional[str] = None,
        tracer: Any = None,
        timeout: float = _DEFAULT_TIMEOUT,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        backoff_base: float = _DEFAULT_BACKOFF_BASE,
        http_client: Optional[httpx.Client] = None,
        trace_tool_arguments: bool = False,
    ) -> None:
        """Create a new GatewayClient.

        Args:
            url:           Gateway base URL (e.g. ``http://localhost:9090``).
            spiffe_id:     SPIFFE identity for X-SPIFFE-ID header in dev mode.
            session_id:    Optional session ID. Auto-generated UUID if omitted.
            tracer:        Optional OpenTelemetry Tracer for span creation.
            timeout:       HTTP request timeout in seconds (default 30).
            max_retries:   Max retry attempts for 503 responses (default 3).
            backoff_base:  Base for exponential backoff in seconds (default 1.0).
            http_client:   Optional preconfigured ``httpx.Client`` for custom
                           transports such as production mTLS.
            trace_tool_arguments:
                           When ``True``, export raw tool arguments in spans.
                           Defaults to ``False`` so sensitive params stay out of telemetry.
        """
        self.url = url
        self.spiffe_id = spiffe_id
        self.session_id = session_id or str(uuid.uuid4())
        self.tracer = tracer
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.trace_tool_arguments = trace_tool_arguments
        self._request_id = 0
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(timeout=timeout)
        if not _is_local_gateway_url(url):
            logger.warning(
                "GatewayClient sends X-SPIFFE-ID only for dev-mode identity. For production gateways, provide an mTLS-configured http_client."
            )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> GatewayClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def call(self, tool_name: str, **params: Any) -> Any:
        """Call a tool through the gateway using MCP-spec tools/call.

        Constructs an MCP JSON-RPC request, sends it to the gateway,
        handles errors (raising :class:`GatewayError` for denials), and
        returns the raw JSON-RPC ``result`` on success.

        Args:
            tool_name: MCP tool name (e.g. ``"tavily_search"``, ``"read"``).
            **params:  Keyword arguments passed as MCP ``params.arguments``.

        Returns:
            The ``result`` field from the JSON-RPC response (dict or value).

        Raises:
            GatewayError: On 4xx/5xx gateway responses or JSON-RPC errors.
            httpx.ConnectError: If the gateway is unreachable.
        """
        span = None
        if self.tracer:
            span_attributes = {
                "mcp.method": "tools/call",
                "mcp.tool.name": tool_name,
                "spiffe.id": self.spiffe_id,
                "session.id": self.session_id,
            }
            if self.trace_tool_arguments:
                span_attributes["mcp.tool.arguments"] = json.dumps(params, sort_keys=True)
                span_attributes["mcp.tool.arguments_redacted"] = False
            else:
                span_attributes["mcp.tool.arguments_redacted"] = True
                span_attributes["mcp.tool.argument_count"] = len(params)
                if params:
                    span_attributes["mcp.tool.argument_keys"] = ",".join(
                        sorted(str(key) for key in params)
                    )
            span = self.tracer.start_span(
                f"gateway.tool_call.{tool_name}",
                attributes=span_attributes,
            )

        try:
            result = self._call_rpc_with_retry(
                method="tools/call",
                params={"name": tool_name, "arguments": params},
                display_name=tool_name,
            )
            if span:
                span.set_attribute("mcp.result.success", True)
            return result
        except GatewayError as exc:
            if span:
                span.set_attribute("mcp.result.success", False)
                span.set_attribute("mcp.error.code", exc.code)
                span.set_attribute("mcp.error.http_status", exc.http_status)
            raise
        except Exception as exc:
            if span:
                span.set_attribute("mcp.result.success", False)
                span.set_attribute("mcp.error", str(exc))
            raise
        finally:
            if span:
                span.end()

    def call_with_metadata(self, tool_name: str, **params: Any) -> CallResult:
        """Call a tool and return both the result and gateway response metadata.

        Like :meth:`call`, but wraps the return in a :class:`CallResult` that
        includes advisory headers (reversibility, principal hierarchy, etc.).

        This is useful when your agent needs to inspect gateway signals to make
        informed decisions -- for example, prompting for confirmation before
        irreversible actions.

        Args:
            tool_name: MCP tool name.
            **params:  Keyword arguments passed as MCP ``params.arguments``.

        Returns:
            :class:`CallResult` with ``.result`` and ``.meta``.

        Raises:
            GatewayError: On denial. The error's ``.response_meta`` is also populated.
        """
        return self._call_rpc_with_retry_meta(
            method="tools/call",
            params={"name": tool_name, "arguments": params},
            display_name=tool_name,
        )

    def call_rpc(self, method: str, params: Optional[dict[str, Any]] = None) -> Any:
        """Call a raw MCP JSON-RPC method through the gateway.

        This is for protocol-level methods like ``tools/list`` or ``resources/read``.
        For tool invocations, prefer :meth:`call`, which uses MCP-spec ``tools/call``.
        """
        return self._call_rpc_with_retry(
            method=method,
            params=params or {},
            display_name=method,
        )

    def call_model_chat(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        provider: str = "groq",
        api_key_ref: Optional[str] = None,
        api_key_header: str = "Authorization",
        endpoint: str = "/openai/v1/chat/completions",
        residency_intent: str = "us",
        budget_profile: str = "standard",
        agent_purpose: Optional[str] = None,
        mission_boundary_mode: Optional[str] = None,
        allowed_intents: Optional[list[str]] = None,
        allowed_topics: Optional[list[str]] = None,
        blocked_topics: Optional[list[str]] = None,
        out_of_scope_action: Optional[str] = None,
        out_of_scope_message: Optional[str] = None,
        extra_headers: Optional[dict[str, str]] = None,
        **extra_payload: Any,
    ) -> Any:
        """Call the gateway's OpenAI-compatible model egress endpoint.

        This helper keeps model calls behind the gateway's model-plane controls
        while preserving a simple SDK interface for agent frameworks.
        """
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            raise ValueError(
                "call_model_chat only supports gateway-relative endpoints; "
                "absolute endpoints are not allowed"
            )

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
        }
        payload.update(extra_payload)

        if endpoint.startswith(("http://", "https://")):
            raise ValueError(
                "call_model_chat only accepts gateway-relative endpoints; "
                "absolute model URLs bypass gateway mediation"
            )
        path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        url = f"{self.url}{path}"
        headers = {
            "Content-Type": "application/json",
            "X-SPIFFE-ID": self.spiffe_id,
            "X-Session-ID": self.session_id,
            "X-Model-Provider": provider,
            "X-Residency-Intent": residency_intent,
            "X-Budget-Profile": budget_profile,
        }
        if api_key_ref:
            headers[api_key_header] = api_key_ref
        if agent_purpose:
            headers["X-Agent-Purpose"] = agent_purpose
        if mission_boundary_mode:
            headers["X-Mission-Boundary-Mode"] = mission_boundary_mode
        if allowed_intents:
            headers["X-Mission-Allowed-Intents"] = ",".join(allowed_intents)
        if allowed_topics:
            headers["X-Mission-Allowed-Topics"] = ",".join(allowed_topics)
        if blocked_topics:
            headers["X-Mission-Blocked-Topics"] = ",".join(blocked_topics)
        if out_of_scope_action:
            headers["X-Mission-Out-Of-Scope-Action"] = out_of_scope_action
        if out_of_scope_message:
            headers["X-Mission-Out-Of-Scope-Message"] = out_of_scope_message
        if extra_headers:
            headers.update(extra_headers)

        resp = self._client.post(url, json=payload, headers=headers)
        if resp.status_code >= 400:
            self._raise_gateway_error(resp)

        try:
            return resp.json()
        except Exception:
            raise GatewayError(
                code="invalid_response",
                message=f"Invalid JSON response (HTTP {resp.status_code}): "
                        f"{resp.text[:200]}",
                http_status=resp.status_code,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_rpc_with_retry_meta(
        self, *, method: str, params: dict[str, Any], display_name: str,
    ) -> CallResult:
        """Execute JSON-RPC call with retry, returning CallResult with metadata."""
        last_exc: Optional[GatewayError] = None
        for attempt in range(self.max_retries + 1):
            try:
                return self._do_call_with_meta(method, params)
            except GatewayError as exc:
                if exc.http_status != 503:
                    raise

                last_exc = exc
                if attempt < self.max_retries:
                    backoff = self.backoff_base * (2 ** attempt)
                    logger.warning(
                        "RPC %s returned 503 (attempt %d/%d). Retrying in %.1fs.",
                        display_name, attempt + 1, self.max_retries + 1, backoff,
                    )
                    time.sleep(backoff)

        assert last_exc is not None
        raise last_exc

    def _do_call_with_meta(self, method: str, params: dict[str, Any]) -> CallResult:
        """Execute a single MCP JSON-RPC call, returning result + metadata."""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._next_id(),
        }
        headers = {
            "Content-Type": "application/json",
            "X-SPIFFE-ID": self.spiffe_id,
            "X-Session-ID": self.session_id,
        }

        resp = self._client.post(self.url, json=payload, headers=headers)
        meta = _parse_response_meta(resp.headers)

        if resp.status_code >= 400:
            self._raise_gateway_error_with_meta(resp, meta)

        try:
            body = resp.json()
        except Exception:
            raise GatewayError(
                code="invalid_response",
                message=f"Invalid JSON response (HTTP {resp.status_code}): "
                        f"{resp.text[:200]}",
                http_status=resp.status_code,
            )

        if "error" in body:
            err = body["error"]
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            raise GatewayError(
                code="jsonrpc_error",
                message=f"JSON-RPC error: {msg}",
                http_status=resp.status_code,
            )

        return CallResult(result=body.get("result", body), meta=meta)

    def _raise_gateway_error_with_meta(
        self, resp: httpx.Response, meta: ResponseMeta,
    ) -> None:
        """Parse gateway error and raise GatewayError with response_meta populated."""
        try:
            body = resp.json()
            if isinstance(body, dict):
                exc = GatewayError.from_response(resp.status_code, body)
                exc.response_meta = meta
                raise exc
            exc = GatewayError(
                code="unknown", message=str(body), http_status=resp.status_code,
            )
            exc.response_meta = meta
            raise exc
        except GatewayError:
            raise
        except Exception:
            exc = GatewayError(
                code="unknown",
                message=resp.text[:200] if resp.text else f"HTTP {resp.status_code}",
                http_status=resp.status_code,
            )
            exc.response_meta = meta
            raise exc

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _call_rpc_with_retry(self, *, method: str, params: dict[str, Any], display_name: str) -> Any:
        """Execute JSON-RPC call with retry logic for 503 responses."""
        last_exc: Optional[GatewayError] = None
        for attempt in range(self.max_retries + 1):
            try:
                return self._do_call(method, params)
            except GatewayError as exc:
                if exc.http_status != 503:
                    raise  # Non-retryable -- propagate immediately

                last_exc = exc
                if attempt < self.max_retries:
                    backoff = self.backoff_base * (2 ** attempt)
                    logger.warning(
                        "RPC %s returned 503 (attempt %d/%d). "
                        "Retrying in %.1fs. Code: %s",
                        display_name,
                        attempt + 1,
                        self.max_retries + 1,
                        backoff,
                        exc.code,
                    )
                    time.sleep(backoff)
                else:
                    logger.error(
                        "RPC %s returned 503 after %d attempts. Giving up. "
                        "Code: %s",
                        display_name,
                        self.max_retries + 1,
                        exc.code,
                    )

        # All retries exhausted -- raise the last 503 error
        assert last_exc is not None  # guaranteed by loop logic
        raise last_exc

    def _do_call(self, method: str, params: dict[str, Any]) -> Any:
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
            "X-Session-ID": self.session_id,
        }

        resp = self._client.post(self.url, json=payload, headers=headers)

        # Handle HTTP-level errors (denials, rate limits, etc.)
        if resp.status_code >= 400:
            self._raise_gateway_error(resp)

        # Parse JSON-RPC response
        try:
            body = resp.json()
        except Exception:
            raise GatewayError(
                code="invalid_response",
                message=f"Invalid JSON response (HTTP {resp.status_code}): "
                        f"{resp.text[:200]}",
                http_status=resp.status_code,
            )

        # Check for JSON-RPC error
        if "error" in body:
            err = body["error"]
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            raise GatewayError(
                code="jsonrpc_error",
                message=f"JSON-RPC error: {msg}",
                http_status=resp.status_code,
            )

        return body.get("result", body)

    def _raise_gateway_error(self, resp: httpx.Response) -> None:
        """Parse gateway error response and raise GatewayError."""
        try:
            body = resp.json()
            if isinstance(body, dict):
                raise GatewayError.from_response(resp.status_code, body)
            # Non-dict JSON (e.g. string)
            raise GatewayError(
                code="unknown",
                message=str(body),
                http_status=resp.status_code,
            )
        except GatewayError:
            raise
        except Exception:
            # Non-JSON response body
            raise GatewayError(
                code="unknown",
                message=resp.text[:200] if resp.text else f"HTTP {resp.status_code}",
                http_status=resp.status_code,
            )

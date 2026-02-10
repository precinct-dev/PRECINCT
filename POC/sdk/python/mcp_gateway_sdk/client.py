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
from typing import Any, Optional

import httpx

from .errors import GatewayError

logger = logging.getLogger("mcp_gateway_sdk")

# Defaults for retry logic
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF_BASE = 1.0  # seconds
_DEFAULT_TIMEOUT = 30.0  # seconds


class GatewayClient:
    """HTTP client for MCP JSON-RPC calls through the security gateway.

    All tool calls go through the gateway. Authenticates with the
    ``X-SPIFFE-ID`` header (dev-mode identity assertion).

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
    ) -> None:
        """Create a new GatewayClient.

        Args:
            url:           Gateway base URL (e.g. ``http://localhost:9090``).
            spiffe_id:     SPIFFE identity for X-SPIFFE-ID header.
            session_id:    Optional session ID. Auto-generated UUID if omitted.
            tracer:        Optional OpenTelemetry Tracer for span creation.
            timeout:       HTTP request timeout in seconds (default 30).
            max_retries:   Max retry attempts for 503 responses (default 3).
            backoff_base:  Base for exponential backoff in seconds (default 1.0).
        """
        self.url = url
        self.spiffe_id = spiffe_id
        self.session_id = session_id or str(uuid.uuid4())
        self.tracer = tracer
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self._request_id = 0
        self._client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        """Close the underlying HTTP client."""
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
            span = self.tracer.start_span(
                f"gateway.tool_call.{tool_name}",
                attributes={
                    "mcp.method": "tools/call",
                    "mcp.tool.name": tool_name,
                    "mcp.tool.arguments": json.dumps(params),
                    "spiffe.id": self.spiffe_id,
                    "session.id": self.session_id,
                },
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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

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

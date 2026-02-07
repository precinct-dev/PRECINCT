"""
Integration tests for mcp-gateway-sdk.

These tests run against the REAL gateway (compose stack).
They verify:
  - SDK can call a tool through the real gateway and get a response
  - SDK correctly parses denial responses from real OPA policy
  - GatewayError contains the unified JSON envelope fields

Run with: pytest tests/test_integration.py -v -m integration
Requires: docker compose stack running (make up)
"""

import os
import pathlib

import httpx
import pytest

from mcp_gateway_sdk import GatewayClient, GatewayError

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:9090")
SPIFFE_ID_PYDANTIC = "spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev"
SPIFFE_ID_DSPY = "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
POC_DIR = os.environ.get(
    "POC_DIR",
    str(pathlib.Path(__file__).resolve().parent.parent.parent.parent),
)


@pytest.fixture(scope="module")
def check_gateway_health():
    """Skip integration tests if gateway is not running."""
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


@pytest.mark.integration
class TestSDKIntegration:
    """Integration tests running against the real compose stack."""

    def test_file_read_success(self, check_gateway_health):
        """SDK reads a file through the real gateway successfully."""
        with GatewayClient(url=GATEWAY_URL, spiffe_id=SPIFFE_ID_PYDANTIC) as client:
            result = client.call("read", file_path=f"{POC_DIR}/docker-compose.yml")

        assert result is not None
        assert isinstance(result, dict) or isinstance(result, list)

    def test_denied_tool_raises_gateway_error(self, check_gateway_health):
        """Calling an unauthorized tool raises GatewayError with parsed fields."""
        with GatewayClient(url=GATEWAY_URL, spiffe_id=SPIFFE_ID_PYDANTIC) as client:
            with pytest.raises(GatewayError) as exc_info:
                client.call("bash", command="echo hello")

        err = exc_info.value
        # Should be denied (403) -- bash requires step-up
        assert err.http_status in (403, 401)
        # Unified envelope fields should be populated
        assert err.code != ""

    def test_invalid_spiffe_id_raises_gateway_error(self, check_gateway_health):
        """Invalid SPIFFE ID produces a 401 GatewayError."""
        with GatewayClient(url=GATEWAY_URL, spiffe_id="not-a-valid-id") as client:
            with pytest.raises(GatewayError) as exc_info:
                client.call("read", file_path=f"{POC_DIR}/docker-compose.yml")

        err = exc_info.value
        assert err.http_status == 401

    def test_search_through_gateway(self, check_gateway_health):
        """SDK sends a search request through the real gateway.

        Tavily may not be configured, so we accept either success or a
        clean GatewayError (not a crash).
        """
        with GatewayClient(url=GATEWAY_URL, spiffe_id=SPIFFE_ID_DSPY) as client:
            try:
                result = client.call(
                    "tavily_search",
                    query="AI security frameworks",
                    max_results=2,
                )
                # If we get here, the search succeeded
                assert result is not None
            except GatewayError:
                # Tavily not configured or rate limited -- acceptable
                pass

    def test_context_manager_with_real_gateway(self, check_gateway_health):
        """Context manager protocol works with real gateway."""
        with GatewayClient(url=GATEWAY_URL, spiffe_id=SPIFFE_ID_PYDANTIC) as client:
            result = client.call("read", file_path=f"{POC_DIR}/Makefile")
        assert result is not None

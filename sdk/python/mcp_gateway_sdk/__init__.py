"""
mcp-gateway-sdk -- Python SDK for agent-gateway integration.

Provides a minimal, framework-independent client for calling MCP tools
through the security gateway. Works with PydanticAI, DSPy, LangGraph,
CrewAI, or raw HTTP.

Identity is asserted with the ``X-SPIFFE-ID`` header for local/dev gateway
workflows. Production SPIFFE mTLS transport is not implemented in this SDK.

Usage:
    from mcp_gateway_sdk import GatewayClient, GatewayError

    client = GatewayClient(url="http://localhost:9090",
                           spiffe_id="spiffe://poc.local/agents/example/dev")
    try:
        result = client.call("tavily_search", query="AI security")
    except GatewayError as e:
        print(f"Denied: {e.code} -- {e.remediation}")
    finally:
        client.close()
"""

from .client import CallResult, GatewayClient, ResponseMeta
from .errors import GatewayError
from .runtime import (
    build_dspy_gateway_lm,
    build_spike_token_ref,
    configure_dspy_gateway_lms,
    load_dotenv,
    normalize_model_name,
    resolve_model_api_key_ref,
    setup_observability,
)

__all__ = [
    "CallResult",
    "GatewayClient",
    "GatewayError",
    "ResponseMeta",
    "build_dspy_gateway_lm",
    "build_spike_token_ref",
    "configure_dspy_gateway_lms",
    "load_dotenv",
    "normalize_model_name",
    "resolve_model_api_key_ref",
    "setup_observability",
]
__version__ = "0.1.0"

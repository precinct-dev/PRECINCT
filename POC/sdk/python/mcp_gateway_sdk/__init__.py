"""
mcp-gateway-sdk -- Python SDK for agent-gateway integration.

Provides a minimal, framework-independent client for calling MCP tools
through the security gateway. Works with PydanticAI, DSPy, LangGraph,
CrewAI, or raw HTTP.

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

from .client import GatewayClient
from .errors import GatewayError

__all__ = ["GatewayClient", "GatewayError"]
__version__ = "0.1.0"

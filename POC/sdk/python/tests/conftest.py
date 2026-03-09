"""
Shared test fixtures for mcp-gateway-sdk tests.

Provides a mock gateway HTTP server that can simulate:
  - Normal MCP JSON-RPC responses
  - 403 policy denials (unified JSON envelope from RFA-tj9.1)
  - 503 service unavailable (retryable)
  - 401 authentication failures
  - 429 rate limiting
"""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

import pytest


class MockGatewayHandler(BaseHTTPRequestHandler):
    """Mock gateway simulating the unified JSON error envelope."""

    # Class-level config -- tests set these before making requests.
    response_mode = "normal"  # normal | deny_403 | deny_503 | deny_401 | deny_429 | deny_403_irreversible | normal_with_meta
    call_log: list[dict] = []
    # Extra response headers to inject (set by tests).
    extra_response_headers: dict[str, str] = {}

    @staticmethod
    def _extract_tool(request_data: dict) -> tuple[str, dict]:
        method = request_data.get("method", "")
        params = request_data.get("params", {}) or {}
        if method == "tools/call":
            tool_name = params.get("name", "")
            args = params.get("arguments", {}) or {}
            if not isinstance(args, dict):
                args = {}
            return tool_name, args
        return method, params if isinstance(params, dict) else {}

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        request_data = json.loads(body) if body else {}
        tool_name, tool_params = self._extract_tool(request_data)
        spiffe_id = self.headers.get("X-SPIFFE-ID", "")
        session_id = self.headers.get("X-Session-ID", "")

        MockGatewayHandler.call_log.append({
            "path": self.path,
            "method": request_data.get("method", ""),
            "params": request_data.get("params", {}),
            "tool_name": tool_name,
            "tool_params": tool_params,
            "spiffe_id": spiffe_id,
            "session_id": session_id,
            "authorization": self.headers.get("Authorization", ""),
            "model_provider": self.headers.get("X-Model-Provider", ""),
            "id": request_data.get("id"),
            "jsonrpc": request_data.get("jsonrpc"),
        })

        if MockGatewayHandler.response_mode == "deny_401":
            self._send_json(401, {
                "code": "auth_missing_identity",
                "message": "Missing or invalid X-SPIFFE-ID header",
                "middleware": "spiffe_auth",
                "middleware_step": 1,
                "decision_id": "dec-test-001",
                "trace_id": "trace-test-001",
            })
            return

        if MockGatewayHandler.response_mode == "deny_403":
            self._send_json(403, {
                "code": "authz_policy_denied",
                "message": "OPA policy denied access to tool",
                "middleware": "opa_authz",
                "middleware_step": 3,
                "decision_id": "dec-test-002",
                "trace_id": "trace-test-002",
                "remediation": "Request access via admin portal",
                "details": {"tool": tool_name},
            })
            return

        if MockGatewayHandler.response_mode == "deny_503":
            self._send_json(503, {
                "code": "circuit_open",
                "message": "Circuit breaker is open -- service unavailable",
                "middleware": "circuit_breaker",
                "middleware_step": 7,
                "decision_id": "dec-test-003",
                "trace_id": "trace-test-003",
            })
            return

        if MockGatewayHandler.response_mode == "deny_403_irreversible":
            self._send_json(403, {
                "code": "irreversible_action_denied",
                "message": "Irreversible action denied for external principal",
                "middleware": "step_up_gating",
                "middleware_step": 9,
                "decision_id": "dec-test-irrev",
                "trace_id": "trace-test-irrev",
            })
            return

        if MockGatewayHandler.response_mode == "deny_429":
            self._send_json(429, {
                "code": "ratelimit_exceeded",
                "message": "Rate limit exceeded for this identity",
                "middleware": "rate_limiter",
                "middleware_step": 2,
                "decision_id": "dec-test-004",
                "trace_id": "trace-test-004",
                "remediation": "Reduce request frequency or request a quota increase",
            })
            return

        # Normal mode -- return a mock MCP JSON-RPC response
        if tool_name == "tavily_search":
            result = {
                "results": [
                    {
                        "title": "AI Security Best Practices",
                        "url": "https://example.com/ai-security",
                        "content": "Key findings about AI security frameworks.",
                    }
                ]
            }
        elif tool_name == "read":
            result = {
                "content": "# Reference Document\nSample content for testing."
            }
        else:
            result = {"status": "ok"}

        response = {
            "jsonrpc": "2.0",
            "result": result,
            "id": request_data.get("id", 1),
        }
        self._send_json(200, response)

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        self.send_response(404)
        self.end_headers()

    def _send_json(self, status: int, body: dict) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in MockGatewayHandler.extra_response_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, format, *args):
        pass  # Suppress request logs in tests


@pytest.fixture
def mock_gateway():
    """Start a mock gateway server and yield (url, handler_class).

    Resets response_mode to "normal" and clears the call log.
    """
    MockGatewayHandler.response_mode = "normal"
    MockGatewayHandler.call_log = []
    MockGatewayHandler.extra_response_headers = {}
    server = HTTPServer(("127.0.0.1", 0), MockGatewayHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", MockGatewayHandler
    server.shutdown()

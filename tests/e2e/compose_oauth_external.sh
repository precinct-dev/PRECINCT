#!/usr/bin/env sh
set -eu

COMPOSE_NETWORK="${COMPOSE_NETWORK:-agentic-security-network}"
GATEWAY_URL="${GATEWAY_URL:-http://precinct-gateway:9090}"
MOCK_OAUTH_ISSUER_URL="${MOCK_OAUTH_ISSUER_URL:-http://mock-oauth-issuer:8088}"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-slim}"

docker run --rm -i \
  --network "${COMPOSE_NETWORK}" \
  -e GATEWAY_URL="${GATEWAY_URL}" \
  -e MOCK_OAUTH_ISSUER_URL="${MOCK_OAUTH_ISSUER_URL}" \
  "${PYTHON_IMAGE}" \
  python -u - <<'PY'
import json
import os
import urllib.request

issuer = os.environ["MOCK_OAUTH_ISSUER_URL"]
gateway = os.environ["GATEWAY_URL"]

def request(url, method="GET", data=None, headers=None):
    body = None
    if data is not None:
        body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status, dict(resp.headers), resp.read().decode()

status, _, body = request(issuer + "/health")
assert status == 200, ("issuer health", status, body)

status, _, body = request(gateway + "/health")
assert status == 200, ("gateway health", status, body)

status, _, body = request(
    issuer + "/token",
    "POST",
    {
        "client_id": "acct",
        "subject": "external-compose",
        "scope": "mcp:tools",
        "audience": "gateway",
        "ttl_seconds": 180,
    },
    {"Content-Type": "application/json"},
)
assert status == 200, ("token", status, body)
token = json.loads(body)["access_token"]

headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token,
}

status, init_headers, body = request(
    gateway,
    "POST",
    {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "oauth-e2e", "version": "1.0.0"},
        },
        "id": 1,
    },
    headers,
)
assert status == 200, ("initialize", status, body)
assert init_headers.get("X-Mock-Authorization") == "<none>", init_headers
assert init_headers.get("X-Mock-Precinct-Auth-Method") == "oauth_jwt", init_headers
session_id = init_headers.get("Mcp-Session-Id")
assert session_id, init_headers

notify_headers = dict(headers)
notify_headers["Mcp-Session-Id"] = session_id
status, _, body = request(
    gateway,
    "POST",
    {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
    notify_headers,
)
assert status == 200, ("notifications/initialized", status, body)

status, list_headers, body = request(
    gateway,
    "POST",
    {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 2},
    notify_headers,
)
assert status == 200, ("tools/list", status, body)
assert list_headers.get("X-Mock-Authorization") == "<none>", list_headers
assert list_headers.get("X-Mock-Precinct-Auth-Method") == "oauth_jwt", list_headers
parsed = json.loads(body)
assert parsed.get("error") is None, parsed
assert "tavily_search" in body, body

print("compose oauth e2e PASS")
print("session_id=" + session_id)
print("x_mock_authorization=" + list_headers.get("X-Mock-Authorization", ""))
print("x_mock_precinct_auth_method=" + list_headers.get("X-Mock-Precinct-Auth-Method", ""))
PY

#!/usr/bin/env bash
# Compose Egress Lock Check (RFA-545e.2)
#
# Proves that containers attached only to the demo/agent network cannot reach the
# public Internet, but can still reach the gateway by service name.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/deploy/compose/docker-compose.yml"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

pass() {
  echo "[PASS] $1"
}

if ! command -v docker >/dev/null 2>&1; then
  fail "docker not found"
fi
if ! command -v jq >/dev/null 2>&1; then
  fail "jq not found"
fi

cfg_json="$(docker compose -f "${COMPOSE_FILE}" config --format json)"

internal="$(echo "${cfg_json}" | jq -r '.networks["agentic-net"].internal // false')"
if [ "${internal}" != "true" ]; then
  fail "agentic-net must be internal=true to block public egress (got: ${internal})"
fi
pass "agentic-net is internal=true"

# Runtime proof (assumes stack is up)
pass "Runtime connectivity checks (from agentic-security-network)"

docker run --rm --network agentic-security-network curlimages/curl:8.6.0 \
  -sSf --max-time 3 "http://mcp-security-gateway:9090/health" >/dev/null
pass "Gateway is reachable from agentic-security-network"

if docker run --rm --network agentic-security-network curlimages/curl:8.6.0 \
  -sSf --max-time 5 "https://example.com" >/dev/null 2>&1; then
  fail "Public Internet egress is allowed from agentic-security-network (should be blocked)"
fi
pass "Public Internet egress is blocked from agentic-security-network"

echo ""
echo "compose_egress_lock_check: PASS"


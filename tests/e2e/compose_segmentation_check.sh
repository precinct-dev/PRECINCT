#!/usr/bin/env bash
# Compose Segmentation Check (RFA-545e.1)
#
# Verifies that tool-plane services are not reachable from the demo/agent network
# and that only the gateway is dual-homed into the tool-plane.

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

get_service() {
  local name="$1"
  echo "${cfg_json}" | jq -e --arg svc "${name}" '.services[$svc]' >/dev/null 2>&1 ||
    fail "service '${name}' not present in compose config"
  echo "${cfg_json}" | jq -c --arg svc "${name}" '.services[$svc]'
}

assert_no_ports() {
  local svc="$1"
  local s
  s="$(get_service "${svc}")"
  local ports_len
  ports_len="$(echo "${s}" | jq -r '(.ports // []) | length')"
  if [ "${ports_len}" != "0" ]; then
    fail "${svc} must not publish host ports (ports_len=${ports_len})"
  fi
  pass "${svc} publishes no host ports"
}

assert_not_on_network() {
  local svc="$1"
  local net="$2"
  local s
  s="$(get_service "${svc}")"
  if echo "${s}" | jq -e --arg net "${net}" '(.networks // {}) | has($net)' >/dev/null 2>&1; then
    fail "${svc} must not be attached to network '${net}'"
  fi
  pass "${svc} is not attached to '${net}'"
}

assert_on_network() {
  local svc="$1"
  local net="$2"
  local s
  s="$(get_service "${svc}")"
  if ! echo "${s}" | jq -e --arg net "${net}" '(.networks // {}) | has($net)' >/dev/null 2>&1; then
    fail "${svc} must be attached to network '${net}'"
  fi
  pass "${svc} is attached to '${net}'"
}

pass "Rendered compose config loaded"

# Static invariants
assert_no_ports "mock-mcp-server"
assert_no_ports "mock-guard-model"
assert_not_on_network "mock-mcp-server" "agentic-net"
assert_not_on_network "mock-guard-model" "agentic-net"
assert_on_network "precinct-gateway" "agentic-net"
assert_on_network "precinct-gateway" "tool-plane"

# Runtime proof (assumes stack is up)
pass "Runtime connectivity checks (from agentic-security-network)"

docker run --rm --network agentic-security-network curlimages/curl:8.6.0 \
  -sSf --max-time 3 "http://precinct-gateway:9090/health" >/dev/null
pass "Gateway is reachable from agentic-security-network"

if docker run --rm --network agentic-security-network curlimages/curl:8.6.0 \
  -sSf --max-time 3 "http://mock-mcp-server:8082/health" >/dev/null 2>&1; then
  fail "mock-mcp-server is reachable from agentic-security-network (should be isolated)"
fi
pass "mock-mcp-server is NOT reachable from agentic-security-network"

if docker run --rm --network agentic-security-network curlimages/curl:8.6.0 \
  -sSf --max-time 3 "http://mock-guard-model:8080/health" >/dev/null 2>&1; then
  fail "mock-guard-model is reachable from agentic-security-network (should be isolated)"
fi
pass "mock-guard-model is NOT reachable from agentic-security-network"

echo ""
echo "compose_segmentation_check: PASS"

#!/usr/bin/env bash
# ensure-stack.sh -- Ensure the Docker Compose stack is healthy
#
# Usage:
#   ensure-stack.sh [--resilient]
#
# Steps:
#   1. Check phoenix-observability-network; run `make phoenix-up` if missing
#   2. Run compose-health-check.sh; if unhealthy, run `make up`
#   3. With --resilient: tolerate non-zero from `make up` if services are actually healthy
#
# Exit 0 = stack is healthy
# Exit 1 = stack could not be brought healthy

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESILIENT=0
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --resilient) RESILIENT=1; shift ;;
    *)           echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

host_port_reachable() {
  local port="$1"
  (echo >"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1
}

has_stale_spike_state() {
  local nexus_logs gateway_logs
  nexus_logs="$(docker compose -f "$ROOT_DIR/deploy/compose/docker-compose.yml" -f "$ROOT_DIR/deploy/compose/docker-compose.mock.yml" --profile mock logs spike-nexus --tail=200 2>/dev/null || true)"
  gateway_logs="$(docker compose -f "$ROOT_DIR/deploy/compose/docker-compose.yml" -f "$ROOT_DIR/deploy/compose/docker-compose.mock.yml" --profile mock logs precinct-gateway --tail=80 2>/dev/null || true)"
  if printf '%s\n%s\n' "$nexus_logs" "$gateway_logs" | rg -q 'crypto_decryption_failed|cipher: message authentication failed'; then
    return 0
  fi
  return 1
}

reset_stale_spike_state() {
  echo "Detected stale SPIKE encrypted state. Resetting compose stack and spike-nexus volume for a clean test bootstrap..."
  make -C "$ROOT_DIR" down >/dev/null 2>&1 || true
  docker volume rm -f spike-nexus-data >/dev/null 2>&1 || true
  mkdir -p "$ROOT_DIR/deploy/compose/data/spire-agent-socket" "$ROOT_DIR/deploy/compose/data/spire-agent"
  chmod 777 "$ROOT_DIR/deploy/compose/data/spire-agent-socket" "$ROOT_DIR/deploy/compose/data/spire-agent"
  find "$ROOT_DIR/deploy/compose/data/spire-agent-socket" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
}

ensure_host_access() {
  local gateway_recreated=0

  if ! host_port_reachable 6379; then
    echo "WARN: KeyDB host port 6379 is not reachable. Integration tests will fall back to compose://keydb."
  fi

  if ! host_port_reachable 9090; then
    echo "Gateway host port 9090 is not reachable. Recreating precinct-gateway to restore host access..."
    docker compose -f deploy/compose/docker-compose.yml up -d --force-recreate precinct-gateway >/dev/null
    gateway_recreated=1
  fi

  if [ "$gateway_recreated" -eq 1 ]; then
    if ! bash "$SCRIPT_DIR/compose-health-check.sh"; then
      echo "ERROR: services are not healthy after host-access recovery."
      exit 1
    fi
  fi
}

# Step 1: Ensure phoenix network exists
if ! docker network inspect phoenix-observability-network >/dev/null 2>&1; then
  echo "Phoenix network not found. Running make phoenix-up..."
  make -C "$SCRIPT_DIR/.." phoenix-up
fi

# Step 2: Check service health
if bash "$SCRIPT_DIR/compose-health-check.sh"; then
  ensure_host_access
  echo "Core services already running and healthy. Skipping make up."
  exit 0
fi

echo "Core services not fully healthy. Running make up..."

if [ "$RESILIENT" -eq 0 ]; then
  make -C "$SCRIPT_DIR/.." up
else
  if ! make -C "$SCRIPT_DIR/.." up; then
    echo "make up returned non-zero. Re-checking service health..."
    if has_stale_spike_state; then
      reset_stale_spike_state
      make -C "$ROOT_DIR" up
    fi
    if ! bash "$SCRIPT_DIR/compose-health-check.sh"; then
      echo "ERROR: services are not healthy after make up."
      exit 1
    fi
    echo "Services are healthy despite make up non-zero; continuing."
  fi
  if has_stale_spike_state; then
    reset_stale_spike_state
    make -C "$ROOT_DIR" up
  fi
fi

ensure_host_access

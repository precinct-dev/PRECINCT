#!/usr/bin/env bash
# compose-health-check.sh -- Check Docker Compose service health
#
# Usage:
#   compose-health-check.sh [--verbose] [--services "svc1 svc2 ..."]
#
# Exit 0 = all required services running and healthy
# Exit 1 = one or more services not ready
#
# --verbose   Print each failing service (diagnostic mode)
# --services  Override default service list (space-separated, quoted)

set -euo pipefail

VERBOSE=0
SERVICES="keydb mcp-security-gateway mock-guard-model mock-mcp-server spire-server spire-agent spike-nexus spike-keeper-1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verbose)  VERBOSE=1; shift ;;
    --services) SERVICES="$2"; shift 2 ;;
    *)          echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose/docker-compose.yml}"
ps_out="$(docker compose -f "$COMPOSE_FILE" ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null || true)"

healthy=1
for s in $SERVICES; do
  line="$(printf '%s\n' "$ps_out" | awk -v svc="$s" '$1==svc {print}')"
  state="$(printf '%s\n' "$line" | awk '{print $2}')"
  health="$(printf '%s\n' "$line" | awk '{print $3}')"
  if [ -z "$line" ] || [ "$state" != "running" ] || { [ -n "$health" ] && [ "$health" != "healthy" ]; }; then
    healthy=0
    if [ "$VERBOSE" -eq 1 ]; then
      echo "  Not ready: $s (state=$state health=$health)"
    else
      break
    fi
  fi
done

exit $(( 1 - healthy ))

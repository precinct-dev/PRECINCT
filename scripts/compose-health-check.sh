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
# Service list adapts to DEMO_SERVICE_MODE: real mode checks for tavily-mcp-server
# instead of mock services. Content-scanner is in both modes.
if [ "${DEMO_SERVICE_MODE:-mock}" = "real" ]; then
  SERVICES="keydb precinct-gateway precinct-control tavily-mcp-server content-scanner spire-server spire-agent spike-nexus spike-keeper-1"
else
  SERVICES="keydb precinct-gateway precinct-control mock-guard-model mock-mcp-server content-scanner spire-server spire-agent spike-nexus spike-keeper-1"
fi

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

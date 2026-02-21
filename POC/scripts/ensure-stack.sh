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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --resilient) RESILIENT=1; shift ;;
    *)           echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

# Step 1: Ensure phoenix network exists
if ! docker network inspect phoenix-observability-network >/dev/null 2>&1; then
  echo "Phoenix network not found. Running make phoenix-up..."
  make -C "$SCRIPT_DIR/.." phoenix-up
fi

# Step 2: Check service health
if bash "$SCRIPT_DIR/compose-health-check.sh"; then
  echo "Core services already running and healthy. Skipping make up."
  exit 0
fi

echo "Core services not fully healthy. Running make up..."

if [ "$RESILIENT" -eq 0 ]; then
  make -C "$SCRIPT_DIR/.." up
else
  if ! make -C "$SCRIPT_DIR/.." up; then
    echo "make up returned non-zero. Re-checking service health..."
    if ! bash "$SCRIPT_DIR/compose-health-check.sh"; then
      echo "ERROR: services are not healthy after make up."
      exit 1
    fi
    echo "Services are healthy despite make up non-zero; continuing."
  fi
fi

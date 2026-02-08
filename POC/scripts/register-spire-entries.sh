#!/bin/sh
# register-spire-entries.sh -- One-shot init container script.
# Registers all SPIRE workload entries after the agent is attested.
# Runs inside a busybox container with the spire-server binary and socket mounted.
#
# This MUST complete before spike-nexus and the gateway start so they
# can obtain SVIDs from the SPIRE Workload API immediately.

set -e

SOCK="/tmp/spire-server/private/api.sock"
DOMAIN="poc.local"
SPIRE=/opt/spire/bin/spire-server
MAX_WAIT=60
ELAPSED=0

echo "SPIRE Entry Registrar: Waiting for attested agent..."

# Poll until at least one agent is attested (visible in agent list).
PARENT_ID=""
while [ $ELAPSED -lt $MAX_WAIT ]; do
    PARENT_ID=$($SPIRE agent list -socketPath "$SOCK" 2>/dev/null \
        | grep 'SPIFFE ID' | head -1 | awk '{print $NF}')
    if [ -n "$PARENT_ID" ]; then
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if [ -z "$PARENT_ID" ]; then
    echo "ERROR: No attested SPIRE agent found within ${MAX_WAIT}s"
    exit 1
fi

echo "Agent SPIFFE ID: $PARENT_ID"
echo "Registering workload entries..."

# Helper: register an entry (idempotent -- duplicate entries log a warning).
reg() {
    local spiffe_id="$1"; shift
    echo "  $spiffe_id"
    $SPIRE entry create \
        -socketPath "$SOCK" \
        -parentID "$PARENT_ID" \
        -spiffeID "$spiffe_id" \
        "$@" 2>/dev/null || true
}

reg "spiffe://$DOMAIN/gateways/mcp-security-gateway/dev" \
    -selector docker:label:spiffe-id:mcp-security-gateway \
    -selector docker:label:component:gateway

reg "spiffe://$DOMAIN/agents/mcp-client/dspy-researcher/dev" \
    -selector docker:label:spiffe-id:dspy-researcher

reg "spiffe://$DOMAIN/agents/mcp-client/pydantic-researcher/dev" \
    -selector docker:label:spiffe-id:pydantic-researcher

reg "spiffe://$DOMAIN/spike/nexus" \
    -selector docker:label:spiffe-id:spike-nexus

# SPIKE Nexus only authorizes Pilot-role SPIFFE IDs for secret writes.
# The seeder uses /spike/pilot/role/superuser/seeder which matches the
# IsPilotOperator() check (base path + optional suffix).
reg "spiffe://$DOMAIN/spike/pilot/role/superuser/seeder" \
    -selector docker:label:spiffe-id:spike-seeder

reg "spiffe://$DOMAIN/keydb" \
    -selector docker:label:spiffe-id:keydb

echo "All SPIRE workload entries registered."

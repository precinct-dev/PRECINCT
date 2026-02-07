#!/bin/bash
# SPIRE Registration Script for POC Workloads
# Creates workload registration entries in SPIRE server
# Based on Reference Architecture Section 4.5 and config/spiffe-ids.yaml
#
# This script is idempotent - it checks for existing entries before creating new ones.
# It can be run inside the SPIRE server container or via docker compose exec.

set -euo pipefail

# Configuration
TRUST_DOMAIN="poc.local"
SPIRE_SERVER_SOCKET="${SPIRE_SERVER_SOCKET:-/run/spire/sockets/registration.sock}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Check if an entry already exists
entry_exists() {
    local spiffe_id="$1"
    spire-server entry show \
        -socketPath "${SPIRE_SERVER_SOCKET}" \
        -spiffeID "${spiffe_id}" 2>/dev/null | grep -q "SPIFFE ID" || return 1
}

# Create a SPIRE entry if it doesn't exist
create_entry() {
    local spiffe_id="$1"
    local parent_id="$2"
    shift 2
    local selectors=("$@")

    if entry_exists "${spiffe_id}"; then
        log_warn "Entry already exists: ${spiffe_id}"
        return 0
    fi

    log_info "Creating entry: ${spiffe_id}"

    # Build selector arguments
    local selector_args=()
    for selector in "${selectors[@]}"; do
        selector_args+=(-selector "${selector}")
    done

    spire-server entry create \
        -socketPath "${SPIRE_SERVER_SOCKET}" \
        -spiffeID "${spiffe_id}" \
        -parentID "${parent_id}" \
        "${selector_args[@]}"

    if [ $? -eq 0 ]; then
        log_info "Successfully created: ${spiffe_id}"
    else
        log_error "Failed to create: ${spiffe_id}"
        return 1
    fi
}

# Main registration logic
main() {
    log_info "Starting SPIRE entry registration for POC workloads"
    log_info "Trust Domain: ${TRUST_DOMAIN}"
    log_info "SPIRE Server Socket: ${SPIRE_SERVER_SOCKET}"

    # Parent SPIFFE ID for all workloads (SPIRE agent)
    # In Docker Compose, this is the SPIRE agent that attests workload containers
    local parent_id="spiffe://${TRUST_DOMAIN}/spire/agent/docker"

    # Create parent agent entry if it doesn't exist
    # This represents the SPIRE agent running on the Docker host
    if ! entry_exists "${parent_id}"; then
        log_info "Creating parent SPIRE agent entry"
        spire-server entry create \
            -socketPath "${SPIRE_SERVER_SOCKET}" \
            -spiffeID "${parent_id}" \
            -parentID "spiffe://${TRUST_DOMAIN}/spire/server" \
            -selector "unix:uid:0" \
            -node

        if [ $? -ne 0 ]; then
            log_error "Failed to create parent agent entry"
            exit 1
        fi
    fi

    log_info "Registering workload entries..."
    echo ""

    # 1. MCP Security Gateway
    create_entry \
        "spiffe://${TRUST_DOMAIN}/gateways/mcp-security-gateway/dev" \
        "${parent_id}" \
        "docker:label:spiffe-id:mcp-security-gateway" \
        "docker:label:component:gateway"

    echo ""

    # 2. DSPy Research Agent
    create_entry \
        "spiffe://${TRUST_DOMAIN}/agents/mcp-client/dspy-researcher/dev" \
        "${parent_id}" \
        "docker:label:spiffe-id:dspy-researcher" \
        "docker:label:agent-type:mcp-client" \
        "docker:label:framework:dspy"

    echo ""

    # 3. PydanticAI Research Agent
    create_entry \
        "spiffe://${TRUST_DOMAIN}/agents/mcp-client/pydantic-researcher/dev" \
        "${parent_id}" \
        "docker:label:spiffe-id:pydantic-researcher" \
        "docker:label:agent-type:mcp-client" \
        "docker:label:framework:pydantic-ai"

    echo ""

    # 4. Docker MCP Tool Server
    create_entry \
        "spiffe://${TRUST_DOMAIN}/tools/docker-mcp-server/dev" \
        "${parent_id}" \
        "docker:label:spiffe-id:docker-mcp-server" \
        "docker:label:component:mcp-server" \
        "docker:label:tool-type:docker"

    echo ""

    # 5. SPIKE Nexus Secrets Server (RFA-a2y.1)
    create_entry \
        "spiffe://${TRUST_DOMAIN}/spike/nexus" \
        "${parent_id}" \
        "docker:label:spiffe-id:spike-nexus"

    echo ""

    # 6. SPIKE Bootstrap Init Container (RFA-a2y.1)
    create_entry \
        "spiffe://${TRUST_DOMAIN}/spike/bootstrap" \
        "${parent_id}" \
        "docker:label:spiffe-id:spike-bootstrap"

    echo ""

    # 7. KeyDB Session Store (RFA-8z8.2)
    # KeyDB uses filesystem-based certs (cannot use Workload API directly).
    # The keydb-svid-init container fetches the SVID and writes PEM files.
    create_entry \
        "spiffe://${TRUST_DOMAIN}/keydb" \
        "${parent_id}" \
        "docker:label:spiffe-id:keydb"

    echo ""
    log_info "Registration complete!"
    echo ""

    # Show all registered entries
    log_info "Listing all registered entries:"
    spire-server entry show \
        -socketPath "${SPIRE_SERVER_SOCKET}" \
        | grep -E "(Entry ID|SPIFFE ID|Parent ID|Selector)" || true
}

# Entry point
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi

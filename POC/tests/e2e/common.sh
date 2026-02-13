#!/usr/bin/env bash
# E2E Validation Common Utilities - RFA-70p
# Shared functions for all E2E validation scenarios

set -euo pipefail

# ---- Terminal colors (ANSI, not emoji) ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---- Configuration ----
GATEWAY_URL="${GATEWAY_URL:-http://localhost:9090}"
PHOENIX_URL="${PHOENIX_URL:-http://localhost:6006}"
OTEL_URL="${OTEL_URL:-http://localhost:4318}"

# POC directory - resolved from env var or discovered from script location.
# The e2e scripts live in tests/e2e/ so the POC root is two levels up.
POC_DIR="${POC_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

# Default test SPIFFE ID (DSPy researcher agent)
DEFAULT_SPIFFE_ID="spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
# Secondary agent for cross-agent tests
SECONDARY_SPIFFE_ID="spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev"

# ---- Results tracking ----
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
RESULTS_LOG=""

# ---- Output helpers ----
log_header() {
    echo ""
    echo -e "${BOLD}=========================================${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}=========================================${NC}"
    echo ""
}

log_subheader() {
    echo -e "${CYAN}--- $1 ---${NC}"
}

log_pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    RESULTS_LOG="${RESULTS_LOG}PASS: $1\n"
    echo -e "  [${GREEN}PASS${NC}] $1"
}

log_fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    RESULTS_LOG="${RESULTS_LOG}FAIL: $1 -- $2\n"
    echo -e "  [${RED}FAIL${NC}] $1"
    echo -e "         Reason: $2"
}

log_skip() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    RESULTS_LOG="${RESULTS_LOG}SKIP: $1 -- $2\n"
    echo -e "  [${YELLOW}SKIP${NC}] $1"
    echo -e "         Reason: $2"
}

log_info() {
    echo -e "  [${CYAN}INFO${NC}] $1"
}

log_detail() {
    echo "         $1"
}

# ---- HTTP request helpers ----

# Make a tool call to the gateway and capture both body and HTTP status
# Usage: gateway_request SPIFFE_ID METHOD_OR_TOOL PARAMS_JSON [EXTRA_HEADERS...]
# Sets: RESP_BODY, RESP_CODE
gateway_request() {
    local spiffe_id="$1"
    local tool_method="$2"
    local params_json="$3"
    shift 3

    local extra_headers=()
    while [ $# -gt 0 ]; do
        extra_headers+=(-H "$1")
        shift
    done

    local full_response
    full_response=$(curl -s -w "\n%{http_code}" -X POST "${GATEWAY_URL}/" \
        -H "Content-Type: application/json" \
        -H "X-SPIFFE-ID: ${spiffe_id}" \
        "${extra_headers[@]}" \
        -d "{
            \"jsonrpc\": \"2.0\",
            \"method\": \"${tool_method}\",
            \"params\": ${params_json},
            \"id\": 1
        }" 2>&1) || true

    RESP_CODE=$(echo "$full_response" | tail -n1)
        # Use sed instead of head -n -1 for macOS compatibility
    RESP_BODY=$(echo "$full_response" | sed '$d')
}

# Make a raw POST to a specific path
# Usage: gateway_post PATH BODY_JSON SPIFFE_ID
# Sets: RESP_BODY, RESP_CODE
gateway_post() {
    local path="$1"
    local body="$2"
    local spiffe_id="${3:-$DEFAULT_SPIFFE_ID}"

    local full_response
    full_response=$(curl -s -w "\n%{http_code}" -X POST "${GATEWAY_URL}${path}" \
        -H "Content-Type: application/json" \
        -H "X-SPIFFE-ID: ${spiffe_id}" \
        -d "$body" 2>&1) || true

    RESP_CODE=$(echo "$full_response" | tail -n1)
        # Use sed instead of head -n -1 for macOS compatibility
    RESP_BODY=$(echo "$full_response" | sed '$d')
}

# Make a raw GET to a specific path
# Usage: gateway_get PATH [SPIFFE_ID]
# Sets: RESP_BODY, RESP_CODE
gateway_get() {
    local path="$1"
    local spiffe_id="${2:-$DEFAULT_SPIFFE_ID}"

    local full_response
    full_response=$(curl -s -w "\n%{http_code}" -X GET "${GATEWAY_URL}${path}" \
        -H "X-SPIFFE-ID: ${spiffe_id}" 2>&1) || true

    RESP_CODE=$(echo "$full_response" | tail -n1)
    RESP_BODY=$(echo "$full_response" | sed '$d')
}

# ---- Gateway log helpers ----

# Get the last N lines of gateway logs
gateway_logs() {
    local count="${1:-20}"
    docker compose logs --tail "$count" mcp-security-gateway 2>/dev/null | grep -v "^mcp-security-gateway" || true
}

# Get gateway logs containing a specific field/value
gateway_logs_grep() {
    local pattern="$1"
    local count="${2:-50}"
    docker compose logs --tail "$count" mcp-security-gateway 2>/dev/null | grep "$pattern" || true
}

# ---- Service health helpers ----

check_service_healthy() {
    local service="$1"
    local status
    status=$(docker compose ps --format '{{.Status}}' "$service" 2>/dev/null || echo "not found")
    if echo "$status" | grep -qi "healthy\|Up"; then
        return 0
    fi
    return 1
}

# ---- Summary ----
print_summary() {
    local total=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))
    echo ""
    log_header "Results Summary"
    echo -e "  Total checks: ${total}"
    echo -e "  ${GREEN}PASS${NC}: ${PASS_COUNT}"
    echo -e "  ${RED}FAIL${NC}: ${FAIL_COUNT}"
    echo -e "  ${YELLOW}SKIP${NC}: ${SKIP_COUNT}"
    echo ""

    if [ "$FAIL_COUNT" -gt 0 ]; then
        echo -e "${RED}Some checks failed. See details above.${NC}"
        return 1
    elif [ "$SKIP_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}All executed checks passed, but some were skipped.${NC}"
        return 0
    else
        echo -e "${GREEN}All checks passed.${NC}"
        return 0
    fi
}

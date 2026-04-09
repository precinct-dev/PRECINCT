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
resolve_control_url() {
    if [ -n "${CONTROL_URL:-}" ]; then
        echo "$CONTROL_URL"
        return
    fi

    case "$GATEWAY_URL" in
        *://precinct-gateway:9090)
            echo "${GATEWAY_URL/precinct-gateway:9090/precinct-control:9090}"
            ;;
        *://localhost:9090)
            echo "${GATEWAY_URL/localhost:9090/localhost:9091}"
            ;;
        *://127.0.0.1:9090)
            echo "${GATEWAY_URL/127.0.0.1:9090/127.0.0.1:9091}"
            ;;
        *)
            echo "$GATEWAY_URL"
            ;;
    esac
}
CONTROL_URL="$(resolve_control_url)"
PHOENIX_URL="${PHOENIX_URL:-http://localhost:6006}"
OTEL_URL="${OTEL_URL:-http://localhost:4318}"

# Project root - resolved from env var or discovered from script location.
# The e2e scripts live in tests/e2e/ so the project root is two levels up.
POC_DIR="${POC_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

# Docker Compose command with explicit compose file
COMPOSE_FILE="${POC_DIR}/deploy/compose/docker-compose.yml"
DC="docker compose -f ${COMPOSE_FILE}"

# Resolve the effective OPA allowlist base path used by the running gateway.
# Priority: explicit env override -> container ALLOWED_BASE_PATH -> container workdir.
resolve_gateway_allowed_base_path() {
    if [ -n "${GATEWAY_ALLOWED_BASE_PATH:-}" ]; then
        echo "$GATEWAY_ALLOWED_BASE_PATH"
        return
    fi

    local base_path=""
    local container_env=""
    container_env=$(docker inspect precinct-gateway --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null || true)
    if [ -n "$container_env" ]; then
        base_path=$(echo "$container_env" | awk -F= '/^ALLOWED_BASE_PATH=/{print substr($0, index($0, "=") + 1); exit}')
    fi

    if [ -z "$base_path" ]; then
        base_path=$(docker inspect precinct-gateway --format '{{.Config.WorkingDir}}' 2>/dev/null || true)
    fi

    if [ -z "$base_path" ]; then
        base_path="/app"
    fi

    echo "$base_path"
}

GATEWAY_ALLOWED_BASE_PATH="$(resolve_gateway_allowed_base_path)"

gateway_allowed_file_path() {
    local relative_path="${1:-go.mod}"
    local base_path="${GATEWAY_ALLOWED_BASE_PATH%/}"
    local rel_path="${relative_path#/}"
    echo "${base_path}/${rel_path}"
}

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

    local curl_args=(
        -s
        -w "\n%{http_code}"
        -X POST "${GATEWAY_URL}/"
        -H "Content-Type: application/json"
        -H "X-SPIFFE-ID: ${spiffe_id}"
    )

    if [ ${#extra_headers[@]} -gt 0 ]; then
        curl_args+=("${extra_headers[@]}")
    fi

    curl_args+=(
        -d "{
            \"jsonrpc\": \"2.0\",
            \"method\": \"${tool_method}\",
            \"params\": ${params_json},
            \"id\": 1
        }"
    )

    local full_response
    full_response=$(curl "${curl_args[@]}" 2>&1) || true

    RESP_CODE=$(echo "$full_response" | tail -n1)
        # Use sed instead of head -n -1 for macOS compatibility
    RESP_BODY=$(echo "$full_response" | sed '$d')
}

# Make a raw POST to a specific path
# Usage: gateway_post PATH BODY_JSON SPIFFE_ID
# Sets: RESP_BODY, RESP_CODE
is_control_path() {
    local path="$1"
    case "$path" in
        /admin|/admin/*|/v1/connectors/*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

request_base_url_for_path() {
    local path="$1"
    if is_control_path "$path"; then
        echo "$CONTROL_URL"
        return
    fi
    echo "$GATEWAY_URL"
}

gateway_post() {
    local path="$1"
    local body="$2"
    local spiffe_id="${3:-$DEFAULT_SPIFFE_ID}"
    local base_url
    base_url="$(request_base_url_for_path "$path")"

    local full_response
    full_response=$(curl -s -w "\n%{http_code}" -X POST "${base_url}${path}" \
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
    local base_url
    base_url="$(request_base_url_for_path "$path")"

    local full_response
    full_response=$(curl -s -w "\n%{http_code}" -X GET "${base_url}${path}" \
        -H "X-SPIFFE-ID: ${spiffe_id}" 2>&1) || true

    RESP_CODE=$(echo "$full_response" | tail -n1)
    RESP_BODY=$(echo "$full_response" | sed '$d')
}

# ---- Gateway log helpers ----

# Get the last N lines of gateway logs
gateway_logs() {
    local count="${1:-20}"
    $DC logs --tail "$count" precinct-gateway 2>/dev/null | grep -v "^precinct-gateway" || true
}

# Get gateway logs containing a specific field/value
gateway_logs_grep() {
    local pattern="$1"
    local count="${2:-50}"
    $DC logs --tail "$count" precinct-gateway 2>/dev/null | grep "$pattern" || true
}

# ---- Service health helpers ----

check_service_healthy() {
    local service="$1"
    local status
    status=$($DC ps --format '{{.Status}}' "$service" 2>/dev/null || echo "not found")
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

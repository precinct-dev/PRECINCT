#!/usr/bin/env bash
# test_x509pop_restart.sh -- Integration test: x509pop compose restart resilience
#
# Verifies the full compose stack starts, stops, and restarts with x509pop
# attestation working correctly across the cycle. This proves the attestation
# migration from join_token to x509pop works end-to-end.
#
# Usage:
#   bash tests/e2e/test_x509pop_restart.sh
#   make test-x509pop-restart

set -euo pipefail

# ---- Configuration -------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_DIR="${REPO_ROOT}/deploy/compose"
COMPOSE_FILE="${COMPOSE_DIR}/docker-compose.yml"
DC="docker compose -f ${COMPOSE_FILE}"

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Timeout guard: 10 minutes
TIMEOUT_SECONDS=600
START_TIME=$(date +%s)

# ---- Helpers --------------------------------------------------------------

log_header() {
    echo ""
    echo -e "${BOLD}=========================================${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}=========================================${NC}"
    echo ""
}

log_info() {
    echo -e "  [${CYAN}INFO${NC}] $1"
}

log_pass() {
    echo -e "  [${GREEN}PASS${NC}] $1"
}

log_fail() {
    echo -e "  [${RED}FAIL${NC}] $1"
    if [ -n "${2:-}" ]; then
        echo -e "         Reason: $2"
    fi
}

log_warn() {
    echo -e "  [${YELLOW}WARN${NC}] $1"
}

check_timeout() {
    local now
    now=$(date +%s)
    local elapsed=$(( now - START_TIME ))
    if [ "$elapsed" -ge "$TIMEOUT_SECONDS" ]; then
        log_fail "Timeout guard exceeded (${TIMEOUT_SECONDS}s)"
        echo ""
        echo -e "${RED}FAIL${NC}: Test aborted after ${elapsed}s (limit: ${TIMEOUT_SECONDS}s)"
        exit 1
    fi
}

# wait_for_condition LABEL MAX_ATTEMPTS SLEEP_SECONDS COMMAND...
# Retries COMMAND up to MAX_ATTEMPTS times with SLEEP_SECONDS between attempts.
# Returns 0 on success, 1 on exhaustion.
wait_for_condition() {
    local label="$1"
    local max_attempts="$2"
    local sleep_seconds="$3"
    shift 3

    local attempt=1
    while [ "$attempt" -le "$max_attempts" ]; do
        check_timeout
        if "$@" 2>/dev/null; then
            return 0
        fi
        log_info "${label}: attempt ${attempt}/${max_attempts} -- retrying in ${sleep_seconds}s..."
        sleep "$sleep_seconds"
        attempt=$(( attempt + 1 ))
    done
    return 1
}

# Check if SPIRE server container is healthy via Docker health status
spire_server_healthy() {
    local health
    health=$(docker inspect --format='{{.State.Health.Status}}' spire-server 2>/dev/null || echo "none")
    [ "$health" = "healthy" ]
}

# Check if SPIRE agent container is healthy via Docker health status
spire_agent_healthy() {
    local health
    health=$(docker inspect --format='{{.State.Health.Status}}' spire-agent 2>/dev/null || echo "none")
    [ "$health" = "healthy" ]
}

# Check if gateway container is healthy via Docker health status
gateway_healthy() {
    local health
    health=$(docker inspect --format='{{.State.Health.Status}}' precinct-gateway 2>/dev/null || echo "none")
    [ "$health" = "healthy" ]
}

# Check if spike-nexus container is healthy via Docker health status
spike_nexus_healthy() {
    local health
    health=$(docker inspect --format='{{.State.Health.Status}}' spike-nexus 2>/dev/null || echo "none")
    [ "$health" = "healthy" ]
}

# Get the SPIRE agent list output from the server
get_agent_list() {
    $DC exec -T spire-server /opt/spire/bin/spire-server agent list 2>/dev/null
}

# Verify an agent with x509pop SPIFFE ID exists
verify_x509pop_agent() {
    local agent_output
    agent_output=$(get_agent_list)
    if echo "$agent_output" | grep -q "x509pop"; then
        return 0
    fi
    return 1
}

# Verify no join_token references in agent list
verify_no_join_token() {
    local agent_output
    agent_output=$(get_agent_list)
    if echo "$agent_output" | grep -qi "join_token"; then
        return 1
    fi
    return 0
}

# Check gateway processes requests (HTTP response from health or MCP endpoint)
verify_gateway_responds() {
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:9090/healthz" 2>/dev/null || echo "000")
    # Accept any non-zero HTTP response (gateway is listening and processing)
    [ "$code" != "000" ] && [ "$code" != "" ]
}

# Check for join_token warnings in SPIRE logs
check_no_join_token_logs() {
    local server_logs agent_logs
    server_logs=$($DC logs spire-server 2>/dev/null || true)
    agent_logs=$($DC logs spire-agent 2>/dev/null || true)
    # Look specifically for join_token attestor warnings/errors (not just any mention)
    if echo "$server_logs" | grep -i "join.token" | grep -iE "warn|error|fail" 2>/dev/null; then
        return 1
    fi
    if echo "$agent_logs" | grep -i "join.token" | grep -iE "warn|error|fail" 2>/dev/null; then
        return 1
    fi
    return 0
}

# ---- Tracking -------------------------------------------------------------

PASS_COUNT=0
FAIL_COUNT=0

record_pass() {
    PASS_COUNT=$(( PASS_COUNT + 1 ))
    log_pass "$1"
}

record_fail() {
    FAIL_COUNT=$(( FAIL_COUNT + 1 ))
    log_fail "$1" "${2:-}"
}

# ---- Main Test Flow -------------------------------------------------------

log_header "x509pop Compose Restart Resilience Test"
log_info "Timeout guard: ${TIMEOUT_SECONDS}s"
log_info "Compose file: ${COMPOSE_FILE}"

# ===========================================================================
# Phase 1: Clean Start
# ===========================================================================

log_header "Phase 1: Clean Start"

log_info "Running 'make clean' to ensure pristine state..."
make -C "${REPO_ROOT}" clean 2>&1 | tail -5
log_info "Clean complete."

# Verify x509pop certs were removed by clean
if [ -f "${COMPOSE_DIR}/data/x509pop/agent.crt" ]; then
    record_fail "make clean did not remove x509pop certs"
else
    log_info "Confirmed: x509pop certs removed by clean."
fi

log_info "Running 'make up' (will auto-generate x509pop certs)..."
make -C "${REPO_ROOT}" up 2>&1 | tail -20
log_info "'make up' complete."

# Verify certs were generated
if [ -f "${COMPOSE_DIR}/data/x509pop/agent.crt" ] && [ -f "${COMPOSE_DIR}/data/x509pop/ca-bundle.crt" ]; then
    record_pass "x509pop certificates auto-generated by 'make up'"
else
    record_fail "x509pop certificates not found after 'make up'" "Expected agent.crt and ca-bundle.crt in ${COMPOSE_DIR}/data/x509pop/"
fi

check_timeout

# --- Verify initial attestation ---

log_info "Waiting for SPIRE server to become healthy..."
if wait_for_condition "SPIRE server health" 30 5 spire_server_healthy; then
    record_pass "SPIRE server healthy after clean start"
else
    record_fail "SPIRE server not healthy after clean start" "Timed out waiting for spire-server health check"
fi

log_info "Waiting for SPIRE agent to become healthy..."
if wait_for_condition "SPIRE agent health" 30 5 spire_agent_healthy; then
    record_pass "SPIRE agent healthy after clean start"
else
    record_fail "SPIRE agent not healthy after clean start" "Timed out waiting for spire-agent health check"
fi

check_timeout

log_info "Waiting for SPIRE agent to appear in agent list with x509pop..."
if wait_for_condition "x509pop agent attestation" 20 5 verify_x509pop_agent; then
    record_pass "SPIRE agent attested with x509pop (initial start)"
    # Show the agent list for proof
    log_info "Agent list:"
    get_agent_list | head -20 | while IFS= read -r line; do
        echo "         $line"
    done
else
    record_fail "SPIRE agent not attested with x509pop" "Agent list does not contain x509pop SPIFFE ID"
    log_info "Agent list output for debugging:"
    (get_agent_list 2>&1 || true) | head -20 | while IFS= read -r line; do
        echo "         $line"
    done
fi

log_info "Checking for absence of join_token in agent list..."
if verify_no_join_token; then
    record_pass "No join_token references in SPIRE agent list"
else
    record_fail "Found join_token references in SPIRE agent list" "Expected only x509pop attestation"
fi

log_info "Waiting for gateway to become healthy..."
if wait_for_condition "Gateway health" 20 5 gateway_healthy; then
    record_pass "Gateway healthy after clean start"
else
    record_fail "Gateway not healthy after clean start" "Timed out waiting for precinct-gateway health check"
fi

log_info "Waiting for SPIKE Nexus to become healthy..."
if wait_for_condition "SPIKE Nexus health" 20 5 spike_nexus_healthy; then
    record_pass "SPIKE Nexus healthy after clean start"
else
    record_fail "SPIKE Nexus not healthy after clean start" "Timed out waiting for spike-nexus health check"
fi

check_timeout

# Record cert fingerprint to verify persistence across restart
CERT_FINGERPRINT_BEFORE=""
if [ -f "${COMPOSE_DIR}/data/x509pop/agent.crt" ]; then
    CERT_FINGERPRINT_BEFORE=$(openssl x509 -in "${COMPOSE_DIR}/data/x509pop/agent.crt" -fingerprint -noout 2>/dev/null || echo "unknown")
    log_info "Certificate fingerprint (before restart): ${CERT_FINGERPRINT_BEFORE}"
fi

# ===========================================================================
# Phase 2: Stop (preserving data)
# ===========================================================================

log_header "Phase 2: Stop Containers (preserving data)"

log_info "Running 'docker compose down' (no -v flag, preserving volumes and certs)..."
$DC down --remove-orphans 2>&1 | tail -10
log_info "Compose stack stopped."

# Verify certs persist after down
if [ -f "${COMPOSE_DIR}/data/x509pop/agent.crt" ]; then
    record_pass "x509pop certificates persist after 'docker compose down'"
else
    record_fail "x509pop certificates lost after 'docker compose down'" "Certs should survive non-volume teardown"
fi

check_timeout

# ===========================================================================
# Phase 3: Restart (without clean)
# ===========================================================================

log_header "Phase 3: Restart Without Clean"

log_info "Running 'make up' (should NOT regenerate certs)..."
make -C "${REPO_ROOT}" up 2>&1 | tail -20
log_info "'make up' complete (restart)."

# Verify certs were NOT regenerated (same fingerprint)
CERT_FINGERPRINT_AFTER=""
if [ -f "${COMPOSE_DIR}/data/x509pop/agent.crt" ]; then
    CERT_FINGERPRINT_AFTER=$(openssl x509 -in "${COMPOSE_DIR}/data/x509pop/agent.crt" -fingerprint -noout 2>/dev/null || echo "unknown")
    log_info "Certificate fingerprint (after restart): ${CERT_FINGERPRINT_AFTER}"
fi

if [ -n "$CERT_FINGERPRINT_BEFORE" ] && [ "$CERT_FINGERPRINT_BEFORE" = "$CERT_FINGERPRINT_AFTER" ]; then
    record_pass "Certificates reused on restart (not regenerated)"
else
    record_fail "Certificate fingerprint changed on restart" "Before: ${CERT_FINGERPRINT_BEFORE}, After: ${CERT_FINGERPRINT_AFTER}"
fi

check_timeout

# --- Verify re-attestation ---

log_info "Waiting for SPIRE server to become healthy after restart..."
if wait_for_condition "SPIRE server health (restart)" 30 5 spire_server_healthy; then
    record_pass "SPIRE server healthy after restart"
else
    record_fail "SPIRE server not healthy after restart"
fi

log_info "Waiting for SPIRE agent to become healthy after restart..."
if wait_for_condition "SPIRE agent health (restart)" 30 5 spire_agent_healthy; then
    record_pass "SPIRE agent healthy after restart"
else
    record_fail "SPIRE agent not healthy after restart"
fi

check_timeout

log_info "Waiting for SPIRE agent to re-attest with x509pop..."
if wait_for_condition "x509pop agent re-attestation" 20 5 verify_x509pop_agent; then
    record_pass "SPIRE agent re-attested with x509pop after restart"
    log_info "Agent list (after restart):"
    get_agent_list | head -20 | while IFS= read -r line; do
        echo "         $line"
    done
else
    record_fail "SPIRE agent did not re-attest with x509pop after restart"
    log_info "Agent list output for debugging:"
    (get_agent_list 2>&1 || true) | head -20 | while IFS= read -r line; do
        echo "         $line"
    done
fi

log_info "Checking for absence of join_token after restart..."
if verify_no_join_token; then
    record_pass "No join_token references in SPIRE agent list after restart"
else
    record_fail "Found join_token references after restart" "Migration to x509pop should eliminate all join_token usage"
fi

log_info "Waiting for gateway to become healthy after restart..."
if wait_for_condition "Gateway health (restart)" 20 5 gateway_healthy; then
    record_pass "Gateway healthy after restart"
else
    record_fail "Gateway not healthy after restart"
fi

log_info "Verifying gateway processes requests after restart..."
if wait_for_condition "Gateway responds (restart)" 10 3 verify_gateway_responds; then
    record_pass "Gateway processes HTTP requests after restart"
else
    record_fail "Gateway does not respond to HTTP requests after restart"
fi

log_info "Waiting for SPIKE Nexus to become healthy after restart..."
if wait_for_condition "SPIKE Nexus health (restart)" 20 5 spike_nexus_healthy; then
    record_pass "SPIKE Nexus healthy after restart"
else
    record_fail "SPIKE Nexus not healthy after restart"
fi

check_timeout

# --- Check logs for join_token warnings ---

log_info "Checking SPIRE logs for join_token-related warnings..."
if check_no_join_token_logs; then
    record_pass "No join_token-related warnings in SPIRE logs"
else
    record_fail "Found join_token-related warnings in SPIRE logs" "Logs contain join_token warn/error messages"
fi

# ===========================================================================
# Phase 4: Cleanup
# ===========================================================================

log_header "Phase 4: Cleanup"

log_info "Running 'make clean' to leave environment tidy..."
make -C "${REPO_ROOT}" clean 2>&1 | tail -5
log_info "Cleanup complete."

# ===========================================================================
# Summary
# ===========================================================================

ELAPSED=$(( $(date +%s) - START_TIME ))

log_header "Test Results"
echo -e "  Total checks: $(( PASS_COUNT + FAIL_COUNT ))"
echo -e "  ${GREEN}PASS${NC}: ${PASS_COUNT}"
echo -e "  ${RED}FAIL${NC}: ${FAIL_COUNT}"
echo -e "  Elapsed: ${ELAPSED}s (limit: ${TIMEOUT_SECONDS}s)"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}FAIL${NC}: ${FAIL_COUNT} check(s) failed."
    exit 1
else
    echo -e "${GREEN}PASS${NC}: All checks passed. x509pop restart resilience verified."
    exit 0
fi

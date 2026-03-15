#!/bin/bash
# Integration Test: SPIRE Registration
# Tests that all expected SPIFFE IDs are registered in SPIRE server

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TRUST_DOMAIN="poc.local"
TESTS_PASSED=0
TESTS_FAILED=0

# Expected SPIFFE IDs from config/spiffe-ids.yaml
EXPECTED_SPIFFE_IDS=(
    "spiffe://${TRUST_DOMAIN}/gateways/mcp-security-gateway/dev"
    "spiffe://${TRUST_DOMAIN}/agents/mcp-client/dspy-researcher/dev"
    "spiffe://${TRUST_DOMAIN}/agents/mcp-client/pydantic-researcher/dev"
    "spiffe://${TRUST_DOMAIN}/tools/docker-mcp-server/dev"
    "spiffe://${TRUST_DOMAIN}/infrastructure/spike-nexus/dev"
)

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    ((TESTS_FAILED++))
}

# Test if SPIRE server is accessible
test_spire_server_accessible() {
    log_info "Testing SPIRE server accessibility..."

    if docker compose exec -T spire-server spire-server healthcheck 2>/dev/null; then
        log_pass "SPIRE server is accessible"
        return 0
    else
        log_fail "SPIRE server is not accessible"
        return 1
    fi
}

# Test if registration script can be executed
test_registration_script_exists() {
    log_info "Checking registration script..."

    if [ -f "./scripts/register-spire-entries.sh" ] && [ -x "./scripts/register-spire-entries.sh" ]; then
        log_pass "Registration script exists and is executable"
        return 0
    else
        log_fail "Registration script not found or not executable"
        return 1
    fi
}

# Run the registration script
test_run_registration() {
    log_info "Running SPIRE registration script..."

    if docker compose exec -T spire-server bash < ./scripts/register-spire-entries.sh; then
        log_pass "Registration script executed successfully"
        return 0
    else
        log_fail "Registration script failed"
        return 1
    fi
}

# Verify each expected SPIFFE ID is registered
test_spiffe_id_registered() {
    local spiffe_id="$1"

    if docker compose exec -T spire-server spire-server entry show \
        -spiffeID "${spiffe_id}" 2>/dev/null | grep -q "SPIFFE ID"; then
        log_pass "SPIFFE ID registered: ${spiffe_id}"
        return 0
    else
        log_fail "SPIFFE ID NOT registered: ${spiffe_id}"
        return 1
    fi
}

# Test that gateway can obtain SVID
test_gateway_svid() {
    log_info "Testing gateway SVID retrieval (requires running containers)..."

    # This test would require the gateway container to be running
    # and the SPIRE agent to be operational
    # For now, we'll check if the entry exists and has proper selectors

    local output
    output=$(docker compose exec -T spire-server spire-server entry show \
        -spiffeID "spiffe://${TRUST_DOMAIN}/gateways/mcp-security-gateway/dev" 2>/dev/null || echo "")

    if echo "${output}" | grep -q "docker:label:spiffe-id:mcp-security-gateway"; then
        log_pass "Gateway entry has correct Docker label selectors"
        return 0
    else
        log_fail "Gateway entry missing Docker label selectors"
        return 1
    fi
}

# Test idempotency - running registration twice should not fail
test_idempotency() {
    log_info "Testing registration script idempotency..."

    # Run registration a second time
    if docker compose exec -T spire-server bash < ./scripts/register-spire-entries.sh 2>&1 | grep -q "already exists"; then
        log_pass "Registration script is idempotent (detected existing entries)"
        return 0
    else
        log_fail "Registration script idempotency check unclear"
        return 1
    fi
}

# Main test execution
main() {
    log_info "Starting SPIRE registration integration tests"
    log_info "Trust Domain: ${TRUST_DOMAIN}"
    echo ""

    # Prerequisite checks
    test_spire_server_accessible || exit 1
    test_registration_script_exists || exit 1
    echo ""

    # Run registration
    test_run_registration
    echo ""

    # Verify all expected SPIFFE IDs
    log_info "Verifying registered SPIFFE IDs..."
    for spiffe_id in "${EXPECTED_SPIFFE_IDS[@]}"; do
        test_spiffe_id_registered "${spiffe_id}"
    done
    echo ""

    # Additional tests
    test_gateway_svid
    echo ""

    test_idempotency
    echo ""

    # Summary
    echo "========================================"
    log_info "Test Summary"
    echo "  Passed: ${TESTS_PASSED}"
    echo "  Failed: ${TESTS_FAILED}"
    echo "========================================"

    if [ "${TESTS_FAILED}" -eq 0 ]; then
        log_info "All tests passed!"
        return 0
    else
        log_error "Some tests failed!"
        return 1
    fi
}

# Entry point
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi

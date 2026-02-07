#!/usr/bin/env bash
# =============================================================================
# Integration Test: Setup Wizard (RFA-tj9.2)
#
# Tests the setup wizard with piped inputs to verify:
#   1. Default inputs generate correct .env
#   2. Custom inputs generate correct .env
#   3. Security posture summary is generated
#   4. Prerequisite checks run
#
# Usage: bash tests/integration/setup_wizard_test.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SETUP_SCRIPT="${POC_DIR}/scripts/setup.sh"

# ---- Terminal colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

test_pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "  [${GREEN}PASS${NC}] $1"
}

test_fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "  [${RED}FAIL${NC}] $1"
    echo "         Reason: $2"
}

echo ""
echo -e "${BOLD}=========================================${NC}"
echo -e "${BOLD}  Setup Wizard Integration Tests${NC}"
echo -e "${BOLD}=========================================${NC}"
echo ""

# =============================================================================
# Test 1: Default inputs produce secure .env
# =============================================================================

echo -e "${CYAN}--- Test 1: Default inputs (all Enter) ---${NC}"
echo ""

# Back up existing .env
if [ -f "${POC_DIR}/.env" ]; then
    cp "${POC_DIR}/.env" "${POC_DIR}/.env.bak.test"
fi

# Pipe all defaults (Enter for every question) plus "n" to skip starting services.
# The wizard asks 5 questions:
#   Q1: fallback policy (default: 1 = fail_closed)
#   Q2: GROQ API key (default: skip)
#   Q3: KeyDB (default: Y)
#   Q4: SPIFFE mode (default: 1 = dev)
#   Q5: Start services? (we say n to avoid starting docker in test)
printf '\n\n\n\n\nn\n' | bash "$SETUP_SCRIPT" 2>&1 | head -200 > /tmp/setup_wizard_test_output.txt || {
    # If wizard exits non-zero due to prereq failure, that is a valid test too
    # but we still want to check the output
    true
}

# Check if .env was generated
if [ -f "${POC_DIR}/.env" ]; then
    test_pass ".env file generated"
else
    test_fail ".env file generation" "File not found at ${POC_DIR}/.env"
fi

# Verify default values in .env
if grep -q "DEEP_SCAN_FALLBACK=fail_closed" "${POC_DIR}/.env" 2>/dev/null; then
    test_pass ".env has DEEP_SCAN_FALLBACK=fail_closed (secure default)"
else
    test_fail "DEEP_SCAN_FALLBACK default" "Expected fail_closed in .env"
fi

if grep -q "GROQ_API_KEY=$" "${POC_DIR}/.env" 2>/dev/null || grep -q "GROQ_API_KEY=\s*$" "${POC_DIR}/.env" 2>/dev/null; then
    test_pass ".env has empty GROQ_API_KEY (skipped by default)"
else
    ENV_GROQ=$(grep "GROQ_API_KEY" "${POC_DIR}/.env" 2>/dev/null || echo "NOT_FOUND")
    test_fail "GROQ_API_KEY default" "Expected empty value, found: ${ENV_GROQ}"
fi

if grep -q "KEYDB_URL=redis://keydb:6379" "${POC_DIR}/.env" 2>/dev/null; then
    test_pass ".env has KEYDB_URL=redis://keydb:6379 (session persistence enabled)"
else
    ENV_KEYDB=$(grep "KEYDB_URL" "${POC_DIR}/.env" 2>/dev/null || echo "NOT_FOUND")
    test_fail "KEYDB_URL default" "Expected redis://keydb:6379, found: ${ENV_KEYDB}"
fi

if grep -q "SPIFFE_MODE=dev" "${POC_DIR}/.env" 2>/dev/null; then
    test_pass ".env has SPIFFE_MODE=dev (default)"
else
    ENV_SPIFFE=$(grep "SPIFFE_MODE" "${POC_DIR}/.env" 2>/dev/null || echo "NOT_FOUND")
    test_fail "SPIFFE_MODE default" "Expected dev, found: ${ENV_SPIFFE}"
fi

# Verify output contains key sections
# Strip ANSI color codes so grep patterns match reliably
OUTPUT_TEXT=$(sed 's/\x1b\[[0-9;]*m//g' /tmp/setup_wizard_test_output.txt)

if echo "$OUTPUT_TEXT" | grep -q "Prerequisite Checks"; then
    test_pass "Output contains prerequisite checks section"
else
    test_fail "Prerequisite checks section" "Not found in output"
fi

if echo "$OUTPUT_TEXT" | grep -q "Security Posture Summary"; then
    test_pass "Output contains security posture summary"
else
    test_fail "Security posture summary" "Not found in output"
fi

if echo "$OUTPUT_TEXT" | grep -q "ENABLED\|DISABLED\|DEGRADED"; then
    test_pass "Security posture shows status indicators"
else
    test_fail "Status indicators" "No ENABLED/DISABLED/DEGRADED found in output"
fi

if echo "$OUTPUT_TEXT" | grep -q "Deep Scan.*DISABLED\|DISABLED.*Deep"; then
    test_pass "Deep Scan shown as DISABLED (no API key)"
else
    test_fail "Deep Scan status" "Expected DISABLED when no API key provided"
fi

echo ""

# =============================================================================
# Test 2: Custom inputs produce correct .env
# =============================================================================

echo -e "${CYAN}--- Test 2: Custom inputs ---${NC}"
echo ""

# Send custom answers:
#   Q1: 2 = fail-open
#   Q2: test-api-key-12345
#   Q3: n = no KeyDB
#   Q4: 2 = prod
#   Q5: n = don't start
printf '2\ntest-api-key-12345\nn\n2\nn\n' | bash "$SETUP_SCRIPT" 2>&1 | head -200 > /tmp/setup_wizard_test_custom_output.txt || true

if grep -q "DEEP_SCAN_FALLBACK=fail_open" "${POC_DIR}/.env" 2>/dev/null; then
    test_pass ".env has DEEP_SCAN_FALLBACK=fail_open (custom choice)"
else
    test_fail "Custom DEEP_SCAN_FALLBACK" "Expected fail_open in .env"
fi

if grep -q "GROQ_API_KEY=test-api-key-12345" "${POC_DIR}/.env" 2>/dev/null; then
    test_pass ".env has custom GROQ_API_KEY"
else
    ENV_GROQ=$(grep "GROQ_API_KEY" "${POC_DIR}/.env" 2>/dev/null || echo "NOT_FOUND")
    test_fail "Custom GROQ_API_KEY" "Expected test-api-key-12345, found: ${ENV_GROQ}"
fi

if grep -q "KEYDB_URL=$" "${POC_DIR}/.env" 2>/dev/null || grep -q "KEYDB_URL=\s*$" "${POC_DIR}/.env" 2>/dev/null; then
    test_pass ".env has empty KEYDB_URL (KeyDB disabled)"
else
    ENV_KEYDB=$(grep "KEYDB_URL" "${POC_DIR}/.env" 2>/dev/null || echo "NOT_FOUND")
    test_fail "Custom KEYDB_URL" "Expected empty (disabled), found: ${ENV_KEYDB}"
fi

if grep -q "SPIFFE_MODE=prod" "${POC_DIR}/.env" 2>/dev/null; then
    test_pass ".env has SPIFFE_MODE=prod (custom choice)"
else
    ENV_SPIFFE=$(grep "SPIFFE_MODE" "${POC_DIR}/.env" 2>/dev/null || echo "NOT_FOUND")
    test_fail "Custom SPIFFE_MODE" "Expected prod, found: ${ENV_SPIFFE}"
fi

# Verify the custom output shows correct posture (strip ANSI codes)
CUSTOM_OUTPUT=$(sed 's/\x1b\[[0-9;]*m//g' /tmp/setup_wizard_test_custom_output.txt)

if echo "$CUSTOM_OUTPUT" | grep -q "DEGRADED"; then
    test_pass "Custom config shows DEGRADED status for fail-open"
else
    test_fail "Custom posture DEGRADED" "Expected DEGRADED for fail-open deep scan"
fi

if echo "$CUSTOM_OUTPUT" | grep -q "Session Persistence.*DISABLED\|DISABLED.*Session"; then
    test_pass "Custom config shows Session Persistence as DISABLED"
else
    test_fail "Custom session status" "Expected DISABLED when KeyDB turned off"
fi

echo ""

# =============================================================================
# Test 3: Prerequisite check formatting
# =============================================================================

echo -e "${CYAN}--- Test 3: Prerequisite check formatting ---${NC}"
echo ""

if echo "$OUTPUT_TEXT" | grep -q "\[OK\].*Docker"; then
    test_pass "Docker check shows [OK] formatting"
else
    if echo "$OUTPUT_TEXT" | grep -q "\[FAIL\].*Docker"; then
        test_pass "Docker check shows [FAIL] formatting (Docker not available)"
    else
        test_fail "Docker check formatting" "No [OK] or [FAIL] marker found for Docker"
    fi
fi

if echo "$OUTPUT_TEXT" | grep -q "\[OK\].*Go\|go"; then
    test_pass "Go check shows [OK] formatting"
else
    if echo "$OUTPUT_TEXT" | grep -q "\[FAIL\].*Go\|go"; then
        test_pass "Go check shows [FAIL] formatting (Go not available)"
    else
        test_fail "Go check formatting" "No [OK] or [FAIL] marker found for Go"
    fi
fi

# Check for optional tool markers
if echo "$OUTPUT_TEXT" | grep -q "\[OK\]\|--"; then
    test_pass "Optional tool checks use [OK] or [--] markers"
else
    test_fail "Optional tool markers" "Expected [OK] or [--] markers for optional tools"
fi

echo ""

# =============================================================================
# Test 4: Security consequence explanations
# =============================================================================

echo -e "${CYAN}--- Test 4: Security consequence explanations ---${NC}"
echo ""

if echo "$OUTPUT_TEXT" | grep -qi "fail-closed\|fail_closed\|block.*request"; then
    test_pass "Fallback policy explains security consequence"
else
    test_fail "Fallback explanation" "No security consequence explanation for fallback policy"
fi

if echo "$OUTPUT_TEXT" | grep -qi "exfiltration\|cross-request\|session"; then
    test_pass "KeyDB question explains security consequence"
else
    test_fail "KeyDB explanation" "No security consequence explanation for session persistence"
fi

if echo "$OUTPUT_TEXT" | grep -qi "mTLS\|header.*inject\|identity\|certificate"; then
    test_pass "SPIFFE question explains security consequence"
else
    test_fail "SPIFFE explanation" "No security consequence explanation for SPIFFE mode"
fi

echo ""

# =============================================================================
# Test 5: Make target exists
# =============================================================================

echo -e "${CYAN}--- Test 5: Make target wiring ---${NC}"
echo ""

if grep -q "^setup:" "${POC_DIR}/Makefile"; then
    test_pass "'make setup' target exists in Makefile"
else
    test_fail "Make target" "'setup' target not found in Makefile"
fi

if grep -q "scripts/setup.sh" "${POC_DIR}/Makefile"; then
    test_pass "Makefile setup target references scripts/setup.sh"
else
    test_fail "Make target wiring" "Makefile setup target does not reference scripts/setup.sh"
fi

echo ""

# =============================================================================
# Test 6: .env does NOT contain secrets from other runs
# =============================================================================

echo -e "${CYAN}--- Test 6: .env isolation ---${NC}"
echo ""

# Run with defaults again to verify clean generation
printf '\n\n\n\n\nn\n' | bash "$SETUP_SCRIPT" 2>&1 > /dev/null || true

# After running with all defaults (no API key), .env should not contain old custom key
if grep -q "test-api-key-12345" "${POC_DIR}/.env" 2>/dev/null; then
    test_fail ".env isolation" "Old custom API key persists across re-runs"
else
    test_pass ".env regenerated cleanly (no stale values)"
fi

echo ""

# =============================================================================
# Cleanup
# =============================================================================

# Restore original .env if it existed
if [ -f "${POC_DIR}/.env.bak.test" ]; then
    mv "${POC_DIR}/.env.bak.test" "${POC_DIR}/.env"
fi

# Clean up temp files
rm -f /tmp/setup_wizard_test_output.txt /tmp/setup_wizard_test_custom_output.txt

# =============================================================================
# Summary
# =============================================================================

echo -e "${BOLD}=========================================${NC}"
echo -e "${BOLD}  Integration Test Results${NC}"
echo -e "${BOLD}=========================================${NC}"
echo ""

TOTAL=$((PASS_COUNT + FAIL_COUNT))
echo -e "  Total: ${TOTAL}"
echo -e "  ${GREEN}PASS${NC}: ${PASS_COUNT}"
echo -e "  ${RED}FAIL${NC}: ${FAIL_COUNT}"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed.${NC}"
    exit 0
fi

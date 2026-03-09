#!/usr/bin/env bash
# E2E Validation Master Runner - RFA-70p + RFA-a2y.2
# Runs all 5 scenarios + readiness checklist + middleware chain verification
# + SPIKE Nexus late-binding secrets validation
# Produces a comprehensive report for capstone milestone validation

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Track overall results
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
declare -a SCENARIO_RESULTS

gateway_healthy() {
    local state health
    state=$(docker compose -f "${PROJECT_ROOT}/docker-compose.yml" ps --format '{{.State}}' mcp-security-gateway 2>/dev/null || true)
    health=$(docker compose -f "${PROJECT_ROOT}/docker-compose.yml" ps --format '{{.Health}}' mcp-security-gateway 2>/dev/null || true)
    [ "$state" = "running" ] && { [ -z "$health" ] || [ "$health" = "healthy" ]; }
}

ensure_stack_ready() {
    if gateway_healthy; then
        echo -e "${GREEN}E2E preflight: gateway is already running.${NC}"
        return 0
    fi

    echo -e "${YELLOW}E2E preflight: gateway not running, starting compose stack via make up...${NC}"
    if ! make -C "${PROJECT_ROOT}" up; then
        echo -e "${RED}E2E preflight failed: make up returned non-zero.${NC}"
        return 1
    fi

    if ! gateway_healthy; then
        echo -e "${RED}E2E preflight failed: gateway is still not healthy after make up.${NC}"
        return 1
    fi

    echo -e "${GREEN}E2E preflight: compose stack is ready.${NC}"
}

run_scenario() {
    local name="$1"
    local script="$2"

    echo ""
    echo -e "${BOLD}================================================================${NC}"
    echo -e "${BOLD}  Running: $name${NC}"
    echo -e "${BOLD}================================================================${NC}"

    local output
    local exit_code
    output=$(bash "$script" 2>&1)
    exit_code=$?

    echo "$output"

    # Extract pass/fail/skip counts from output
    # Strip ANSI color codes before counting to avoid false matches
    local stripped
    stripped=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')
    local pass fail skip
    pass=$(echo "$stripped" | grep -c '\[PASS\]' || true)
    pass=$(echo "$pass" | tr -d '[:space:]')
    pass=${pass:-0}
    fail=$(echo "$stripped" | grep -c '\[FAIL\]' || true)
    fail=$(echo "$fail" | tr -d '[:space:]')
    fail=${fail:-0}
    skip=$(echo "$stripped" | grep -c '\[SKIP\]' || true)
    skip=$(echo "$skip" | tr -d '[:space:]')
    skip=${skip:-0}

    TOTAL_PASS=$((TOTAL_PASS + pass))
    TOTAL_FAIL=$((TOTAL_FAIL + fail))
    TOTAL_SKIP=$((TOTAL_SKIP + skip))

    if [ "$exit_code" -eq 0 ]; then
        SCENARIO_RESULTS+=("${GREEN}PASS${NC} $name (${pass}P/${fail}F/${skip}S)")
    else
        SCENARIO_RESULTS+=("${RED}FAIL${NC} $name (${pass}P/${fail}F/${skip}S)")
    fi
}

echo ""
echo -e "${BOLD}################################################################${NC}"
echo -e "${BOLD}  RFA-70p: Final E2E Validation -- POC Docker Compose${NC}"
echo -e "${BOLD}  Full 13-Middleware Chain Capstone Test${NC}"
echo -e "${BOLD}################################################################${NC}"
echo ""
echo "Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Branch: $(git branch --show-current 2>/dev/null || echo 'unknown')"
echo "Commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
echo ""

ensure_stack_ready || exit 1

# ================================================================
# Run all scenarios
# ================================================================

run_scenario "Scenario A: Happy Path" "${SCRIPT_DIR}/scenario_a_happy_path.sh"
run_scenario "Scenario B: Security Denial" "${SCRIPT_DIR}/scenario_b_security_denial.sh"
run_scenario "Scenario C: Exfiltration Detection" "${SCRIPT_DIR}/scenario_c_exfiltration.sh"
run_scenario "Scenario D: Tool Poisoning" "${SCRIPT_DIR}/scenario_d_tool_poisoning.sh"
run_scenario "Scenario E: DLP Detection" "${SCRIPT_DIR}/scenario_e_dlp.sh"
run_scenario "Scenario F: Phase 3 Multi-Plane" "${SCRIPT_DIR}/scenario_f_phase3_planes.sh"
run_scenario "Scenario G: Model Egress SPIKE Reference" "${SCRIPT_DIR}/scenario_g_model_egress_ref.sh"
run_scenario "Section 10.13.1 Readiness Checklist" "${SCRIPT_DIR}/readiness_checklist.sh"
run_scenario "Full 13-Middleware Chain" "${SCRIPT_DIR}/middleware_chain_verify.sh"
run_scenario "Scenario SPIKE Nexus: Late-Binding Secrets" "${SCRIPT_DIR}/scenario_spike_nexus.sh"

# ================================================================
# Grand Summary
# ================================================================
echo ""
echo ""
echo -e "${BOLD}################################################################${NC}"
echo -e "${BOLD}  GRAND SUMMARY -- RFA-70p E2E Validation${NC}"
echo -e "${BOLD}################################################################${NC}"
echo ""

for result in "${SCENARIO_RESULTS[@]}"; do
    echo -e "  $result"
done

echo ""
GRAND_TOTAL=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))
echo -e "  Grand Total: ${GRAND_TOTAL} checks"
echo -e "  ${GREEN}PASS${NC}: ${TOTAL_PASS}"
echo -e "  ${RED}FAIL${NC}: ${TOTAL_FAIL}"
echo -e "  ${YELLOW}SKIP${NC}: ${TOTAL_SKIP}"
echo ""

if [ "$TOTAL_FAIL" -gt 0 ]; then
    echo -e "${RED}VALIDATION: Some checks failed. See details above.${NC}"
    exit 1
elif [ "$TOTAL_SKIP" -gt 0 ]; then
    echo -e "${YELLOW}VALIDATION: All executed checks passed, but some were skipped.${NC}"
    echo -e "${YELLOW}Skipped items are known gaps documented in the variance report.${NC}"
    exit 0
else
    echo -e "${GREEN}VALIDATION: All checks passed.${NC}"
    exit 0
fi

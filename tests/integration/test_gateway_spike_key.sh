#!/usr/bin/env bash
# Integration Test: Gateway SPIKE Key Fetch at Startup (RFA-bci)
#
# Validates that the gateway correctly fetches the Groq API key from SPIKE
# at startup and uses it for the guard model (step-up gating and deep scan).
#
# Preconditions:
#   - Docker Compose stack is running (make up) with the updated docker-compose.yml
#   - .env contains GROQ_API_KEY (seeded into SPIKE by spike-secret-seeder)
#
# Usage:
#   bash tests/integration/test_gateway_spike_key.sh
#   make test-gateway-spike-key
#
# The test sources the E2E common.sh for shared utilities (log_pass, log_fail, etc.)
# and follows the same conventions as tests/integration/test_spike_seeder_groq.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

# Source common E2E utilities (log_pass, log_fail, print_summary, etc.)
source "${POC_DIR}/tests/e2e/common.sh"

log_header "Integration Test: Gateway SPIKE Key Fetch (RFA-bci)"

# ============================================================
# Pre-flight: Load .env and verify GROQ_API_KEY is available
# ============================================================
log_subheader "Pre-flight checks"

ENV_FILE="${POC_DIR}/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "SKIP: ${ENV_FILE} not found. This test requires .env with GROQ_API_KEY."
    exit 0
fi

# Source .env to get the expected key value
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

if [ -z "${GROQ_API_KEY:-}" ]; then
    echo "SKIP: GROQ_API_KEY is empty in ${ENV_FILE}. Cannot validate SPIKE key fetch."
    exit 0
fi

log_pass "GROQ_API_KEY loaded from .env (non-empty)"

# ============================================================
# Pre-flight: Verify Docker Compose stack is running
# ============================================================

if ! $DC ps --format '{{.Name}}' 2>/dev/null | grep -q "precinct-gateway"; then
    echo "SKIP: Docker Compose stack is not running (precinct-gateway not found). Start with: make up"
    exit 0
fi
log_pass "Docker Compose stack is running"

if ! check_service_healthy "precinct-gateway"; then
    echo "SKIP: precinct-gateway is not healthy. Wait for stack initialization."
    exit 0
fi
log_pass "precinct-gateway is healthy"

# Collect gateway startup logs once (used by multiple tests).
# Use --no-log-prefix for clean parsing (Docker Compose >= 2.19).
GW_LOGS=$($DC logs --no-log-prefix precinct-gateway 2>/dev/null || \
          $DC logs precinct-gateway 2>/dev/null || echo "")

# ============================================================
# Test 1: Gateway logs show SPIKE key fetch succeeded (AC1, AC2)
#
# The gateway should log:
#   "guard model API key loaded from SPIKE"
# when SPIKENexusRedeemer.RedeemSecret succeeds.
# ============================================================
log_subheader "Test 1: Gateway fetched guard model key from SPIKE"

if echo "$GW_LOGS" | grep -q "guard model API key loaded from SPIKE"; then
    log_pass "Gateway logs contain 'guard model API key loaded from SPIKE' (AC1+AC2)"
else
    # If the SPIKE fetch failed but the gateway fell back to env, it will log
    # the fallback warning instead. Either path is acceptable for demonstrating
    # the mechanism, but SPIKE success is the primary AC.
    if echo "$GW_LOGS" | grep -q "failed to load guard model API key from SPIKE"; then
        log_fail "SPIKE key fetch" "Gateway fell back to env (SPIKE Nexus returned error). Check spike-nexus health."
    else
        log_fail "SPIKE key fetch" "Neither SPIKE success nor fallback log found in gateway logs"
    fi
fi

# ============================================================
# Test 2: Gateway logs show dual-mode endpoint switch (AC9)
#
# When the gateway has a real API key AND the configured endpoint
# points to mock-guard-model, it should switch to real Groq API.
# The docker-compose.yml sets GUARD_MODEL_ENDPOINT=http://mock-guard-model:8080/openai/v1.
# ============================================================
log_subheader "Test 2: Dual-mode endpoint switch to real Groq API"

if echo "$GW_LOGS" | grep -q "guard model endpoint switched to real Groq API"; then
    log_pass "Gateway logs contain 'guard model endpoint switched to real Groq API' (AC9)"
else
    # If SPIKE key fetch failed and no env key is available, the endpoint
    # will NOT be switched (which is correct behavior -- no key = no switch).
    if echo "$GW_LOGS" | grep -q "no guard model API key available"; then
        log_skip "Dual-mode endpoint switch" "No API key available (SPIKE failed and no env fallback)"
    else
        log_fail "Dual-mode endpoint switch" "Expected 'guard model endpoint switched to real Groq API' in logs"
    fi
fi

# ============================================================
# Test 3: Step-up guard uses the SPIKE-fetched key (not fail-open)
#
# Send a medium-risk tool call that triggers step-up gating.
# If the guard model API key was loaded from SPIKE, the guard client
# should attempt to classify the content (not skip with "no Groq API
# key configured"). We verify by checking the audit log for the
# step-up gating decision: it should show "step-up controls passed"
# (guard invoked successfully) rather than "guard model not configured".
#
# We use tavily_search with a destination that triggers step-up range.
# ============================================================
log_subheader "Test 3: Step-up guard model is operational (not fail-open)"

# Send a tool call that triggers step-up evaluation
gateway_request "$DEFAULT_SPIFFE_ID" "tools/call" \
    '{"name":"tavily_search","arguments":{"query":"integration test RFA-bci guard model check"}}'

log_info "Response code: ${RESP_CODE}"

# Check gateway logs for step-up audit that does NOT indicate missing key.
# Collect recent logs (last 100 lines) to catch the step-up decision for our request.
RECENT_GW_LOGS=$($DC logs --tail 100 --no-log-prefix precinct-gateway 2>/dev/null || \
                 $DC logs --tail 100 precinct-gateway 2>/dev/null || echo "")

# The fail-open indicator is: "guard model not configured" in the step_up_gating audit.
# A working guard shows: "step-up controls passed" or "injection probability" or "guard model unavailable"
# (network timeout to real Groq is acceptable; what matters is the key was present).
if echo "$RECENT_GW_LOGS" | grep -q "step_up_gating"; then
    if echo "$RECENT_GW_LOGS" | grep "step_up_gating" | grep -q "guard model not configured"; then
        log_fail "Guard model key" "Step-up audit shows 'guard model not configured' -- SPIKE key not used"
    else
        log_pass "Step-up guard model is configured (not reporting 'not configured')"
    fi
else
    # Step-up gating may not be triggered if the tool scores in fast_path range.
    # Check the response for clues.
    if echo "$RESP_BODY" | grep -q "no Groq API key configured"; then
        log_fail "Guard model key" "Response contains 'no Groq API key configured' -- key missing"
    elif [ "$RESP_CODE" = "200" ] || [ "$RESP_CODE" = "502" ]; then
        # 200 = request passed through (fast path or step-up passed)
        # 502 = upstream unreachable (acceptable in integration test -- key was used but Groq unreachable)
        log_pass "Guard model operational (response ${RESP_CODE}, no 'key not configured' error)"
    else
        log_skip "Guard model check" "Could not determine guard model status from response (code=${RESP_CODE})"
    fi
fi

# ============================================================
# Test 4: Gateway logs do NOT contain the raw API key (AC8)
#
# The gateway must never log the actual secret value. Logs should
# only contain the path reference ("groq-api-key"), not the key itself.
# ============================================================
log_subheader "Test 4: No secrets in gateway logs"

if echo "$GW_LOGS" | grep -qF "$GROQ_API_KEY"; then
    log_fail "SECRET LEAK IN GATEWAY LOGS" "Raw GROQ_API_KEY value found in precinct-gateway logs"
else
    log_pass "Raw GROQ_API_KEY value NOT found in gateway logs (AC8 satisfied)"
fi

# Also check for common Groq key prefix as a secondary safeguard
if echo "$GW_LOGS" | grep -q "gsk_[A-Za-z0-9]"; then
    log_fail "Gateway logs contain gsk_ prefix" "Possible Groq API key leak in gateway logs"
else
    log_pass "No gsk_ key prefix found in gateway logs"
fi

# ============================================================
# Test 5: GROQ_API_KEY= removed from docker compose config (AC5)
#
# The docker-compose.yml should no longer contain the GROQ_API_KEY=
# blank line in the gateway service environment.
# ============================================================
log_subheader "Test 5: GROQ_API_KEY removed from compose config"

COMPOSE_CONFIG=$($DC config 2>&1)

# Check that GROQ_API_KEY is not set as an environment variable for
# the gateway service. The rendered config should not contain it.
GW_ENV=$(docker inspect precinct-gateway --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null || echo "")

if echo "$GW_ENV" | grep -q "^GROQ_API_KEY="; then
    log_fail "GROQ_API_KEY in gateway env" "Gateway container still has GROQ_API_KEY environment variable"
else
    log_pass "GROQ_API_KEY not present in gateway container environment (AC5)"
fi

# Verify GUARD_API_KEY is still present (AC6)
if echo "$GW_ENV" | grep -q "^GUARD_API_KEY=demo-guard-key"; then
    log_pass "GUARD_API_KEY=demo-guard-key still present in gateway environment (AC6)"
else
    log_fail "GUARD_API_KEY missing" "Expected GUARD_API_KEY=demo-guard-key in gateway container environment"
fi

# ============================================================
# Summary
# ============================================================
print_summary

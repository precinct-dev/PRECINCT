#!/usr/bin/env bash
# Integration Test: SPIKE Secret Seeder Groq API Key (RFA-cjc)
#
# Validates that the spike-secret-seeder correctly seeds the Groq API key
# into SPIKE and that docker compose config does not leak the raw key value.
#
# Preconditions:
#   - Docker Compose stack is running (make up) with the updated docker-compose.yml
#   - .env contains GROQ_API_KEY
#
# Usage:
#   bash tests/integration/test_spike_seeder_groq.sh
#   make test-spike-seeder-groq
#
# The test sources the E2E common.sh for shared utilities (log_pass, log_fail, etc.)
# and follows the same conventions as tests/e2e/scenario_spike_nexus.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

# Source common E2E utilities (log_pass, log_fail, print_summary, etc.)
source "${POC_DIR}/tests/e2e/common.sh"

# The spike-pilot image used by the seeder (must match docker-compose.yml)
SPIKE_PILOT_IMAGE="ghcr.io/spiffe/spike-pilot:0.8.0@sha256:86b26666c171c5284c522bfb42f16473c85be6f3e3e32b1e3deaa8cd5a18eaff"
# Network where SPIKE Nexus lives
SECRETS_NETWORK="agentic-security-secrets-plane"

log_header "Integration Test: SPIKE Seeder Groq API Key (RFA-cjc)"

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
    echo "SKIP: GROQ_API_KEY is empty in ${ENV_FILE}. Cannot validate secret seeding."
    exit 0
fi

log_pass "GROQ_API_KEY loaded from .env (non-empty)"

# Compute the expected hash of the key (for comparison without logging the raw value)
EXPECTED_HASH=$(printf '%s' "$GROQ_API_KEY" | shasum -a 256 | awk '{print $1}')
log_info "Expected key hash (sha256): ${EXPECTED_HASH}"

# ============================================================
# Pre-flight: Verify Docker Compose stack is running
# ============================================================

if ! $DC ps --format '{{.Name}}' 2>/dev/null | grep -q "spike-nexus"; then
    echo "SKIP: Docker Compose stack is not running. Start with: make up"
    exit 0
fi
log_pass "Docker Compose stack is running"

if ! check_service_healthy "spike-nexus"; then
    echo "SKIP: spike-nexus is not healthy. Wait for stack initialization."
    exit 0
fi
log_pass "SPIKE Nexus is healthy"

# ============================================================
# Helper: run spike CLI via docker run (avoids dependency chain recreation)
# The spike-pilot image entrypoint is 'spike', so args are passed directly
# (e.g., "secret list" not "spike secret list").
# ============================================================
run_spike_cli() {
    docker run --rm \
        --network "$SECRETS_NETWORK" \
        -v spire-agent-socket:/tmp/spire-agent/public:ro \
        -e SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/public/api.sock \
        -e SPIKE_NEXUS_API_URL=https://spike-nexus:8443 \
        -e SPIKE_TRUST_ROOT=poc.local \
        -e SPIKE_TRUST_ROOT_NEXUS=poc.local \
        -e SPIKE_TRUST_ROOT_PILOT=poc.local \
        --label spiffe-id=spike-seeder \
        "$SPIKE_PILOT_IMAGE" \
        "$@"
}

# ============================================================
# Test 1: Seeder container exited with code 0
# ============================================================
log_subheader "Test 1: Seeder container exit code"

SEEDER_STATUS=$(docker compose ps --format '{{.Status}}' spike-secret-seeder 2>/dev/null || echo "not found")
log_info "spike-secret-seeder status: ${SEEDER_STATUS}"

if echo "$SEEDER_STATUS" | grep -qi "exited (0)"; then
    log_pass "spike-secret-seeder exited with code 0"
elif [ -z "$SEEDER_STATUS" ]; then
    # One-shot containers may not persist in `docker compose ps` after removal.
    # Check logs instead for the "done" marker.
    DONE_LOG=$(docker compose logs spike-secret-seeder 2>/dev/null | grep -c "spike-seeder: done" || echo "0")
    if [ "$DONE_LOG" -gt 0 ]; then
        log_pass "spike-secret-seeder completed (container removed but 'done' log present)"
    else
        log_fail "spike-secret-seeder exit code" "Container not found and no completion log"
    fi
else
    log_fail "spike-secret-seeder exit code" "Expected 'Exited (0)', got: ${SEEDER_STATUS}"
fi

# ============================================================
# Test 2: Seeder logs show groq-api-key seeding activity
# ============================================================
log_subheader "Test 2: Seeder logs contain groq-api-key activity"

SEEDER_LOGS=$(docker compose logs spike-secret-seeder 2>/dev/null || echo "")

if echo "$SEEDER_LOGS" | grep -q "spike-seeder: seeding groq-api-key"; then
    log_pass "Seeder logs show groq-api-key seeding started"
else
    log_fail "Seeder log: seeding start" "Missing 'spike-seeder: seeding groq-api-key' in logs"
fi

if echo "$SEEDER_LOGS" | grep -q "spike-seeder: groq-api-key seeded successfully"; then
    log_pass "Seeder logs confirm groq-api-key seeded successfully"
else
    log_fail "Seeder log: seeding success" "Missing 'spike-seeder: groq-api-key seeded successfully' in logs"
fi

# ============================================================
# Test 3: Read groq-api-key back from SPIKE (AC7)
#
# Uses `docker run` directly with the spike-pilot image on the secrets-plane
# network, avoiding `docker compose run` which recreates the entire dependency
# chain (spike-bootstrap etc.) and blocks on one-shot init containers.
# The spike-pilot image entrypoint is 'spike', so we pass 'secret get <path>'.
# Output format: "value: <secret_value>"
# ============================================================
log_subheader "Test 3: Read groq-api-key from SPIKE via CLI"

SPIKE_READ_OUT=""
SPIKE_READ_EXIT=0

SPIKE_READ_OUT=$(run_spike_cli secret get groq-api-key 2>&1) || SPIKE_READ_EXIT=$?

if [ "$SPIKE_READ_EXIT" -ne 0 ]; then
    log_info "spike secret get exit code: ${SPIKE_READ_EXIT}"
    log_info "spike secret get output (first 200 chars): ${SPIKE_READ_OUT:0:200}"
    log_fail "Read groq-api-key from SPIKE" "spike secret get failed with exit code ${SPIKE_READ_EXIT}"
else
    log_info "spike secret get succeeded (output length: ${#SPIKE_READ_OUT} chars)"

    # Extract the value from "value: <val>" format.
    # Use awk for POSIX/macOS portability (BSD sed does not support \s).
    RETRIEVED_VALUE=""

    # Pattern 1: "value: <val>" (observed spike CLI format)
    if echo "$SPIKE_READ_OUT" | grep -q '^value:'; then
        RETRIEVED_VALUE=$(echo "$SPIKE_READ_OUT" | awk -F': ' '/^value:/{print $2}' | head -1)
    fi

    # Pattern 2: "value=<val>" (alternative format)
    if [ -z "$RETRIEVED_VALUE" ] && echo "$SPIKE_READ_OUT" | grep -q '^value='; then
        RETRIEVED_VALUE=$(echo "$SPIKE_READ_OUT" | awk -F'=' '/^value=/{print $2}' | head -1)
    fi

    # Pattern 3: Single-line output (raw value)
    if [ -z "$RETRIEVED_VALUE" ]; then
        RETRIEVED_VALUE=$(echo "$SPIKE_READ_OUT" | grep -v '^$' | head -1 | xargs)
    fi

    if [ -n "$RETRIEVED_VALUE" ]; then
        RETRIEVED_HASH=$(printf '%s' "$RETRIEVED_VALUE" | shasum -a 256 | awk '{print $1}')
        log_info "Retrieved value hash (sha256): ${RETRIEVED_HASH}"

        if [ "$RETRIEVED_HASH" = "$EXPECTED_HASH" ]; then
            log_pass "groq-api-key in SPIKE matches .env value (hash comparison verified)"
        else
            log_fail "groq-api-key hash mismatch" "Expected hash ${EXPECTED_HASH}, got ${RETRIEVED_HASH}"
        fi
    else
        log_fail "groq-api-key value extraction" "Could not extract value from spike secret get output"
    fi
fi

# ============================================================
# Test 4: groq-api-key appears in SPIKE secret listing
# ============================================================
log_subheader "Test 4: groq-api-key listed in SPIKE secrets"

SPIKE_LIST_OUT=$(run_spike_cli secret list 2>&1) || true

if echo "$SPIKE_LIST_OUT" | grep -q "groq-api-key"; then
    log_pass "groq-api-key appears in SPIKE secret listing"
else
    log_fail "groq-api-key not in secret listing" "Output: ${SPIKE_LIST_OUT:0:200}"
fi

# ============================================================
# Test 5: Seeder logs do NOT contain the raw key value (AC6)
# ============================================================
log_subheader "Test 5: Seeder logs do not contain raw key value"

if echo "$SEEDER_LOGS" | grep -qF "$GROQ_API_KEY"; then
    log_fail "SECRET LEAK IN SEEDER LOGS" "Raw GROQ_API_KEY value found in spike-secret-seeder logs"
else
    log_pass "Raw GROQ_API_KEY value NOT found in seeder logs (AC6 satisfied)"
fi

# ============================================================
# Test 6: docker compose config does not contain raw key (AC8)
# ============================================================
log_subheader "Test 6: docker compose config does not leak raw key"

COMPOSE_CONFIG=$($DC config 2>&1)

if echo "$COMPOSE_CONFIG" | grep -qF "$GROQ_API_KEY"; then
    log_fail "SECRET LEAK in docker compose config" "Raw GROQ_API_KEY value found in docker compose config output"
else
    log_pass "Raw GROQ_API_KEY value NOT found in docker compose config output (AC8 satisfied)"
fi

# Also check for common Groq key prefix as a secondary check
if echo "$COMPOSE_CONFIG" | grep -q "gsk_"; then
    log_fail "docker compose config contains gsk_ prefix" "Possible Groq API key leak"
else
    log_pass "No gsk_ prefix found in docker compose config output"
fi

# ============================================================
# Test 7: Existing deadbeef seeding still works (AC4)
# ============================================================
log_subheader "Test 7: Existing deadbeef seeding unchanged"

if echo "$SEEDER_LOGS" | grep -q "spike-seeder: seeding ref=deadbeef"; then
    log_pass "Deadbeef seeding started (existing behavior preserved)"
else
    log_fail "Deadbeef seeding" "Missing deadbeef seeding log entry"
fi

# ============================================================
# Test 8: Gateway-read policy creation unchanged (AC4)
# ============================================================
log_subheader "Test 8: Gateway-read policy creation unchanged"

if echo "$SEEDER_LOGS" | grep -q "spike-seeder: creating gateway-read ACL policy"; then
    log_pass "Gateway-read ACL policy creation present in logs (AC4 satisfied)"
else
    log_fail "Gateway-read policy" "Missing policy creation log entry"
fi

# ============================================================
# Summary
# ============================================================
print_summary

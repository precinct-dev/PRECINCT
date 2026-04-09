#!/bin/bash
# Unit Tests: x509pop certificate generation script
#
# Verifies:
#   1. All expected files are created with correct permissions
#   2. CA is self-signed (issuer == subject)
#   3. Agent cert is signed by CA (openssl verify)
#   4. Agent cert subject CN = "spire-agent"
#   5. Idempotent: second run is a no-op
#   6. FORCE=1 regenerates all certs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GENERATE_SCRIPT="${REPO_ROOT}/scripts/generate-x509pop-certs.sh"
OUTPUT_DIR="${REPO_ROOT}/deploy/compose/data/x509pop"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

cleanup() {
    # Remove generated certs from this test run
    rm -rf "${OUTPUT_DIR}"
}

# --- setup -----------------------------------------------------------------

echo "=== x509pop Certificate Generation Tests ==="
echo ""

# Clean slate
cleanup

# Verify the generate script exists and is executable
if [ ! -x "${GENERATE_SCRIPT}" ]; then
    echo "ERROR: ${GENERATE_SCRIPT} not found or not executable"
    exit 1
fi

# --- Test 1: First run creates all expected files --------------------------

echo "--- Test 1: First run creates all expected files ---"
bash "${GENERATE_SCRIPT}"

EXPECTED_FILES=(
    "${OUTPUT_DIR}/ca.key"
    "${OUTPUT_DIR}/ca.crt"
    "${OUTPUT_DIR}/ca-bundle.crt"
    "${OUTPUT_DIR}/agent.key"
    "${OUTPUT_DIR}/agent.crt"
)

all_exist=true
for f in "${EXPECTED_FILES[@]}"; do
    if [ -f "${f}" ]; then
        log_pass "File exists: $(basename "${f}")"
    else
        log_fail "File missing: $(basename "${f}")"
        all_exist=false
    fi
done

# --- Test 2: Correct file permissions -------------------------------------

echo ""
echo "--- Test 2: Correct file permissions ---"

check_perms() {
    local file="$1"
    local expected="$2"
    local actual
    # stat format differs between macOS and Linux
    if stat --version >/dev/null 2>&1; then
        # GNU stat (Linux)
        actual=$(stat -c '%a' "${file}")
    else
        # BSD stat (macOS)
        actual=$(stat -f '%Lp' "${file}")
    fi
    if [ "${actual}" = "${expected}" ]; then
        log_pass "Permissions $(basename "${file}"): ${actual} (expected ${expected})"
    else
        log_fail "Permissions $(basename "${file}"): ${actual} (expected ${expected})"
    fi
}

check_perms "${OUTPUT_DIR}/ca.key" "600"
check_perms "${OUTPUT_DIR}/agent.key" "600"
check_perms "${OUTPUT_DIR}/ca.crt" "644"
check_perms "${OUTPUT_DIR}/agent.crt" "644"
check_perms "${OUTPUT_DIR}/ca-bundle.crt" "644"

# --- Test 3: CA is self-signed (issuer == subject) -------------------------

echo ""
echo "--- Test 3: CA is self-signed ---"

CA_SUBJECT=$(openssl x509 -in "${OUTPUT_DIR}/ca.crt" -noout -subject 2>/dev/null | sed 's/^subject=//')
CA_ISSUER=$(openssl x509 -in "${OUTPUT_DIR}/ca.crt" -noout -issuer 2>/dev/null | sed 's/^issuer=//')

if [ "${CA_SUBJECT}" = "${CA_ISSUER}" ]; then
    log_pass "CA is self-signed (issuer == subject)"
else
    log_fail "CA is not self-signed: subject='${CA_SUBJECT}' issuer='${CA_ISSUER}'"
fi

# --- Test 4: CA uses EC P-256 and has correct CN ---------------------------

echo ""
echo "--- Test 4: CA key type and subject CN ---"

CA_KEY_TYPE=$(openssl x509 -in "${OUTPUT_DIR}/ca.crt" -noout -text 2>/dev/null | grep 'Public Key Algorithm' | head -1)
if echo "${CA_KEY_TYPE}" | grep -qi 'ec\|id-ecPublicKey'; then
    log_pass "CA uses EC key"
else
    log_fail "CA key type unexpected: ${CA_KEY_TYPE}"
fi

if echo "${CA_SUBJECT}" | grep -q 'PRECINCT Compose x509pop CA'; then
    log_pass "CA subject contains CN=PRECINCT Compose x509pop CA"
else
    log_fail "CA subject unexpected: ${CA_SUBJECT}"
fi

# --- Test 5: Agent cert is signed by CA ------------------------------------

echo ""
echo "--- Test 5: Agent cert signed by CA ---"

if openssl verify -CAfile "${OUTPUT_DIR}/ca.crt" "${OUTPUT_DIR}/agent.crt" >/dev/null 2>&1; then
    log_pass "Agent cert verified against CA"
else
    log_fail "Agent cert verification failed"
fi

# --- Test 6: Agent cert subject CN = spire-agent --------------------------

echo ""
echo "--- Test 6: Agent cert subject CN ---"

AGENT_SUBJECT=$(openssl x509 -in "${OUTPUT_DIR}/agent.crt" -noout -subject 2>/dev/null | sed 's/^subject=//')

if echo "${AGENT_SUBJECT}" | grep -q 'CN.*=.*spire-agent'; then
    log_pass "Agent cert CN = spire-agent"
else
    log_fail "Agent cert subject unexpected: ${AGENT_SUBJECT}"
fi

# --- Test 7: Agent cert uses EC P-256 -------------------------------------

echo ""
echo "--- Test 7: Agent key type ---"

AGENT_KEY_TYPE=$(openssl x509 -in "${OUTPUT_DIR}/agent.crt" -noout -text 2>/dev/null | grep 'Public Key Algorithm' | head -1)
if echo "${AGENT_KEY_TYPE}" | grep -qi 'ec\|id-ecPublicKey'; then
    log_pass "Agent uses EC key"
else
    log_fail "Agent key type unexpected: ${AGENT_KEY_TYPE}"
fi

# --- Test 8: CA bundle matches CA cert ------------------------------------

echo ""
echo "--- Test 8: CA bundle matches CA cert ---"

if diff -q "${OUTPUT_DIR}/ca.crt" "${OUTPUT_DIR}/ca-bundle.crt" >/dev/null 2>&1; then
    log_pass "CA bundle is identical to CA cert"
else
    log_fail "CA bundle differs from CA cert"
fi

# --- Test 9: Idempotent - second run is a no-op ---------------------------

echo ""
echo "--- Test 9: Idempotent (second run is no-op) ---"

# Record modification times before second run
CA_MTIME_BEFORE=$(stat -f '%m' "${OUTPUT_DIR}/ca.crt" 2>/dev/null || stat -c '%Y' "${OUTPUT_DIR}/ca.crt" 2>/dev/null)
AGENT_MTIME_BEFORE=$(stat -f '%m' "${OUTPUT_DIR}/agent.crt" 2>/dev/null || stat -c '%Y' "${OUTPUT_DIR}/agent.crt" 2>/dev/null)

SECOND_RUN_OUTPUT=$(bash "${GENERATE_SCRIPT}" 2>&1)

CA_MTIME_AFTER=$(stat -f '%m' "${OUTPUT_DIR}/ca.crt" 2>/dev/null || stat -c '%Y' "${OUTPUT_DIR}/ca.crt" 2>/dev/null)
AGENT_MTIME_AFTER=$(stat -f '%m' "${OUTPUT_DIR}/agent.crt" 2>/dev/null || stat -c '%Y' "${OUTPUT_DIR}/agent.crt" 2>/dev/null)

if [ "${CA_MTIME_BEFORE}" = "${CA_MTIME_AFTER}" ] && [ "${AGENT_MTIME_BEFORE}" = "${AGENT_MTIME_AFTER}" ]; then
    log_pass "Second run did not modify certificates"
else
    log_fail "Second run modified certificates (not idempotent)"
fi

if echo "${SECOND_RUN_OUTPUT}" | grep -q "already exist"; then
    log_pass "Second run printed skip message"
else
    log_fail "Second run did not print skip message"
fi

# --- Test 10: FORCE=1 regenerates all certs --------------------------------

echo ""
echo "--- Test 10: FORCE=1 regenerates certs ---"

# Capture the CA cert fingerprint before force-regen
CA_FP_BEFORE=$(openssl x509 -in "${OUTPUT_DIR}/ca.crt" -noout -fingerprint -sha256 2>/dev/null)

FORCE=1 bash "${GENERATE_SCRIPT}"

CA_FP_AFTER=$(openssl x509 -in "${OUTPUT_DIR}/ca.crt" -noout -fingerprint -sha256 2>/dev/null)

if [ "${CA_FP_BEFORE}" != "${CA_FP_AFTER}" ]; then
    log_pass "FORCE=1 regenerated CA certificate (fingerprint changed)"
else
    log_fail "FORCE=1 did not regenerate CA certificate"
fi

# Verify the new certs are still valid after force-regen
if openssl verify -CAfile "${OUTPUT_DIR}/ca.crt" "${OUTPUT_DIR}/agent.crt" >/dev/null 2>&1; then
    log_pass "Regenerated certs are valid (agent verifies against new CA)"
else
    log_fail "Regenerated certs are invalid after FORCE=1"
fi

# --- cleanup ---------------------------------------------------------------

cleanup

# --- summary ---------------------------------------------------------------

echo ""
echo "========================================"
echo "  Test Summary"
echo "  Passed: ${TESTS_PASSED}"
echo "  Failed: ${TESTS_FAILED}"
echo "========================================"

if [ "${TESTS_FAILED}" -eq 0 ]; then
    echo "All tests passed."
    exit 0
else
    echo "Some tests failed."
    exit 1
fi

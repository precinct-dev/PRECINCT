#!/usr/bin/env bash
# tests/test_makefile_x509pop.sh -- Verify Makefile x509pop migration (OC-z8kp)
#
# Validates that join-token references are removed and x509pop integration is
# wired correctly. Pure static analysis via grep -- no containers required.

set -euo pipefail

MAKEFILE="${MAKEFILE:-Makefile}"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

echo "=== Makefile x509pop migration tests ==="
echo ""

# --------------------------------------------------------------------------
# AC 1 + AC 8: up target does not reference spire-join-token
# --------------------------------------------------------------------------
echo "[AC1/AC8] No spire-join-token references in Makefile"
if grep -q 'spire-join-token' "$MAKEFILE"; then
    fail "Found 'spire-join-token' in Makefile"
else
    pass "No 'spire-join-token' references found"
fi

# --------------------------------------------------------------------------
# AC 2: up target auto-generates x509pop certs if missing
# --------------------------------------------------------------------------
echo "[AC2] up target checks for x509pop cert existence"
if grep -q 'x509pop/agent\.crt' "$MAKEFILE"; then
    pass "up target checks for x509pop/agent.crt"
else
    fail "up target does not check for x509pop/agent.crt"
fi

if grep -q 'generate-x509pop-certs\.sh' "$MAKEFILE"; then
    pass "up target calls generate-x509pop-certs.sh"
else
    fail "up target does not call generate-x509pop-certs.sh"
fi

# --------------------------------------------------------------------------
# AC 3: up target preserves spire-agent-socket directory management
# --------------------------------------------------------------------------
echo "[AC3] up target preserves spire-agent-socket management"
if grep -q 'spire-agent-socket' "$MAKEFILE"; then
    pass "spire-agent-socket directory management preserved"
else
    fail "spire-agent-socket directory management missing"
fi

# --------------------------------------------------------------------------
# AC 4: test-mcpserver-integration -- no join-token dirs, no spire-token-generator
# --------------------------------------------------------------------------
echo "[AC4] test-mcpserver-integration updated"
if grep -q 'spire-token-generator' "$MAKEFILE"; then
    fail "Found 'spire-token-generator' in Makefile"
else
    pass "No 'spire-token-generator' references found"
fi

# --------------------------------------------------------------------------
# AC 5: COMPOSE_PARENT_ID uses x509pop path
# --------------------------------------------------------------------------
echo "[AC5] COMPOSE_PARENT_ID contains x509pop"
if grep -q 'COMPOSE_PARENT_ID.*x509pop' "$MAKEFILE"; then
    pass "COMPOSE_PARENT_ID uses x509pop path"
else
    fail "COMPOSE_PARENT_ID does not use x509pop path"
fi

if grep -q 'COMPOSE_PARENT_ID.*join_token' "$MAKEFILE"; then
    fail "COMPOSE_PARENT_ID still references join_token"
else
    pass "COMPOSE_PARENT_ID does not reference join_token"
fi

# --------------------------------------------------------------------------
# AC 6: clean target removes x509pop directory
# --------------------------------------------------------------------------
echo "[AC6] clean target removes x509pop directory"
if grep -q 'x509pop/' "$MAKEFILE"; then
    pass "clean target references x509pop/ directory"
else
    fail "clean target does not reference x509pop/ directory"
fi

# --------------------------------------------------------------------------
# AC 7: generate-spire-certs target exists with help text
# --------------------------------------------------------------------------
echo "[AC7] generate-spire-certs target exists"
if grep -q '^generate-spire-certs:' "$MAKEFILE"; then
    pass "generate-spire-certs target exists"
else
    fail "generate-spire-certs target missing"
fi

if grep -q 'generate-spire-certs:.*##' "$MAKEFILE"; then
    pass "generate-spire-certs has help text"
else
    fail "generate-spire-certs missing help text"
fi

# --------------------------------------------------------------------------
# AC 8: No remaining join-token or spire-token-generator references
# --------------------------------------------------------------------------
echo "[AC8] No stale join-token or token-generator references"
if grep -q 'join.token' "$MAKEFILE"; then
    fail "Found 'join.token' pattern in Makefile"
else
    pass "No join.token patterns remain"
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi

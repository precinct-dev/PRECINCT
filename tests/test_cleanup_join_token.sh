#!/usr/bin/env bash
# test_cleanup_join_token.sh -- Verifies legacy join-token artifacts are removed
# and no stale references remain in the codebase.
#
# Story: OC-fl8h -- Remove legacy join-token artifacts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
FAIL=0
TOTAL=0

pass() {
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
    echo "[PASS] $1"
}

fail() {
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
    echo "[FAIL] $1" >&2
    if [ -n "${2:-}" ]; then
        echo "       Detail: $2" >&2
    fi
}

# ---------------------------------------------------------------------------
# AC 1: deploy/compose/Dockerfile.token-generator is deleted
# ---------------------------------------------------------------------------
echo ""
echo "=== AC 1: Dockerfile.token-generator deleted ==="

if [ -f "$PROJECT_ROOT/deploy/compose/Dockerfile.token-generator" ]; then
    fail "deploy/compose/Dockerfile.token-generator still exists"
else
    pass "deploy/compose/Dockerfile.token-generator is deleted"
fi

# ---------------------------------------------------------------------------
# AC 2: scripts/generate-spire-token.sh is deleted
# ---------------------------------------------------------------------------
echo ""
echo "=== AC 2: generate-spire-token.sh deleted ==="

if [ -f "$PROJECT_ROOT/scripts/generate-spire-token.sh" ]; then
    fail "scripts/generate-spire-token.sh still exists"
else
    pass "scripts/generate-spire-token.sh is deleted"
fi

# ---------------------------------------------------------------------------
# AC 5: No references to deleted files remain in codebase
# ---------------------------------------------------------------------------
echo ""
echo "=== AC 5: No references to deleted files ==="

# Search for Dockerfile.token-generator references (excluding this test file)
DOCKERFILE_REFS=$(grep -rl 'Dockerfile\.token-generator' "$PROJECT_ROOT" \
    --include='*.sh' --include='*.yml' --include='*.yaml' --include='*.md' \
    --include='*.json' --include='*.env' --include='*.html' --include='*.go' \
    --include='Makefile' --include='Dockerfile*' 2>/dev/null \
    | grep -v 'test_cleanup_join_token.sh' || true)
if [ -n "$DOCKERFILE_REFS" ]; then
    fail "Found references to Dockerfile.token-generator" "$DOCKERFILE_REFS"
else
    pass "No references to Dockerfile.token-generator in codebase"
fi

# Search for generate-spire-token references (excluding this test file)
SCRIPT_REFS=$(grep -rl 'generate-spire-token' "$PROJECT_ROOT" \
    --include='*.sh' --include='*.yml' --include='*.yaml' --include='*.md' \
    --include='*.json' --include='*.env' --include='*.html' --include='*.go' \
    --include='Makefile' --include='Dockerfile*' 2>/dev/null \
    | grep -v 'test_cleanup_join_token.sh' || true)
if [ -n "$SCRIPT_REFS" ]; then
    fail "Found references to generate-spire-token" "$SCRIPT_REFS"
else
    pass "No references to generate-spire-token in codebase (excluding this test)"
fi

# ---------------------------------------------------------------------------
# AC 6: No references to spire-token-generator in active compose/config files
# ---------------------------------------------------------------------------
echo ""
echo "=== AC 6: No spire-token-generator in active compose/config files ==="

# Check main docker-compose files and config files
ACTIVE_COMPOSE_CONFIG=(
    "$PROJECT_ROOT/deploy/compose/docker-compose.yml"
    "$PROJECT_ROOT/deploy/compose/docker-compose.prod-intent.yml"
    "$PROJECT_ROOT/deploy/compose/docker-compose.strict.yml"
    "$PROJECT_ROOT/deploy/compose/docker-compose.mock.yml"
    "$PROJECT_ROOT/deploy/compose/docker-compose.real.yml"
    "$PROJECT_ROOT/config/compose-production-intent-policy.json"
    "$PROJECT_ROOT/config/compose-production-intent.env"
    "$PROJECT_ROOT/scripts/compose-bootstrap-verify.sh"
    "$PROJECT_ROOT/Makefile"
)

ACTIVE_REFS=""
for f in "${ACTIVE_COMPOSE_CONFIG[@]}"; do
    if [ -f "$f" ] && grep -q 'spire-token-generator' "$f" 2>/dev/null; then
        ACTIVE_REFS="$ACTIVE_REFS $f"
    fi
done

if [ -n "$ACTIVE_REFS" ]; then
    fail "Found spire-token-generator in active compose/config files" "$ACTIVE_REFS"
else
    pass "No spire-token-generator references in active compose/config files"
fi

# ---------------------------------------------------------------------------
# AC 7: No join_token/join-token references in register-spire-entries.sh comments
# ---------------------------------------------------------------------------
echo ""
echo "=== AC 7: No join_token/join-token in register-spire-entries.sh ==="

REGISTER_SCRIPT="$PROJECT_ROOT/scripts/register-spire-entries.sh"
if [ ! -f "$REGISTER_SCRIPT" ]; then
    fail "scripts/register-spire-entries.sh not found"
else
    JOIN_REFS=$(grep -n 'join_token\|join-token' "$REGISTER_SCRIPT" 2>/dev/null || true)
    if [ -n "$JOIN_REFS" ]; then
        fail "Found join_token/join-token in register-spire-entries.sh" "$JOIN_REFS"
    else
        pass "No join_token/join-token references in register-spire-entries.sh"
    fi
fi

# ---------------------------------------------------------------------------
# AC 3: register-spire-entries.sh comments updated to reference x509pop
# ---------------------------------------------------------------------------
echo ""
echo "=== AC 3: register-spire-entries.sh references x509pop ==="

if [ -f "$REGISTER_SCRIPT" ]; then
    if grep -q 'x509pop' "$REGISTER_SCRIPT" 2>/dev/null; then
        pass "register-spire-entries.sh references x509pop"
    else
        fail "register-spire-entries.sh does not reference x509pop"
    fi
fi

# ---------------------------------------------------------------------------
# AC 4: deployment-patterns.md references x509pop for compose
# ---------------------------------------------------------------------------
echo ""
echo "=== AC 4: deployment-patterns.md references x509pop ==="

DEPLOY_PATTERNS="$PROJECT_ROOT/docs/architecture/deployment-patterns.md"
if [ ! -f "$DEPLOY_PATTERNS" ]; then
    fail "docs/architecture/deployment-patterns.md not found"
else
    if grep -q 'x509pop' "$DEPLOY_PATTERNS" 2>/dev/null; then
        pass "deployment-patterns.md references x509pop"
    else
        fail "deployment-patterns.md does not reference x509pop"
    fi

    # Verify no join_token/join-token remain outside the "Historical note" section
    # The story allows join_token references as "historical reference or K8s context"
    # The historical note is a clearly labeled paragraph starting with "**Historical note**"
    PATTERN_JOIN_COUNT=$(grep -c 'join_token\|join-token' "$DEPLOY_PATTERNS" 2>/dev/null || echo "0")
    HISTORICAL_JOIN_COUNT=$(sed -n '/\*\*Historical note\*\*/,/^$/p' "$DEPLOY_PATTERNS" \
        | grep -c 'join_token\|join-token' 2>/dev/null || echo "0")
    ACTIVE_JOIN_COUNT=$((PATTERN_JOIN_COUNT - HISTORICAL_JOIN_COUNT))
    if [ "$ACTIVE_JOIN_COUNT" -gt 0 ]; then
        fail "deployment-patterns.md has $ACTIVE_JOIN_COUNT active join_token/join-token references outside historical notes"
    else
        pass "deployment-patterns.md has no active join_token/join-token references (historical context only)"
    fi
fi

# ---------------------------------------------------------------------------
# AC 8: No active Makefile targets reference deleted files
# ---------------------------------------------------------------------------
echo ""
echo "=== AC 8: No Makefile targets reference deleted files ==="

MAKEFILE="$PROJECT_ROOT/Makefile"
if [ ! -f "$MAKEFILE" ]; then
    fail "Makefile not found"
else
    MAKEFILE_REFS=$(grep -n 'Dockerfile\.token-generator\|generate-spire-token\|spire-token-generator' "$MAKEFILE" 2>/dev/null || true)
    if [ -n "$MAKEFILE_REFS" ]; then
        fail "Makefile references deleted artifacts" "$MAKEFILE_REFS"
    else
        pass "No Makefile targets reference deleted files"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================"
echo "Results: $PASS passed, $FAIL failed, $TOTAL total"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi

echo ""
echo "test_cleanup_join_token: ALL PASSED"

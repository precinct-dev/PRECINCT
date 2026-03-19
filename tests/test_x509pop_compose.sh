#!/bin/sh
# Tests for OC-b9g1: Verify x509pop attestation configuration across all modified files.
# These are file-content unit tests (no containers needed).

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0

pass() {
    PASS=$((PASS + 1))
    echo "  PASS: $1"
}

fail() {
    FAIL=$((FAIL + 1))
    echo "  FAIL: $1"
}

echo "=== OC-b9g1: x509pop attestation file-content tests ==="
echo ""

# ---- server.conf ----
echo "[server.conf]"
SERVER_CONF="$REPO_ROOT/config/spire/server.conf"

if grep -q 'NodeAttestor "x509pop"' "$SERVER_CONF"; then
    pass "server.conf contains NodeAttestor x509pop"
else
    fail "server.conf missing NodeAttestor x509pop"
fi

if grep -q 'join_token' "$SERVER_CONF"; then
    fail "server.conf still references join_token"
else
    pass "server.conf does not reference join_token"
fi

if grep -q 'ca_bundle_path' "$SERVER_CONF"; then
    pass "server.conf has ca_bundle_path"
else
    fail "server.conf missing ca_bundle_path"
fi

echo ""

# ---- agent.conf ----
echo "[agent.conf]"
AGENT_CONF="$REPO_ROOT/config/spire/agent.conf"

if grep -q 'NodeAttestor "x509pop"' "$AGENT_CONF"; then
    pass "agent.conf contains NodeAttestor x509pop"
else
    fail "agent.conf missing NodeAttestor x509pop"
fi

if grep -q 'join_token' "$AGENT_CONF"; then
    fail "agent.conf still references join_token"
else
    pass "agent.conf does not reference join_token"
fi

if grep -q 'private_key_path' "$AGENT_CONF"; then
    pass "agent.conf has private_key_path"
else
    fail "agent.conf missing private_key_path"
fi

if grep -q 'certificate_path' "$AGENT_CONF"; then
    pass "agent.conf has certificate_path"
else
    fail "agent.conf missing certificate_path"
fi

if grep -q 'insecure_bootstrap = true' "$AGENT_CONF"; then
    pass "agent.conf retains insecure_bootstrap = true"
else
    fail "agent.conf missing insecure_bootstrap = true"
fi

echo ""

# ---- docker-compose.yml ----
echo "[docker-compose.yml]"
COMPOSE="$REPO_ROOT/deploy/compose/docker-compose.yml"

if grep -q 'spire-token-generator' "$COMPOSE"; then
    fail "docker-compose.yml still references spire-token-generator"
else
    pass "docker-compose.yml does not reference spire-token-generator"
fi

if grep -q 'x509pop-ca-bundle.crt' "$COMPOSE"; then
    pass "docker-compose.yml spire-server mounts x509pop-ca-bundle.crt"
else
    fail "docker-compose.yml missing x509pop-ca-bundle.crt mount"
fi

if grep -q 'x509pop-agent.crt' "$COMPOSE"; then
    pass "docker-compose.yml spire-agent mounts x509pop-agent.crt"
else
    fail "docker-compose.yml missing x509pop-agent.crt mount"
fi

if grep -q 'x509pop-agent.key' "$COMPOSE"; then
    pass "docker-compose.yml spire-agent mounts x509pop-agent.key"
else
    fail "docker-compose.yml missing x509pop-agent.key mount"
fi

if grep -q 'spire-join-token' "$COMPOSE"; then
    fail "docker-compose.yml still mounts spire-join-token"
else
    pass "docker-compose.yml does not mount spire-join-token"
fi

if grep -q 'spire-tools:latest' "$COMPOSE"; then
    pass "docker-compose.yml spire-entry-registrar uses spire-tools:latest"
else
    fail "docker-compose.yml spire-entry-registrar not using spire-tools:latest"
fi

if grep -q 'join_token' "$COMPOSE" || grep -q 'join-token' "$COMPOSE"; then
    fail "docker-compose.yml still contains join_token or join-token reference"
else
    pass "docker-compose.yml has no join_token or join-token references"
fi

echo ""

# ---- docker-compose.mcpserver-test.yml ----
echo "[docker-compose.mcpserver-test.yml]"
TEST_COMPOSE="$REPO_ROOT/deploy/compose/docker-compose.mcpserver-test.yml"

if grep -q 'spire-token-generator' "$TEST_COMPOSE"; then
    fail "mcpserver-test.yml still references spire-token-generator"
else
    pass "mcpserver-test.yml does not reference spire-token-generator"
fi

if grep -q 'spire-tools:latest' "$TEST_COMPOSE"; then
    pass "mcpserver-test.yml uses spire-tools:latest"
else
    fail "mcpserver-test.yml not using spire-tools:latest"
fi

echo ""

# ---- spire-agent-wrapper.sh ----
echo "[spire-agent-wrapper.sh]"
WRAPPER="$REPO_ROOT/scripts/spire-agent-wrapper.sh"

if grep -qi 'token' "$WRAPPER"; then
    fail "spire-agent-wrapper.sh still contains 'token' reference"
else
    pass "spire-agent-wrapper.sh does not contain 'token' reference"
fi

if grep -qi 'joinToken' "$WRAPPER"; then
    fail "spire-agent-wrapper.sh still contains 'joinToken' reference"
else
    pass "spire-agent-wrapper.sh does not contain 'joinToken' reference"
fi

if grep -q 'rm -f' "$WRAPPER"; then
    pass "spire-agent-wrapper.sh retains stale data cleanup"
else
    fail "spire-agent-wrapper.sh missing stale data cleanup"
fi

if grep -q 'exec /opt/spire/bin/spire-agent' "$WRAPPER"; then
    pass "spire-agent-wrapper.sh execs spire-agent"
else
    fail "spire-agent-wrapper.sh missing spire-agent exec"
fi

echo ""

# ---- Dockerfile.spire-agent ----
echo "[Dockerfile.spire-agent]"
DOCKERFILE_AGENT="$REPO_ROOT/deploy/compose/Dockerfile.spire-agent"

if grep -qi 'join' "$DOCKERFILE_AGENT" || grep -qi 'token' "$DOCKERFILE_AGENT"; then
    fail "Dockerfile.spire-agent still contains join/token reference"
else
    pass "Dockerfile.spire-agent has no join/token references"
fi

echo ""

# ---- Dockerfile.spire-tools ----
echo "[Dockerfile.spire-tools]"
DOCKERFILE_TOOLS="$REPO_ROOT/deploy/compose/Dockerfile.spire-tools"

if [ -f "$DOCKERFILE_TOOLS" ]; then
    pass "Dockerfile.spire-tools exists"
else
    fail "Dockerfile.spire-tools does not exist"
fi

if grep -q 'spire-server' "$DOCKERFILE_TOOLS"; then
    pass "Dockerfile.spire-tools copies spire-server binary"
else
    fail "Dockerfile.spire-tools missing spire-server binary"
fi

if grep -qi 'token' "$DOCKERFILE_TOOLS"; then
    fail "Dockerfile.spire-tools contains token reference"
else
    pass "Dockerfile.spire-tools has no token references"
fi

echo ""

# ---- Cross-file: no join_token or join-token in any modified file ----
echo "[Cross-file: no join_token/join-token in modified files]"
MODIFIED_FILES="$SERVER_CONF $AGENT_CONF $COMPOSE $TEST_COMPOSE $WRAPPER $DOCKERFILE_AGENT $DOCKERFILE_TOOLS"
JOIN_REFS=$(grep -rl 'join.token\|join_token' $MODIFIED_FILES 2>/dev/null || true)
if [ -n "$JOIN_REFS" ]; then
    fail "join_token/join-token found in: $JOIN_REFS"
else
    pass "No join_token/join-token references in any modified file"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0

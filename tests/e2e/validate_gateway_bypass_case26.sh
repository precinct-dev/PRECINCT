#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ART_DIR="$ROOT_DIR/tests/e2e/artifacts"
GO_FILE="$ROOT_DIR/examples/go/main.go"
PY_FILE="$ROOT_DIR/examples/python/demo.py"

# Docker Compose command (same as common.sh)
COMPOSE_FILE="${ROOT_DIR}/deploy/compose/docker-compose.yml"
DC="docker compose -f ${COMPOSE_FILE}"

compose_log="${1:-}"
k8s_log="${2:-}"

# --- Log discovery ---
# Priority: (1) explicit args, (2) artifact files, (3) live compose logs, (4) skip

if [ -z "$compose_log" ]; then
    compose_log="$(ls -1t "$ART_DIR"/rfa-02lt-demo-compose-*.log 2>/dev/null | head -1 || true)"
fi
if [ -z "$k8s_log" ]; then
    k8s_log="$(ls -1t "$ART_DIR"/rfa-02lt-demo-k8s-*.log 2>/dev/null | head -1 || true)"
fi

# If compose log is missing, try collecting from a running compose stack
compose_from_live=false
if [ -z "$compose_log" ]; then
    # Check if the compose stack is running by looking for the gateway container
    if $DC ps --format '{{.Status}}' mcp-security-gateway 2>/dev/null | grep -qi "up"; then
        echo "[INFO] No artifact logs found; collecting live logs from running compose stack"
        mkdir -p "$ART_DIR"
        compose_log="$ART_DIR/rfa-02lt-demo-compose-live.log"
        $DC logs 2>/dev/null > "$compose_log"
        compose_from_live=true

        # Ensure temp file is cleaned up on any exit (set -e, fail(), etc.)
        cleanup_live_log() {
            if [ "$compose_from_live" = true ] && [ -f "$compose_log" ]; then
                rm -f "$compose_log"
            fi
        }
        trap cleanup_live_log EXIT

        # Check if live logs contain case26 demo activity
        if ! grep -q "Gateway -- Go SDK Demo\|case26\|bypass" "$compose_log" 2>/dev/null; then
            echo "[SKIP] Live compose logs contain no case26 demo activity. Run 'make demo-compose' first."
            exit 0
        fi
    fi
fi

# Decide whether we can proceed
has_compose=false
has_k8s=false
[ -n "$compose_log" ] && [ -f "$compose_log" ] && has_compose=true
[ -n "$k8s_log" ] && [ -f "$k8s_log" ] && has_k8s=true

if [ "$has_compose" = false ] && [ "$has_k8s" = false ]; then
    echo "[SKIP] Gateway bypass case26 validation: no demo artifact logs found and compose stack is not running."
    echo "       Run 'make demo-compose' or 'make demo-k8s' first, or start the compose stack."
    exit 0
fi

fail() {
    echo "[FAIL] $1"
    exit 1
}

pass() {
    echo "[PASS] $1"
}

require_file() {
    local path="$1"
    [ -n "$path" ] || fail "Missing required log path"
    [ -f "$path" ] || fail "File not found: $path"
}

count_case26_proof() {
    local log_file="$1"
    local sdk_marker="$2"
    local proof_marker="$3"
    # Strip ANSI escape codes before matching (logs may contain terminal colours)
    sed 's/\x1b\[[0-9;]*m//g' "$log_file" | awk -v sdk="$sdk_marker" -v proof="$proof_marker" '
        /Gateway -- Go SDK Demo/ {active = (sdk == "go"); in_case = 0}
        /Gateway -- Python SDK Demo/ {active = (sdk == "python"); in_case = 0}
        active && /\[26\/28\] Gateway-only path/ {in_case = 1; next}
        in_case && /\[27\/28\]/ {in_case = 0}
        in_case && $0 ~ proof {count++}
        END {print count + 0}
    '
}

# AC #2 safety: strict-mode guard must remain explicit in both SDK demos.
grep -Fq 'if os.Getenv("DEMO_STRICT_DEEPSCAN") != "1" && isLikelyGatewayModelRouteTimeout(err)' "$GO_FILE" \
    || fail "Go strict/non-strict timeout guard missing from examples/go/main.go"
grep -Fq 'if os.getenv("DEMO_STRICT_DEEPSCAN") != "1" and is_likely_gateway_model_route_timeout(e):' "$PY_FILE" \
    || fail "Python strict/non-strict timeout guard missing from examples/python/demo.py"
pass "Strict-mode fail-closed timeout guards present in Go and Python demos"

# Validate available logs -- skip modes that have no log
if [ "$has_compose" = true ]; then
    require_file "$compose_log"
    pass "Using compose log: $compose_log"

    # Compose runs strict mode in demo/run.sh, so case26 must not rely on non-strict timeout variance.
    compose_timeout_variance="$(count_case26_proof "$compose_log" go 'accepted runtime variance')"
    compose_timeout_variance_py="$(count_case26_proof "$compose_log" python 'accepted runtime variance')"
    if [ "$compose_timeout_variance" -gt 0 ] || [ "$compose_timeout_variance_py" -gt 0 ]; then
        fail "Compose case26 used non-strict timeout variance path; strict compose assertion regressed"
    fi
    pass "Compose case26 stays on strict path (no non-strict timeout variance marker)"
fi

if [ "$has_k8s" = true ]; then
    require_file "$k8s_log"
    pass "Using k8s log: $k8s_log"
fi

# Deterministic parity check: both SDK demos must pass case26 in available logs.
for mode in compose k8s; do
    if [ "$mode" = "compose" ] && [ "$has_compose" = false ]; then
        echo "[SKIP] No compose log available -- skipping compose parity check"
        continue
    fi
    if [ "$mode" = "k8s" ] && [ "$has_k8s" = false ]; then
        echo "[SKIP] No k8s log available -- skipping k8s parity check"
        continue
    fi

    if [ "$mode" = "compose" ]; then
        log="$compose_log"
    else
        log="$k8s_log"
    fi

    go_passes="$(count_case26_proof "$log" go 'PROOF:.*PASS')"
    go_fails="$(count_case26_proof "$log" go 'PROOF:.*FAIL')"
    py_passes="$(count_case26_proof "$log" python 'PROOF:.*PASS')"
    py_fails="$(count_case26_proof "$log" python 'PROOF:.*FAIL')"

    [ "$go_passes" -ge 1 ] || fail "No Go case26 PASS proof found in $mode log"
    [ "$py_passes" -ge 1 ] || fail "No Python case26 PASS proof found in $mode log"
    [ "$go_fails" -eq 0 ] || fail "Go case26 FAIL proof found in $mode log"
    [ "$py_fails" -eq 0 ] || fail "Python case26 FAIL proof found in $mode log"
    pass "$mode case26 parity verified (Go PASS=$go_passes, Python PASS=$py_passes)"
done

pass "Gateway bypass case26 conformance validation passed"

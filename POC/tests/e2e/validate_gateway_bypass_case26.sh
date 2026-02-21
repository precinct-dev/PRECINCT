#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ART_DIR="$ROOT_DIR/tests/e2e/artifacts"
GO_FILE="$ROOT_DIR/demo/go/main.go"
PY_FILE="$ROOT_DIR/demo/python/demo.py"

compose_log="${1:-}"
k8s_log="${2:-}"

if [ -z "$compose_log" ]; then
    compose_log="$(ls -1t "$ART_DIR"/rfa-02lt-demo-compose-*.log 2>/dev/null | head -1 || true)"
fi
if [ -z "$k8s_log" ]; then
    k8s_log="$(ls -1t "$ART_DIR"/rfa-02lt-demo-k8s-*.log 2>/dev/null | head -1 || true)"
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
    awk -v sdk="$sdk_marker" -v proof="$proof_marker" '
        /PRECINCT Gateway -- Go SDK Demo/ {active = (sdk == "go"); in_case = 0}
        /PRECINCT Gateway -- Python SDK Demo/ {active = (sdk == "python"); in_case = 0}
        active && /\[26\/28\] Gateway-only path/ {in_case = 1; next}
        in_case && /\[27\/28\]/ {in_case = 0}
        in_case && $0 ~ proof {count++}
        END {print count + 0}
    ' "$log_file"
}

require_file "$compose_log"
require_file "$k8s_log"
pass "Using compose log: $compose_log"
pass "Using k8s log: $k8s_log"

# AC #2 safety: strict-mode guard must remain explicit in both SDK demos.
grep -Fq 'if os.Getenv("DEMO_STRICT_DEEPSCAN") != "1" && isLikelyGatewayModelRouteTimeout(err)' "$GO_FILE" \
    || fail "Go strict/non-strict timeout guard missing from demo/go/main.go"
grep -Fq 'if os.getenv("DEMO_STRICT_DEEPSCAN") != "1" and is_likely_gateway_model_route_timeout(e):' "$PY_FILE" \
    || fail "Python strict/non-strict timeout guard missing from demo/python/demo.py"
pass "Strict-mode fail-closed timeout guards present in Go and Python demos"

# Compose runs strict mode in demo/run.sh, so case26 must not rely on non-strict timeout variance.
compose_timeout_variance="$(count_case26_proof "$compose_log" go 'accepted runtime variance')"
compose_timeout_variance_py="$(count_case26_proof "$compose_log" python 'accepted runtime variance')"
if [ "$compose_timeout_variance" -gt 0 ] || [ "$compose_timeout_variance_py" -gt 0 ]; then
    fail "Compose case26 used non-strict timeout variance path; strict compose assertion regressed"
fi
pass "Compose case26 stays on strict path (no non-strict timeout variance marker)"

# Deterministic parity check: both SDK demos must pass case26 in both Compose and K8s logs.
for mode in compose k8s; do
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

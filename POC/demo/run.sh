#!/usr/bin/env bash
# demo/run.sh -- Orchestrate E2E demos against Docker Compose or K8s.
# Both demos run as containers -- no local Go/Python/httpx needed.
#
# Usage: ./demo/run.sh {compose|k8s|both} [--skip-setup]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODE="${1:-compose}"
SKIP_SETUP=false

for arg in "$@"; do
    if [ "$arg" = "--skip-setup" ]; then
        SKIP_SETUP=true
    fi
done

# Docker image names
GO_IMAGE="demo-go-sdk"
PY_IMAGE="demo-python-sdk"
COMPOSE_NETWORK="agentic-security-network"
PF_PID=""

# Lua script for targeted rate-limit key cleanup (avoids FLUSHALL).
# Scans for ratelimit:* keys only, leaving other KeyDB data intact.
RATELIMIT_FLUSH_LUA='
local count = 0
local cursor = "0"
repeat
    local result = redis.call("SCAN", cursor, "MATCH", "ratelimit:*", "COUNT", 100)
    cursor = result[1]
    local keys = result[2]
    for i, key in ipairs(keys) do
        redis.call("DEL", key)
        count = count + 1
    end
until cursor == "0"
return count
'

cleanup() { [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null; true; }

# Colors
RESET="\033[0m"
GREEN="\033[32m"
RED="\033[31m"
CYAN="\033[36m"
BOLD="\033[1m"

log() { echo -e "${CYAN}==> $1${RESET}"; }
err() { echo -e "${RED}ERROR: $1${RESET}" >&2; }
ok()  { echo -e "${GREEN}OK:  $1${RESET}"; }

# --------------------------------------------------------------------------
# Pre-flight checks
# --------------------------------------------------------------------------
preflight() {
    log "Pre-flight checks"
    local missing=0

    if ! command -v docker >/dev/null 2>&1; then
        err "docker not found"; missing=1
    fi

    if [ "$missing" -ne 0 ]; then
        err "Missing prerequisites. Aborting."
        exit 1
    fi
    ok "All prerequisites found (docker)"
}

# --------------------------------------------------------------------------
# Build demo container images
# --------------------------------------------------------------------------
build_images() {
    log "Building Go SDK demo image"
    docker build -t "$GO_IMAGE" -f "$SCRIPT_DIR/go/Dockerfile" "$POC_DIR"

    log "Building Python SDK demo image"
    docker build -t "$PY_IMAGE" -f "$SCRIPT_DIR/python/Dockerfile" "$POC_DIR"

    ok "Demo images built"
}

# --------------------------------------------------------------------------
# Infrastructure management
# --------------------------------------------------------------------------
start_compose() {
    log "Starting Docker Compose stack"
    make -C "$POC_DIR" up
}

start_k8s() {
    log "Deploying to Docker Desktop K8s"
    kubectl config use-context docker-desktop 2>/dev/null || {
        err "docker-desktop context not found. Is Docker Desktop K8s enabled?"
        exit 1
    }
    make -C "$POC_DIR" k8s-up
}

# --------------------------------------------------------------------------
# Health check with timeout
# --------------------------------------------------------------------------
wait_for_health() {
    local url="$1"
    local timeout=60
    local elapsed=0

    log "Waiting for gateway health at ${url}/health (timeout: ${timeout}s)"
    while [ "$elapsed" -lt "$timeout" ]; do
        if curl -sf "${url}/health" >/dev/null 2>&1; then
            echo ""
            ok "Gateway is healthy"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
        printf "."
    done
    echo ""
    err "Gateway did not become healthy within ${timeout}s"
    return 1
}

# --------------------------------------------------------------------------
# Run containerized demos
# --------------------------------------------------------------------------
run_go_demo() {
    local url="$1"
    local network="$2"
    log "Running Go SDK demo (container)"
    docker run --rm --network "$network" "$GO_IMAGE" --gateway-url="$url"
    return $?
}

run_python_demo() {
    local url="$1"
    local network="$2"
    log "Running Python SDK demo (container)"
    docker run --rm --network "$network" "$PY_IMAGE" --gateway-url="$url"
    return $?
}

# --------------------------------------------------------------------------
# Proof collection
# --------------------------------------------------------------------------
collect_audit_proof_compose() {
    log "Audit hash-chain proof (Docker Compose logs)"
    echo ""
    docker compose -f "$POC_DIR/docker-compose.yml" logs mcp-security-gateway 2>/dev/null \
        | grep -i "prev_hash" | tail -5 || echo "  (no prev_hash entries found in logs)"
    echo ""
}

collect_audit_proof_k8s() {
    log "Audit hash-chain proof (K8s logs)"
    echo ""
    kubectl -n gateway logs deploy/mcp-security-gateway --tail=200 2>/dev/null \
        | grep -i "prev_hash" | tail -5 || echo "  (no prev_hash entries found in logs)"
    echo ""
}

collect_mcp_transport_proof_compose() {
    log "MCP transport detection proof (Docker Compose logs)"
    echo ""
    # Check gateway logs for MCP transport initialization
    docker compose -f "$POC_DIR/docker-compose.yml" logs mcp-security-gateway 2>/dev/null \
        | grep -i -E "streamable|mcp.*transport|mcp.*session|mock-mcp|transport.*mode" | tail -10 \
        || echo "  (no MCP transport entries found in logs)"
    echo ""
    # Check mock MCP server logs for session activity
    docker compose -f "$POC_DIR/docker-compose.yml" logs mock-mcp-server 2>/dev/null \
        | grep -i -E "session|tools" | tail -10 \
        || echo "  (no mock MCP server activity found)"
    echo ""
}

collect_dlp_injection_proof_compose() {
    log "DLP injection detection proof (Docker Compose logs)"
    echo ""
    docker compose -f "$POC_DIR/docker-compose.yml" logs mcp-security-gateway 2>/dev/null \
        | grep -E '"safezone_flags".*"potential_injection"|"potential_injection"' | tail -5 \
        || echo "  (no injection detection entries found in logs)"
    echo ""
}

collect_dlp_credential_proof_compose() {
    log "DLP credential blocking proof (Docker Compose logs)"
    echo ""
    docker compose -f "$POC_DIR/docker-compose.yml" logs mcp-security-gateway 2>/dev/null \
        | grep -E '"safezone_flags".*"blocked_content"|dlp_credentials_detected' | tail -5 \
        || echo "  (no credential blocking entries found in logs)"
    echo ""
}

collect_spike_token_proof_compose() {
    log "SPIKE token processing proof (Docker Compose logs)"
    echo ""
    docker compose -f "$POC_DIR/docker-compose.yml" logs mcp-security-gateway 2>/dev/null \
        | grep -i -E "token_substitution|spike.*ref|spike.*redeem|token.*redeem" | tail -10 \
        || echo "  (no SPIKE token processing entries found in logs)"
    echo ""
}

collect_dlp_injection_proof_k8s() {
    log "DLP injection detection proof (K8s logs)"
    echo ""
    kubectl -n gateway logs deploy/mcp-security-gateway --tail=200 2>/dev/null \
        | grep -i -E "potential_injection|injection.*detected|injection.*flagged" | tail -10 \
        || echo "  (no injection detection entries found in logs)"
    echo ""
}

collect_dlp_credential_proof_k8s() {
    log "DLP credential blocking proof (K8s logs)"
    echo ""
    kubectl -n gateway logs deploy/mcp-security-gateway --tail=200 2>/dev/null \
        | grep -i -E "credential.*block|secret.*block|dlp.*block|sensitive.*data" | tail -10 \
        || echo "  (no credential blocking entries found in logs)"
    echo ""
}

collect_spike_token_proof_k8s() {
    log "SPIKE token processing proof (K8s logs)"
    echo ""
    kubectl -n gateway logs deploy/mcp-security-gateway --tail=200 2>/dev/null \
        | grep -i -E "token_substitution|spike.*ref|spike.*redeem|token.*redeem" | tail -10 \
        || echo "  (no SPIKE token processing entries found in logs)"
    echo ""
}

print_otel_proof() {
    log "OpenTelemetry traces"
    echo "  Phoenix UI: http://localhost:6006"
    echo "  Open in browser to inspect distributed traces from the demo calls."
    echo ""
}

# --------------------------------------------------------------------------
# Run a full demo cycle for a given mode
# --------------------------------------------------------------------------
run_demo_cycle() {
    local mode="$1"
    local url
    local network

    if [ "$mode" = "compose" ]; then
        # Inside the Docker network, gateway is at service name:port
        url="http://mcp-security-gateway:9090"
        network="$COMPOSE_NETWORK"
        if [ "$SKIP_SETUP" = false ]; then
            start_compose
        fi
        # Clear rate-limit keys and restart gateway to reset circuit breaker
        # from any previous run. Without this, accumulated 502s keep the
        # circuit breaker open and subsequent demo runs fail with 503.
        log "Clearing rate-limit keys and restarting gateway"
        docker compose -f "$POC_DIR/docker-compose.yml" exec -T keydb keydb-cli EVAL "$RATELIMIT_FLUSH_LUA" 0 >/dev/null 2>&1 || true
        docker compose -f "$POC_DIR/docker-compose.yml" restart mcp-security-gateway >/dev/null 2>&1
        # Health check via localhost (host-side port mapping)
        wait_for_health "http://localhost:9090" || exit 1
    elif [ "$mode" = "k8s" ]; then
        # K8s (Docker Desktop): connect demo containers to "kind" network
        # so they can reach the K8s node's NodePort directly.
        local node_ip
        node_ip=$(docker inspect desktop-control-plane --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null | head -1)
        if [ -z "$node_ip" ]; then
            err "Cannot find K8s node IP. Is Docker Desktop K8s running?"
            exit 1
        fi
        url="http://${node_ip}:30090"
        network="kind"
        if [ "$SKIP_SETUP" = false ]; then
            start_k8s
        fi
        # Restart gateway to reset circuit breaker state
        log "Restarting gateway to reset circuit breaker state"
        kubectl -n gateway rollout restart deploy/mcp-security-gateway >/dev/null 2>&1 || true
        sleep 5
        # Health check: use port-forward since NodePort isn't exposed on host
        kubectl -n gateway port-forward svc/mcp-security-gateway 30090:9090 >/dev/null 2>&1 &
        PF_PID=$!
        trap cleanup EXIT
        wait_for_health "http://localhost:30090" || { cleanup; exit 1; }
    else
        err "Unknown mode: $mode (expected compose|k8s|both)"
        exit 1
    fi

    echo ""
    echo -e "${BOLD}============================================${RESET}"
    echo -e "${BOLD}  E2E Demo -- mode: $mode${RESET}"
    echo -e "${BOLD}============================================${RESET}"
    echo ""

    local go_ok=0
    local py_ok=0

    run_go_demo "$url" "$network" || go_ok=1
    echo ""

    # Reset rate limits between demos (both use same SPIFFE ID).
    # Rate limits persist in KeyDB, so gateway restart alone is insufficient.
    if [ "$mode" = "compose" ]; then
        log "Clearing rate-limit keys and restarting gateway for Python demo"
        docker compose -f "$POC_DIR/docker-compose.yml" exec -T keydb keydb-cli EVAL "$RATELIMIT_FLUSH_LUA" 0 >/dev/null 2>&1 || true
        docker compose -f "$POC_DIR/docker-compose.yml" restart mcp-security-gateway >/dev/null 2>&1
        wait_for_health "http://localhost:9090" || exit 1
    elif [ "$mode" = "k8s" ]; then
        log "Clearing rate-limit keys and restarting gateway for Python demo"
        kubectl -n data exec deploy/keydb -- keydb-cli EVAL "$RATELIMIT_FLUSH_LUA" 0 >/dev/null 2>&1 || true
        kubectl -n gateway rollout restart deploy/mcp-security-gateway >/dev/null 2>&1 || true
        kubectl -n gateway rollout status deploy/mcp-security-gateway --timeout=60s 2>/dev/null || true
        # Restart port-forward (old one died with old pod)
        cleanup
        sleep 2
        kubectl -n gateway port-forward svc/mcp-security-gateway 30090:9090 >/dev/null 2>&1 &
        PF_PID=$!
        wait_for_health "http://localhost:30090" || exit 1
    fi

    run_python_demo "$url" "$network" || py_ok=1
    echo ""

    # Collect proofs
    if [ "$mode" = "compose" ]; then
        collect_audit_proof_compose
        collect_mcp_transport_proof_compose
        collect_dlp_injection_proof_compose
        collect_dlp_credential_proof_compose
        collect_spike_token_proof_compose
    else
        collect_audit_proof_k8s
        collect_dlp_injection_proof_k8s
        collect_dlp_credential_proof_k8s
        collect_spike_token_proof_k8s
    fi
    print_otel_proof

    # Summary
    echo -e "${BOLD}============================================${RESET}"
    if [ "$go_ok" -eq 0 ] && [ "$py_ok" -eq 0 ]; then
        echo -e "  ${GREEN}ALL DEMOS PASSED ($mode)${RESET}"
    else
        [ "$go_ok" -ne 0 ] && echo -e "  ${RED}Go demo had failures${RESET}"
        [ "$py_ok" -ne 0 ] && echo -e "  ${RED}Python demo had failures${RESET}"
    fi
    echo -e "${BOLD}============================================${RESET}"
    echo ""

    return $((go_ok + py_ok))
}

# --------------------------------------------------------------------------
# Teardown
# --------------------------------------------------------------------------
teardown() {
    local mode="$1"
    log "Tearing down environment ($mode)"
    if [ "$mode" = "compose" ]; then
        docker compose -f "$POC_DIR/docker-compose.yml" down -v 2>/dev/null || true
    elif [ "$mode" = "k8s" ]; then
        make -C "$POC_DIR" k8s-down 2>/dev/null || true
    fi
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
main() {
    preflight
    build_images

    local total_failures=0
    local cycle1_failures=0
    local cycle2_failures=0

    case "$MODE" in
        compose|k8s)
            # Cycle 1: full setup
            log "=== Cycle 1 ==="
            run_demo_cycle "$MODE" || cycle1_failures=$?

            # Cycle 2: re-run on same environment (skip setup)
            log "Sleeping 5s before re-run cycle..."
            sleep 5
            SKIP_SETUP=true
            log "=== Cycle 2 (re-run) ==="
            run_demo_cycle "$MODE" || cycle2_failures=$?

            total_failures=$((cycle1_failures + cycle2_failures))

            # Auto-teardown (unconditional -- runs whether tests passed or failed)
            teardown "$MODE"
            ;;
        both)
            # Compose cycles
            log "=== Compose Cycle 1 ==="
            run_demo_cycle compose || cycle1_failures=$?
            log "Sleeping 5s before re-run cycle..."
            sleep 5
            SKIP_SETUP=true
            log "=== Compose Cycle 2 (re-run) ==="
            run_demo_cycle compose || cycle2_failures=$?
            total_failures=$((cycle1_failures + cycle2_failures))
            teardown compose

            # K8s cycles
            cycle1_failures=0
            cycle2_failures=0
            SKIP_SETUP=false
            log "=== K8s Cycle 1 ==="
            run_demo_cycle k8s || cycle1_failures=$?
            log "Sleeping 5s before re-run cycle..."
            sleep 5
            SKIP_SETUP=true
            log "=== K8s Cycle 2 (re-run) ==="
            run_demo_cycle k8s || cycle2_failures=$?
            total_failures=$((total_failures + cycle1_failures + cycle2_failures))
            teardown k8s
            ;;
        *)
            echo "Usage: $0 {compose|k8s|both} [--skip-setup]"
            exit 1
            ;;
    esac

    # Final summary
    echo ""
    echo -e "${BOLD}============================================${RESET}"
    if [ "$total_failures" -eq 0 ]; then
        echo -e "  ${GREEN}ALL CYCLES PASSED${RESET}"
    else
        echo -e "  ${RED}FAILURES DETECTED (exit code: $total_failures)${RESET}"
    fi
    echo -e "${BOLD}============================================${RESET}"

    exit "$total_failures"
}

main

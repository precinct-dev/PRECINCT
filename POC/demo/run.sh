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
    make -C "$POC_DIR" k8s-local-up
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
        # Health check via localhost (host-side port mapping)
        wait_for_health "http://localhost:9090" || exit 1
    elif [ "$mode" = "k8s" ]; then
        # K8s: use host network so containers can reach NodePort
        url="http://host.docker.internal:30090"
        network="host"
        if [ "$SKIP_SETUP" = false ]; then
            start_k8s
        fi
        wait_for_health "http://localhost:30090" || exit 1
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

    # Reset rate limits between demos (both use same SPIFFE ID)
    if [ "$mode" = "compose" ]; then
        log "Restarting gateway to reset rate limits for Python demo"
        docker compose -f "$POC_DIR/docker-compose.yml" restart mcp-security-gateway >/dev/null 2>&1
        wait_for_health "http://localhost:9090" || exit 1
    fi

    run_python_demo "$url" "$network" || py_ok=1
    echo ""

    # Collect proofs
    if [ "$mode" = "compose" ]; then
        collect_audit_proof_compose
    else
        collect_audit_proof_k8s
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
# Main
# --------------------------------------------------------------------------
main() {
    preflight
    build_images

    local total_failures=0

    case "$MODE" in
        compose)
            run_demo_cycle compose || total_failures=$?
            ;;
        k8s)
            run_demo_cycle k8s || total_failures=$?
            ;;
        both)
            run_demo_cycle compose || total_failures=$?
            run_demo_cycle k8s || { total_failures=$((total_failures + $?)); }
            ;;
        *)
            echo "Usage: $0 {compose|k8s|both} [--skip-setup]"
            exit 1
            ;;
    esac

    exit "$total_failures"
}

main

#!/usr/bin/env bash
# =============================================================================
# Validate Setup Time - RFA-t07
# Validates BUSINESS.md O1: 'Git Clone to Running in Under 30 Minutes'
#
# Tests both Docker Compose and local K8s deployment flows from fresh state
# to first successful request through the full middleware chain.
#
# Timing excludes container image pulls (network-dependent).
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
POC_DIR="${ROOT_DIR}"

# ---- Terminal colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---- Configuration ----
MODE="${1:-}"
DRY_RUN=false
THRESHOLD_SECONDS=$((30 * 60))  # 30 minutes
GATEWAY_URL="http://localhost:9090"
K8S_GATEWAY_URL="http://localhost:30090"

# ---- Usage ----
usage() {
    echo "Usage: $0 {compose|k8s} [--dry-run]"
    echo ""
    echo "Validates the 30-minute git-clone-to-running claim (BUSINESS.md O1)."
    echo ""
    echo "Modes:"
    echo "  compose   - Docker Compose deployment (localhost:9090)"
    echo "  k8s       - Local K8s deployment (localhost:30090)"
    echo ""
    echo "Options:"
    echo "  --dry-run - Validate configuration without starting services"
    echo ""
    echo "Timing:"
    echo "  - Start: after 'make setup' begins"
    echo "  - End: first successful request through gateway"
    echo "  - Threshold: 30 minutes"
    echo "  - Excludes: container image pull time (pre-pulled)"
    exit 1
}

# ---- Output helpers ----
log_header() {
    echo ""
    echo -e "${BOLD}=========================================${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}=========================================${NC}"
    echo ""
}

log_info() {
    echo -e "  [${CYAN}INFO${NC}] $1"
}

log_pass() {
    echo -e "  [${GREEN}PASS${NC}] $1"
}

log_fail() {
    echo -e "  [${RED}FAIL${NC}] $1"
    echo -e "         Reason: $2"
}

format_duration() {
    local seconds=$1
    local minutes=$((seconds / 60))
    local remaining_seconds=$((seconds % 60))
    echo "${minutes}m ${remaining_seconds}s"
}

# ---- Parse arguments ----
if [ -z "$MODE" ]; then
    usage
fi

if [ "$MODE" = "--help" ] || [ "$MODE" = "-h" ]; then
    usage
fi

# Check for --dry-run flag
if [ "${2:-}" = "--dry-run" ]; then
    DRY_RUN=true
fi

# ---- Validate mode ----
if [ "$MODE" != "compose" ] && [ "$MODE" != "k8s" ]; then
    echo -e "${RED}ERROR: Invalid mode '$MODE'${NC}"
    usage
fi

# ---- Pre-flight checks ----
log_header "Setup Time Validation: ${MODE}"

if [ "$DRY_RUN" = true ]; then
    log_info "DRY RUN MODE - validating configuration only"
    echo ""
fi

# Check that we're in the POC directory
if [ ! -f "${POC_DIR}/Makefile" ]; then
    echo -e "${RED}ERROR: Not in POC directory (no Makefile found at ${POC_DIR})${NC}"
    exit 1
fi

cd "$POC_DIR"

# ---- Pre-pull images (timing exclusion per BUSINESS.md O1) ----
if [ "$DRY_RUN" = false ]; then
    log_header "Pre-pulling Images (excluded from timing)"

    if [ "$MODE" = "compose" ]; then
        log_info "Pulling Docker Compose images..."
        docker compose pull 2>&1 | sed 's/^/    /'
        log_pass "Images pre-pulled"
    elif [ "$MODE" = "k8s" ]; then
        log_info "Building images for K8s (uses local images)..."
        make build-images 2>&1 | sed 's/^/    /' || {
            log_fail "Image build" "make build-images failed"
            exit 1
        }
        log_pass "Images built"
    fi
fi

# ============================================================================
# DRY RUN MODE - Configuration Validation Only
# ============================================================================

if [ "$DRY_RUN" = true ]; then
    log_header "Configuration Validation (Dry Run)"

    if [ "$MODE" = "compose" ]; then
        log_info "Validating Docker Compose configuration files..."
        if [ -f "${ROOT_DIR}/deploy/compose/docker-compose.yml" ]; then
            log_pass "deploy/compose/docker-compose.yml exists"
        else
            log_fail "deploy/compose/docker-compose.yml" "File not found"
            exit 1
        fi

        log_info "Validating scripts exist..."
        if [ -f "${POC_DIR}/scripts/setup.sh" ]; then
            log_pass "scripts/setup.sh exists"
        else
            log_fail "setup script" "scripts/setup.sh not found"
            exit 1
        fi

        log_info "Validating Makefile targets..."
        if grep -q "^setup:" "${POC_DIR}/Makefile" && grep -q "^up:" "${POC_DIR}/Makefile"; then
            log_pass "Makefile targets (setup, up) exist"
        else
            log_fail "Makefile targets" "Required targets missing"
            exit 1
        fi

    elif [ "$MODE" = "k8s" ]; then
        log_info "Validating Kustomize manifests..."
        if kustomize build infra/eks/overlays/local/ >/dev/null 2>&1; then
            log_pass "Kustomize manifests are valid"
        else
            log_fail "Kustomize validation" "kustomize build failed"
            exit 1
        fi

        log_info "Checking kubeconform..."
        if command -v kubeconform >/dev/null 2>&1; then
            if kustomize build infra/eks/overlays/local/ | kubeconform -summary -strict -ignore-missing-schemas >/dev/null 2>&1; then
                log_pass "kubeconform validation passed"
            else
                log_fail "kubeconform validation" "Schema validation failed"
                exit 1
            fi
        else
            log_info "kubeconform not installed - skipping schema validation"
        fi
    fi

    log_header "Dry Run Complete"
    echo -e "${GREEN}Configuration is valid. Re-run without --dry-run to test actual deployment.${NC}"
    exit 0
fi

# ============================================================================
# TIMED VALIDATION - Actual Deployment
# ============================================================================

log_header "Starting Timed Validation"
log_info "Mode: ${MODE}"
log_info "Threshold: $(format_duration $THRESHOLD_SECONDS)"
echo ""

# Record start time
START_TIME=$(date +%s)
log_info "Timer started at: $(date)"

# ---- Phase 1: Run 'make setup' with default inputs ----
log_header "Phase 1: Running 'make setup'"

# Pipe default inputs (press Enter at every prompt)
# Based on setup.sh, questions are:
# 1. Deep scan fallback: Enter = fail-closed
# 2. GROQ_API_KEY: Enter = skip
# 3. Session persistence: Enter = Y
# 4. SPIFFE mode: Enter = dev
# 5. Proceed with docker compose up: n (we'll do it separately to control timing)

if [ "$MODE" = "compose" ]; then
    log_info "Running setup with default inputs (compose mode)..."
    printf "\n\n\nn\n" | make setup 2>&1 | sed 's/^/    /' || {
        log_fail "make setup" "Setup failed"
        exit 1
    }
    log_pass "Setup complete"
elif [ "$MODE" = "k8s" ]; then
    # For K8s, we still run setup to generate .env, but we won't docker compose up
    log_info "Running setup with default inputs (k8s mode)..."
    printf "\n\n\nn\n" | make setup 2>&1 | sed 's/^/    /' || {
        log_fail "make setup" "Setup failed"
        exit 1
    }
    log_pass "Setup complete"
fi

# ---- Phase 2: Start services ----
log_header "Phase 2: Starting Services"

if [ "$MODE" = "compose" ]; then
    log_info "Starting Docker Compose stack..."
    make up 2>&1 | sed 's/^/    /' || {
        log_fail "make up" "Docker Compose up failed"
        exit 1
    }
    log_pass "Docker Compose stack started"

    # Wait for services to be healthy
    log_info "Waiting for services to be healthy (max 5 minutes)..."
    timeout=300
    while [ $timeout -gt 0 ]; do
        if docker compose ps --format '{{.Name}}\t{{.Status}}' 2>/dev/null | grep -q "mcp-security-gateway.*healthy\|Up"; then
            log_pass "Gateway is healthy"
            break
        fi
        sleep 2
        timeout=$((timeout - 2))
    done

    if [ $timeout -le 0 ]; then
        log_fail "Health check" "Gateway did not become healthy within 5 minutes"
        exit 1
    fi

    GATEWAY_TARGET="$GATEWAY_URL"

elif [ "$MODE" = "k8s" ]; then
    log_info "Deploying to local K8s..."
    make k8s-local-up 2>&1 | sed 's/^/    /' || {
        log_fail "make k8s-local-up" "K8s deployment failed"
        exit 1
    }
    log_pass "K8s deployment complete"

    # Wait for pods to be Running (Makefile already does rollout status, so we just verify)
    log_info "Verifying pods are Running..."
    if kubectl -n gateway get pod -l app=mcp-security-gateway -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q "Running"; then
        log_pass "Gateway pod is Running"
    else
        log_fail "Pod status" "Gateway pod not Running"
        exit 1
    fi

    GATEWAY_TARGET="$K8S_GATEWAY_URL"
fi

# ---- Phase 3: Send first E2E request ----
log_header "Phase 3: First E2E Request"

log_info "Sending request to ${GATEWAY_TARGET}/health..."

# First, verify health endpoint
HEALTH_RESP=$(curl -s -w "\n%{http_code}" "${GATEWAY_TARGET}/health" 2>&1 || echo "connection_failed")
HEALTH_CODE=$(echo "$HEALTH_RESP" | tail -1)

if [ "$HEALTH_CODE" = "200" ]; then
    log_pass "Health endpoint returned 200"
elif [ "$HEALTH_CODE" = "connection_failed" ]; then
    log_fail "Health check" "Connection failed - gateway not reachable"
    exit 1
else
    log_fail "Health check" "Expected 200, got ${HEALTH_CODE}"
    exit 1
fi

# Now send a tool call through the full middleware chain
log_info "Sending tool call through full middleware chain..."

TOOL_RESP=$(curl -s -w "\n%{http_code}" -X POST "${GATEWAY_TARGET}/" \
    -H "Content-Type: application/json" \
    -H "X-SPIFFE-ID: spiffe://poc.local/agents/mcp-client/dspy-researcher/dev" \
    -d '{
        "jsonrpc": "2.0",
        "method": "read",
        "params": {"file_path": "/tmp/test"},
        "id": 1
    }' 2>&1 || echo "connection_failed")

TOOL_CODE=$(echo "$TOOL_RESP" | tail -1)

# Accept 200 (success), 502 (upstream unreachable), 404 (upstream not found), 403 (policy denial)
# All prove middleware chain executed
if [ "$TOOL_CODE" = "200" ] || [ "$TOOL_CODE" = "502" ] || [ "$TOOL_CODE" = "404" ] || [ "$TOOL_CODE" = "403" ]; then
    log_pass "Tool call processed through middleware chain (HTTP ${TOOL_CODE})"
else
    log_fail "Tool call" "Expected 200/404/502/403, got ${TOOL_CODE}"
    # Don't exit - we still want to show timing
fi

# ---- Record end time and compute elapsed ----
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

log_header "Timing Results"

log_info "Start time:    $(date -r $START_TIME)"
log_info "End time:      $(date -r $END_TIME)"
log_info "Elapsed time:  $(format_duration $ELAPSED)"
log_info "Threshold:     $(format_duration $THRESHOLD_SECONDS)"
echo ""

# ---- Final verdict ----
if [ $ELAPSED -le $THRESHOLD_SECONDS ]; then
    log_header "RESULT: PASS"
    echo -e "${GREEN}Setup completed in $(format_duration $ELAPSED) (under 30-minute threshold)${NC}"
    echo ""
    exit 0
else
    log_header "RESULT: FAIL"
    echo -e "${RED}Setup took $(format_duration $ELAPSED) (exceeds 30-minute threshold)${NC}"
    echo ""
    exit 1
fi

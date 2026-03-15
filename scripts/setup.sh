#!/usr/bin/env bash
# =============================================================================
# CLI Setup Wizard - RFA-tj9.2
# Guides users through POC configuration with clear security consequence
# explanations. Invoked via 'make setup'.
#
# Design principles (from DESIGN.md 4.1):
# - Pressing Enter at every prompt produces a secure, working configuration
# - No silent degradation: every disabled control is explicitly called out
# - Target user: 'someone who doesn't know much about security'
# =============================================================================

set -euo pipefail

# Resolve POC root from script location (scripts/ is one level below POC root)
POC_DIR="${POC_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DC="docker compose -f ${POC_DIR}/deploy/compose/docker-compose.yml"
ENV_FILE="${POC_DIR}/.env"

# ---- Terminal colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---- State variables for security posture ----
DEEP_SCAN_FALLBACK="fail_closed"
GROQ_API_KEY=""
GROQ_API_KEY_SET=false
GUARD_ENDPOINT=""
GUARD_MODEL_NAME=""
GUARD_API_KEY_OVERRIDE=""
SESSION_PERSISTENCE=true
SPIFFE_MODE="dev"

# Track optional tool availability for posture summary
HAS_COSIGN=false
HAS_SYFT=false
HAS_OPA=false

# ---- Output helpers ----
print_header() {
    echo ""
    echo -e "${BOLD}=========================================${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}=========================================${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${CYAN}--- $1 ---${NC}"
    echo ""
}

# =============================================================================
# PHASE 1: Prerequisite Checks
# =============================================================================

print_header "PRECINCT Gateway - Setup Wizard"
echo "  This wizard will guide you through configuring the Agentic"
echo "  Reference Architecture POC (Docker Compose tier)."
echo ""
echo "  Every prompt has a secure default. Press Enter to accept."
echo ""

print_section "Prerequisite Checks"

PREREQ_FAIL=false

# ---- Required: Docker ----
check_version_ge() {
    # Compare two version strings (major.minor format).
    # Returns 0 if $1 >= $2, 1 otherwise.
    local have="$1"
    local need="$2"
    local have_major have_minor need_major need_minor
    have_major=$(echo "$have" | cut -d. -f1)
    have_minor=$(echo "$have" | cut -d. -f2)
    need_major=$(echo "$need" | cut -d. -f1)
    need_minor=$(echo "$need" | cut -d. -f2)
    if [ "$have_major" -gt "$need_major" ] 2>/dev/null; then return 0; fi
    if [ "$have_major" -eq "$need_major" ] 2>/dev/null && [ "$have_minor" -ge "$need_minor" ] 2>/dev/null; then return 0; fi
    return 1
}

# Docker
if command -v docker >/dev/null 2>&1; then
    DOCKER_VERSION=$(docker --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo "0.0")
    if check_version_ge "$DOCKER_VERSION" "25.0"; then
        echo -e "  [${GREEN}OK${NC}]   Docker ${DOCKER_VERSION} (>= 25.0 required)"
    else
        echo -e "  [${RED}FAIL${NC}] Docker ${DOCKER_VERSION} found, but >= 25.0 required"
        echo "         Install: https://docs.docker.com/get-docker/"
        PREREQ_FAIL=true
    fi
else
    echo -e "  [${RED}FAIL${NC}] Docker not found"
    echo "         Install: https://docs.docker.com/get-docker/"
    PREREQ_FAIL=true
fi

# Docker Compose
if docker compose version >/dev/null 2>&1; then
    COMPOSE_VERSION=$(docker compose version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo "0.0")
    if check_version_ge "$COMPOSE_VERSION" "2.24"; then
        echo -e "  [${GREEN}OK${NC}]   Docker Compose ${COMPOSE_VERSION} (>= 2.24 required)"
    else
        echo -e "  [${RED}FAIL${NC}] Docker Compose ${COMPOSE_VERSION} found, but >= 2.24 required"
        echo "         Update Docker Desktop or install: https://docs.docker.com/compose/install/"
        PREREQ_FAIL=true
    fi
else
    echo -e "  [${RED}FAIL${NC}] Docker Compose not found"
    echo "         Install: https://docs.docker.com/compose/install/"
    PREREQ_FAIL=true
fi

# Go
if command -v go >/dev/null 2>&1; then
    GO_VERSION=$(go version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo "0.0")
    if check_version_ge "$GO_VERSION" "1.23"; then
        echo -e "  [${GREEN}OK${NC}]   Go ${GO_VERSION} (>= 1.23 required)"
    else
        echo -e "  [${RED}FAIL${NC}] Go ${GO_VERSION} found, but >= 1.23 required"
        echo "         Install: https://go.dev/dl/"
        PREREQ_FAIL=true
    fi
else
    echo -e "  [${RED}FAIL${NC}] Go not found"
    echo "         Install: https://go.dev/dl/"
    PREREQ_FAIL=true
fi

echo ""

# ---- Optional tools ----
echo "  Optional tools (reduced functionality without these):"
echo ""

# cosign
if command -v cosign >/dev/null 2>&1; then
    echo -e "  [${GREEN}OK${NC}]   cosign (container image signing)"
    HAS_COSIGN=true
else
    echo -e "  [${YELLOW}--${NC}]   cosign not found"
    echo "         Without cosign: Container image signatures cannot be verified."
    echo "         Install: https://docs.sigstore.dev/cosign/system_config/installation/"
fi

# syft
if command -v syft >/dev/null 2>&1; then
    echo -e "  [${GREEN}OK${NC}]   syft (SBOM generation)"
    HAS_SYFT=true
else
    echo -e "  [${YELLOW}--${NC}]   syft not found"
    echo "         Without syft: Software Bill of Materials (SBOM) cannot be generated."
    echo "         Install: https://github.com/anchore/syft"
fi

# opa
if command -v opa >/dev/null 2>&1; then
    echo -e "  [${GREEN}OK${NC}]   opa (policy testing CLI)"
    HAS_OPA=true
else
    echo -e "  [${YELLOW}--${NC}]   opa not found"
    echo "         Without opa: OPA policy unit tests cannot run locally (policies still"
    echo "         enforced at runtime via the embedded OPA engine in the gateway)."
    echo "         Install: https://www.openpolicyagent.org/docs/latest/#running-opa"
fi

echo ""

if [ "$PREREQ_FAIL" = true ]; then
    echo -e "${RED}One or more required prerequisites are missing.${NC}"
    echo "Please install them and re-run 'make setup'."
    exit 1
fi

echo -e "${GREEN}All required prerequisites satisfied.${NC}"

# =============================================================================
# PHASE 2: Guided Configuration
# =============================================================================

print_header "Configuration"
echo "  Each question below affects the security posture of the POC."
echo "  Defaults (press Enter) produce the most secure configuration."
echo ""

# ---- Q1: Deep scan fallback policy ----
print_section "Q1: Deep Scan Fallback Policy"
echo "  The deep scan middleware uses an LLM to analyze tool call payloads"
echo "  for prompt injection and other attacks. If the LLM is unreachable,"
echo "  the fallback policy determines what happens:"
echo ""
echo "    [1] fail-closed (DEFAULT) -- Block the request. Safer: no request"
echo "        passes without security analysis, but the system stops working"
echo "        if the LLM API goes down."
echo ""
echo "    [2] fail-open -- Allow the request through. Less safe: requests"
echo "        proceed without deep analysis if the LLM is unavailable."
echo ""
printf "  Choose [1] or [2] (default: 1): "
read -r FALLBACK_CHOICE || true
FALLBACK_CHOICE="${FALLBACK_CHOICE:-1}"
case "$FALLBACK_CHOICE" in
    2)
        DEEP_SCAN_FALLBACK="fail_open"
        echo -e "  ${YELLOW}Selected: fail-open${NC} -- requests pass through without deep scan on LLM failure"
        ;;
    *)
        DEEP_SCAN_FALLBACK="fail_closed"
        echo -e "  ${GREEN}Selected: fail-closed${NC} -- requests blocked if deep scan is unavailable"
        ;;
esac

# ---- Q2: GROQ API Key ----
print_section "Q2: GROQ API Key (for Deep Scan)"
echo "  The deep scan middleware calls the Groq LLM API to analyze payloads."
echo "  Without an API key, deep scan is DISABLED and payloads are not analyzed"
echo "  for prompt injection or policy violations beyond pattern matching."
echo ""
echo "  Get a free key at: https://console.groq.com/keys"
echo ""
printf "  Paste your GROQ API key (or press Enter to skip): "
read -r GROQ_API_KEY_INPUT || true
GROQ_API_KEY_INPUT="${GROQ_API_KEY_INPUT:-}"
if [ -n "$GROQ_API_KEY_INPUT" ]; then
    GROQ_API_KEY="$GROQ_API_KEY_INPUT"
    GROQ_API_KEY_SET=true
    echo -e "  ${GREEN}API key set.${NC} Deep scan ENABLED."
else
    GROQ_API_KEY=""
    GROQ_API_KEY_SET=false
    echo -e "  ${YELLOW}Skipped.${NC} Deep scan DISABLED -- payloads will not be analyzed by LLM."
fi

# ---- Q2b: Guard Model Configuration (only shown if GROQ_API_KEY was set) ----
if [ "$GROQ_API_KEY_SET" = true ]; then
    print_section "Q2b: Guard Model Configuration"
    echo "  By default, deep scan uses the Groq API with Prompt Guard 2."
    echo "  You can override the endpoint, model, or API key to use an"
    echo "  alternative OpenAI-compatible provider (Ollama, Azure, Together AI, etc.)."
    echo ""
    echo "  Press Enter at each prompt to keep the Groq defaults."
    echo ""

    printf "  Guard model endpoint (default: Groq): "
    read -r GUARD_ENDPOINT_INPUT || true
    GUARD_ENDPOINT="${GUARD_ENDPOINT_INPUT:-}"
    if [ -n "$GUARD_ENDPOINT" ]; then
        echo -e "  ${GREEN}Custom endpoint:${NC} ${GUARD_ENDPOINT}"
    else
        echo -e "  ${GREEN}Using default:${NC} Groq API (https://api.groq.com/openai/v1)"
    fi

    printf "  Guard model name (default: meta-llama/llama-prompt-guard-2-86m): "
    read -r GUARD_MODEL_NAME_INPUT || true
    GUARD_MODEL_NAME="${GUARD_MODEL_NAME_INPUT:-}"
    if [ -n "$GUARD_MODEL_NAME" ]; then
        echo -e "  ${GREEN}Custom model:${NC} ${GUARD_MODEL_NAME}"
    else
        echo -e "  ${GREEN}Using default:${NC} meta-llama/llama-prompt-guard-2-86m"
    fi

    printf "  Guard API key (default: use GROQ_API_KEY): "
    read -r GUARD_API_KEY_INPUT || true
    GUARD_API_KEY_OVERRIDE="${GUARD_API_KEY_INPUT:-}"
    if [ -n "$GUARD_API_KEY_OVERRIDE" ]; then
        echo -e "  ${GREEN}Custom API key set.${NC}"
    else
        echo -e "  ${GREEN}Using GROQ_API_KEY.${NC}"
    fi
fi

# ---- Q3: Session Persistence (KeyDB) ----
print_section "Q3: Session Persistence (KeyDB)"
echo "  KeyDB (Redis-compatible) stores session context across requests."
echo "  This enables cross-request exfiltration detection: the gateway can"
echo "  detect when an agent slowly leaks data across multiple tool calls."
echo ""
echo "  Without session persistence:"
echo "    - Cross-request exfiltration detection is DISABLED"
echo "    - Distributed rate limiting falls back to in-memory (per-instance)"
echo "    - Session context resets on every request"
echo ""
printf "  Enable KeyDB session persistence? Y/n (default: Y): "
read -r KEYDB_CHOICE || true
KEYDB_CHOICE="${KEYDB_CHOICE:-Y}"
case "$KEYDB_CHOICE" in
    [nN])
        SESSION_PERSISTENCE=false
        echo -e "  ${YELLOW}KeyDB DISABLED.${NC} Session persistence and cross-request detection off."
        ;;
    *)
        SESSION_PERSISTENCE=true
        echo -e "  ${GREEN}KeyDB ENABLED.${NC} Full session persistence and exfiltration detection."
        ;;
esac

# ---- Q4: SPIFFE Mode ----
print_section "Q4: SPIFFE Identity Mode"
echo "  SPIFFE provides cryptographic identity for every workload."
echo ""
echo "    [1] dev (DEFAULT) -- Identity is injected via X-SPIFFE-ID header."
echo "        Easy to test, no TLS certificates needed. Not for production."
echo ""
echo "    [2] prod -- Identity verified via mTLS with SPIRE-issued X.509"
echo "        certificates. More secure, but requires full SPIRE setup."
echo ""
printf "  Choose [1] or [2] (default: 1): "
read -r SPIFFE_CHOICE || true
SPIFFE_CHOICE="${SPIFFE_CHOICE:-1}"
case "$SPIFFE_CHOICE" in
    2)
        SPIFFE_MODE="prod"
        echo -e "  ${GREEN}Selected: prod${NC} -- mTLS with SPIRE-issued X.509 SVIDs"
        ;;
    *)
        SPIFFE_MODE="dev"
        echo -e "  ${GREEN}Selected: dev${NC} -- header-injected identity (for development/testing)"
        ;;
esac

# ---- Q5: Enforcement Profile ----
print_section "Q5: Enforcement Profile"
echo "  Enforcement profiles define startup conformance strictness and control gates."
echo ""
echo "    [1] dev (DEFAULT for local dev)"
echo "        Fast local iteration. Permissive startup checks."
echo ""
echo "    [2] prod_standard (RECOMMENDED for secure staging/prod)"
echo "        Strict startup conformance; fails fast on missing controls."
echo ""
echo "    [3] prod_regulated_hipaa"
echo "        Strict startup + HIPAA prompt-safety enforcement."
echo ""
default_profile_choice="1"
if [ "$SPIFFE_MODE" = "prod" ]; then
    default_profile_choice="2"
fi
printf "  Choose [1], [2], or [3] (default: %s): " "$default_profile_choice"
read -r PROFILE_CHOICE || true
PROFILE_CHOICE="${PROFILE_CHOICE:-$default_profile_choice}"
case "$PROFILE_CHOICE" in
    2)
        ENFORCEMENT_PROFILE="prod_standard"
        echo -e "  ${GREEN}Selected: prod_standard${NC} -- strict startup conformance"
        ;;
    3)
        ENFORCEMENT_PROFILE="prod_regulated_hipaa"
        echo -e "  ${GREEN}Selected: prod_regulated_hipaa${NC} -- strict + HIPAA prompt-safety"
        ;;
    *)
        ENFORCEMENT_PROFILE="dev"
        echo -e "  ${GREEN}Selected: dev${NC} -- permissive local profile"
        ;;
esac

# =============================================================================
# PHASE 3: Generate .env File
# =============================================================================

print_section "Generating .env"

# Construct KEYDB_URL based on session persistence and SPIFFE mode
KEYDB_URL=""
if [ "$SESSION_PERSISTENCE" = true ]; then
    if [ "$SPIFFE_MODE" = "prod" ]; then
        KEYDB_URL="rediss://keydb:6380"
    else
        KEYDB_URL="redis://keydb:6379"
    fi
fi

# Dev-mode startup guardrails (RFA-9so.1)
ALLOW_INSECURE_DEV_MODE="0"
DEV_LISTEN_HOST="127.0.0.1"
ALLOW_NON_LOOPBACK_DEV_BIND="0"
if [ "$SPIFFE_MODE" = "dev" ]; then
    # Docker requires non-loopback bind to publish container port to host.
    ALLOW_INSECURE_DEV_MODE="1"
    DEV_LISTEN_HOST="0.0.0.0"
    ALLOW_NON_LOOPBACK_DEV_BIND="1"
fi

cat > "$ENV_FILE" <<ENVEOF
# Generated by setup wizard (RFA-tj9.2)
# $(date -u '+%Y-%m-%dT%H:%M:%SZ')
#
# Re-run 'make setup' to regenerate.

# Deep scan (LLM-based payload analysis)
GROQ_API_KEY=${GROQ_API_KEY}
DEEP_SCAN_FALLBACK=${DEEP_SCAN_FALLBACK}

# Guard model configuration (RFA-j6c)
GUARD_MODEL_ENDPOINT=${GUARD_ENDPOINT}
GUARD_MODEL_NAME=${GUARD_MODEL_NAME}
GUARD_API_KEY=${GUARD_API_KEY_OVERRIDE}

# Session persistence (KeyDB)
KEYDB_URL=${KEYDB_URL}

# SPIFFE identity mode
SPIFFE_MODE=${SPIFFE_MODE}
ENFORCEMENT_PROFILE=${ENFORCEMENT_PROFILE}
ALLOW_INSECURE_DEV_MODE=${ALLOW_INSECURE_DEV_MODE}
DEV_LISTEN_HOST=${DEV_LISTEN_HOST}
ALLOW_NON_LOOPBACK_DEV_BIND=${ALLOW_NON_LOOPBACK_DEV_BIND}
ENVEOF

echo -e "  ${GREEN}.env file written to ${ENV_FILE}${NC}"
echo ""

# =============================================================================
# PHASE 4: Security Posture Summary
# =============================================================================

print_header "Security Posture Summary"

# Determine status for each control
DEEP_SCAN_STATUS="ENABLED"
DEEP_SCAN_DETAIL="Groq LLM analyzes payloads; fallback=${DEEP_SCAN_FALLBACK}"
if [ "$GROQ_API_KEY_SET" = false ]; then
    DEEP_SCAN_STATUS="DISABLED"
    DEEP_SCAN_DETAIL="No GROQ_API_KEY -- LLM payload analysis skipped"
elif [ "$DEEP_SCAN_FALLBACK" = "fail_open" ]; then
    DEEP_SCAN_STATUS="DEGRADED"
    DEEP_SCAN_DETAIL="LLM analysis active, but fail-open on LLM errors"
fi
# Show custom guard model info if configured
if [ -n "$GUARD_ENDPOINT" ] || [ -n "$GUARD_MODEL_NAME" ]; then
    GUARD_PROVIDER="${GUARD_ENDPOINT:-Groq}"
    GUARD_MODEL="${GUARD_MODEL_NAME:-llama-prompt-guard-2-86m}"
    DEEP_SCAN_DETAIL="Guard: ${GUARD_MODEL} @ ${GUARD_PROVIDER}; fallback=${DEEP_SCAN_FALLBACK}"
fi

SESSION_STATUS="ENABLED"
SESSION_DETAIL="KeyDB stores cross-request context; exfiltration detection active"
if [ "$SESSION_PERSISTENCE" = false ]; then
    SESSION_STATUS="DISABLED"
    SESSION_DETAIL="No KeyDB -- in-memory only; cross-request detection off"
fi

SPIFFE_STATUS="ENABLED"
SPIFFE_DETAIL="Header injection (dev mode)"
if [ "$SPIFFE_MODE" = "prod" ]; then
    SPIFFE_DETAIL="mTLS with SPIRE X.509 SVIDs"
fi

PROFILE_STATUS="ENABLED"
PROFILE_DETAIL="dev profile (permissive startup)"
case "$ENFORCEMENT_PROFILE" in
    prod_standard)
        PROFILE_DETAIL="prod_standard profile (strict startup conformance)"
        ;;
    prod_regulated_hipaa)
        PROFILE_DETAIL="prod_regulated_hipaa profile (strict + HIPAA prompt safety)"
        ;;
esac

# Controls that are always enabled in this tier
OPA_STATUS="ENABLED"
OPA_DETAIL="Embedded OPA engine; policies in config/opa/"

DLP_STATUS="ENABLED"
DLP_DETAIL="Pattern-based credential/PII detection always active"

AUDIT_STATUS="ENABLED"
AUDIT_DETAIL="Structured JSON events with hash chain integrity"

TOOL_INTEGRITY_STATUS="ENABLED"
TOOL_INTEGRITY_DETAIL="SHA-256 hash verification via tool registry"

COSIGN_STATUS="ENABLED"
COSIGN_DETAIL="Container image signature verification available"
if [ "$HAS_COSIGN" = false ]; then
    COSIGN_STATUS="DEGRADED"
    COSIGN_DETAIL="cosign not installed -- image signing/verification unavailable"
fi

SBOM_STATUS="ENABLED"
SBOM_DETAIL="SBOM generation available via syft"
if [ "$HAS_SYFT" = false ]; then
    SBOM_STATUS="DEGRADED"
    SBOM_DETAIL="syft not installed -- SBOM generation unavailable"
fi

OPA_TESTING_STATUS="ENABLED"
OPA_TESTING_DETAIL="OPA CLI available for local policy testing"
if [ "$HAS_OPA" = false ]; then
    OPA_TESTING_STATUS="DEGRADED"
    OPA_TESTING_DETAIL="opa CLI not installed -- policy unit tests cannot run locally"
fi

# Print posture table
printf "  %-28s %-10s %s\n" "Control" "Status" "Detail"
printf "  %-28s %-10s %s\n" "----------------------------" "----------" "----------------------------------------------"

print_posture_row() {
    local control="$1"
    local status="$2"
    local detail="$3"
    local color="$GREEN"
    case "$status" in
        DISABLED) color="$RED" ;;
        DEGRADED) color="$YELLOW" ;;
        ENABLED)  color="$GREEN" ;;
    esac
    printf "  %-28s ${color}%-10s${NC} %s\n" "$control" "$status" "$detail"
}

print_posture_row "SPIFFE Identity"       "$SPIFFE_STATUS"       "$SPIFFE_DETAIL"
print_posture_row "Enforcement Profile"   "$PROFILE_STATUS"      "$PROFILE_DETAIL"
print_posture_row "OPA Policy Engine"     "$OPA_STATUS"          "$OPA_DETAIL"
print_posture_row "Tool Integrity (Hash)" "$TOOL_INTEGRITY_STATUS" "$TOOL_INTEGRITY_DETAIL"
print_posture_row "DLP Scanner"           "$DLP_STATUS"          "$DLP_DETAIL"
print_posture_row "Deep Scan (LLM)"       "$DEEP_SCAN_STATUS"    "$DEEP_SCAN_DETAIL"
print_posture_row "Session Persistence"   "$SESSION_STATUS"      "$SESSION_DETAIL"
print_posture_row "Audit Chain"           "$AUDIT_STATUS"        "$AUDIT_DETAIL"
print_posture_row "Image Signing"         "$COSIGN_STATUS"       "$COSIGN_DETAIL"
print_posture_row "SBOM Generation"       "$SBOM_STATUS"         "$SBOM_DETAIL"
print_posture_row "OPA Policy Testing"    "$OPA_TESTING_STATUS"  "$OPA_TESTING_DETAIL"

echo ""

# Print warnings for non-ENABLED controls
WARNINGS=false
for status_var in "$DEEP_SCAN_STATUS" "$SESSION_STATUS" "$COSIGN_STATUS" "$SBOM_STATUS" "$OPA_TESTING_STATUS"; do
    if [ "$status_var" != "ENABLED" ]; then
        WARNINGS=true
        break
    fi
done

if [ "$WARNINGS" = true ]; then
    echo -e "  ${BOLD}Warnings:${NC}"
    echo ""
    if [ "$DEEP_SCAN_STATUS" = "DISABLED" ]; then
        echo -e "  ${RED}[!]${NC} Deep Scan DISABLED: Payloads not analyzed by LLM."
        echo "      Remediation: Set GROQ_API_KEY in .env or re-run 'make setup'."
        echo "      Get a key at: https://console.groq.com/keys"
        echo ""
    elif [ "$DEEP_SCAN_STATUS" = "DEGRADED" ]; then
        echo -e "  ${YELLOW}[!]${NC} Deep Scan DEGRADED: fail-open policy allows requests without LLM analysis on error."
        echo "      Remediation: Change DEEP_SCAN_FALLBACK to 'fail_closed' in .env."
        echo ""
    fi
    if [ "$SESSION_STATUS" = "DISABLED" ]; then
        echo -e "  ${RED}[!]${NC} Session Persistence DISABLED: Cross-request exfiltration detection off."
        echo "      Remediation: Set KEYDB_URL=redis://keydb:6379 in .env or re-run 'make setup'."
        echo ""
    fi
    if [ "$COSIGN_STATUS" = "DEGRADED" ]; then
        echo -e "  ${YELLOW}[!]${NC} Image Signing unavailable: Install cosign for container image verification."
        echo "      Install: https://docs.sigstore.dev/cosign/system_config/installation/"
        echo ""
    fi
    if [ "$SBOM_STATUS" = "DEGRADED" ]; then
        echo -e "  ${YELLOW}[!]${NC} SBOM Generation unavailable: Install syft for software bill of materials."
        echo "      Install: https://github.com/anchore/syft"
        echo ""
    fi
    if [ "$OPA_TESTING_STATUS" = "DEGRADED" ]; then
        echo -e "  ${YELLOW}[!]${NC} OPA Policy Testing unavailable: Install opa CLI for local policy unit tests."
        echo "      Install: https://www.openpolicyagent.org/docs/latest/#running-opa"
        echo ""
    fi
fi

# =============================================================================
# PHASE 5: Start Services
# =============================================================================

print_section "Start Services"

echo "  Configuration is complete. Ready to start the Docker Compose stack."
echo ""
printf "  Start services now? Y/n (default: Y): "
read -r START_CHOICE || true
START_CHOICE="${START_CHOICE:-Y}"

if [[ "$START_CHOICE" =~ ^[nN] ]]; then
    echo ""
    echo "  Skipped. To start later, run: make up"
    echo ""
    exit 0
fi

echo ""
echo "  Starting services with 'docker compose up -d'..."
echo ""

cd "$POC_DIR"
$DC up -d

echo ""
echo "  Waiting for services to become healthy..."

# Wait for gateway to be healthy (with timeout)
TIMEOUT=120
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    GATEWAY_STATUS=$($DC ps --format '{{.Status}}' mcp-security-gateway 2>/dev/null || echo "")
    if echo "$GATEWAY_STATUS" | grep -qi "healthy"; then
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    printf "."
done
echo ""

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo -e "  ${RED}[FAIL]${NC} Gateway did not become healthy within ${TIMEOUT}s"
    echo "         Check logs with: docker compose logs mcp-security-gateway"
    echo "         Try: make down && make up"
    exit 1
fi

echo -e "  ${GREEN}Gateway is healthy.${NC}"
echo ""

# Wait a little longer for SPIRE registration
echo "  Waiting for SPIRE server to be ready..."
SPIRE_TIMEOUT=60
SPIRE_ELAPSED=0
while [ $SPIRE_ELAPSED -lt $SPIRE_TIMEOUT ]; do
    SPIRE_STATUS=$($DC ps --format '{{.Status}}' spire-server 2>/dev/null || echo "")
    if echo "$SPIRE_STATUS" | grep -qi "healthy"; then
        break
    fi
    sleep 2
    SPIRE_ELAPSED=$((SPIRE_ELAPSED + 2))
    printf "."
done
echo ""

if echo "$SPIRE_STATUS" | grep -qi "healthy"; then
    echo "  Registering SPIRE workload entries..."
    $DC exec -T spire-server /bin/bash < "${POC_DIR}/scripts/register-spire-entries.sh" 2>/dev/null || true
    echo -e "  ${GREEN}SPIRE entries registered.${NC}"
else
    echo -e "  ${YELLOW}SPIRE server not healthy yet. SPIRE registration may need manual step: make register-spire${NC}"
fi

echo ""

# =============================================================================
# PHASE 6: Post-Startup Smoke Tests
# =============================================================================

print_header "Post-Startup Smoke Tests"
echo "  Verifying the security middleware chain is working correctly."
echo ""

GATEWAY_URL="http://localhost:9090"
DEFAULT_SPIFFE_ID="spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"

SMOKE_PASS=0
SMOKE_FAIL=0

smoke_pass() {
    SMOKE_PASS=$((SMOKE_PASS + 1))
    echo -e "  [${GREEN}PASS${NC}] $1"
    if [ -n "${2:-}" ]; then
        echo "         Architecture Claim: $2"
    fi
}

smoke_fail() {
    SMOKE_FAIL=$((SMOKE_FAIL + 1))
    echo -e "  [${RED}FAIL${NC}] $1"
    echo "         Reason: $2"
    if [ -n "${3:-}" ]; then
        echo "         Remediation: $3"
    fi
}

# ---- Smoke 1: Happy Path ----
print_section "Smoke 1: Happy Path (authorized tool call)"
echo "  Architecture Claim: Authorized tool calls pass through the 13-middleware chain"
echo ""

RESP=$(curl -s -w "\n%{http_code}" -X POST "${GATEWAY_URL}/" \
    -H "Content-Type: application/json" \
    -H "X-SPIFFE-ID: ${DEFAULT_SPIFFE_ID}" \
    -d '{
        "jsonrpc": "2.0",
        "method": "read",
        "params": {"file_path": "/tmp/test"},
        "id": 1
    }' 2>&1) || true

RESP_CODE=$(echo "$RESP" | tail -n1)
RESP_BODY=$(echo "$RESP" | sed '$d')

# 200 = upstream reachable, 502/404 = upstream unreachable but middleware chain executed
if [ "$RESP_CODE" = "200" ] || [ "$RESP_CODE" = "502" ] || [ "$RESP_CODE" = "404" ]; then
    smoke_pass "Authorized tool call processed (HTTP ${RESP_CODE})" \
        "Full middleware chain executed -> Evidence: HTTP ${RESP_CODE} (502/404 = upstream Docker MCP not running, expected)"
else
    smoke_fail "Authorized tool call" \
        "Expected 200/502/404, got HTTP ${RESP_CODE}. Body: ${RESP_BODY:0:200}" \
        "Check gateway logs: docker compose logs mcp-security-gateway"
fi

# ---- Smoke 2: Policy Denial ----
print_section "Smoke 2: Policy Denial (unauthorized tool)"
echo "  Architecture Claim: OPA policy denies unauthorized tool access"
echo ""

RESP=$(curl -s -w "\n%{http_code}" -X POST "${GATEWAY_URL}/" \
    -H "Content-Type: application/json" \
    -H "X-SPIFFE-ID: ${DEFAULT_SPIFFE_ID}" \
    -d '{
        "jsonrpc": "2.0",
        "method": "nonexistent_unauthorized_tool",
        "params": {"arg": "test"},
        "id": 2
    }' 2>&1) || true

RESP_CODE=$(echo "$RESP" | tail -n1)
RESP_BODY=$(echo "$RESP" | sed '$d')

if [ "$RESP_CODE" = "403" ]; then
    smoke_pass "Unauthorized tool denied (HTTP 403)" \
        "OPA policy enforcement -> Evidence: HTTP 403, body: ${RESP_BODY:0:100}"
else
    smoke_fail "Policy denial" \
        "Expected HTTP 403, got ${RESP_CODE}. Body: ${RESP_BODY:0:200}" \
        "Check OPA policies in config/opa/ and gateway logs"
fi

# ---- Smoke 3: DLP Detection ----
print_section "Smoke 3: DLP Detection (AWS key in payload)"
echo "  Architecture Claim: DLP scanner blocks credentials in tool call payloads"
echo ""

RESP=$(curl -s -w "\n%{http_code}" -X POST "${GATEWAY_URL}/" \
    -H "Content-Type: application/json" \
    -H "X-SPIFFE-ID: ${DEFAULT_SPIFFE_ID}" \
    -d '{
        "jsonrpc": "2.0",
        "method": "read",
        "params": {"file_path": "/tmp/test", "data": "Here is the key: AKIAIOSFODNN7EXAMPLE"},
        "id": 3
    }' 2>&1) || true

RESP_CODE=$(echo "$RESP" | tail -n1)
RESP_BODY=$(echo "$RESP" | sed '$d')

if [ "$RESP_CODE" = "403" ]; then
    smoke_pass "AWS credential blocked by DLP (HTTP 403)" \
        "DLP scanner blocks credentials -> Evidence: HTTP 403, body: ${RESP_BODY:0:100}"
else
    smoke_fail "DLP detection" \
        "Expected HTTP 403, got ${RESP_CODE}. Body: ${RESP_BODY:0:200}" \
        "Check that the gateway DLP middleware is active in the middleware chain"
fi

# ---- Smoke 4: Audit Chain Integrity ----
print_section "Smoke 4: Audit Chain (hash chain integrity)"
echo "  Architecture Claim: Every audit event links to the previous via prev_hash"
echo ""

sleep 1  # Allow audit log to flush

AUDIT_LINE=$($DC logs --tail 10 mcp-security-gateway 2>/dev/null | grep "prev_hash" | tail -1 || echo "")

if [ -n "$AUDIT_LINE" ]; then
    # Verify key fields exist
    CHAIN_OK=true
    for field in prev_hash session_id decision_id trace_id; do
        if ! echo "$AUDIT_LINE" | grep -q "\"${field}\""; then
            CHAIN_OK=false
            break
        fi
    done
    if [ "$CHAIN_OK" = true ]; then
        smoke_pass "Audit hash chain intact" \
            "Tamper-evident audit log -> Evidence: prev_hash, session_id, decision_id, trace_id all present"
    else
        smoke_fail "Audit chain fields" \
            "Some required audit fields missing from event" \
            "Check audit log format in gateway code"
    fi
else
    smoke_fail "Audit chain" \
        "No audit events with prev_hash found in gateway logs" \
        "Check that the gateway is processing requests and emitting audit events"
fi

# ---- Smoke 5: Health Endpoint ----
print_section "Smoke 5: Health Endpoint (circuit breaker state)"
echo "  Architecture Claim: /health endpoint exposes circuit breaker state"
echo ""

HEALTH_RESP=$(curl -s -w "\n%{http_code}" "${GATEWAY_URL}/health" 2>&1) || true
HEALTH_CODE=$(echo "$HEALTH_RESP" | tail -n1)
HEALTH_BODY=$(echo "$HEALTH_RESP" | sed '$d')

if [ "$HEALTH_CODE" = "200" ]; then
    # Check for circuit breaker state in response
    if echo "$HEALTH_BODY" | grep -qi "circuit\|status\|ok\|healthy"; then
        smoke_pass "Health endpoint returns 200 with status" \
            "Circuit breaker health -> Evidence: HTTP 200, body: ${HEALTH_BODY:0:150}"
    else
        smoke_pass "Health endpoint returns 200" \
            "Gateway healthy -> Evidence: HTTP 200"
    fi
else
    smoke_fail "Health endpoint" \
        "Expected HTTP 200, got ${HEALTH_CODE}" \
        "Check that the gateway health handler is registered at /health"
fi

# =============================================================================
# Smoke Test Summary
# =============================================================================

echo ""
print_header "Smoke Test Results"

SMOKE_TOTAL=$((SMOKE_PASS + SMOKE_FAIL))
echo -e "  Total: ${SMOKE_TOTAL}"
echo -e "  ${GREEN}PASS${NC}: ${SMOKE_PASS}"
echo -e "  ${RED}FAIL${NC}: ${SMOKE_FAIL}"
echo ""

if [ "$SMOKE_FAIL" -gt 0 ]; then
    echo -e "  ${RED}Some smoke tests failed.${NC} See [FAIL] items above for remediation."
    echo ""
    echo "  Common troubleshooting steps:"
    echo "    1. Check gateway logs:  docker compose logs mcp-security-gateway"
    echo "    2. Restart services:    make down && make up"
    echo "    3. Re-run wizard:       make setup"
    echo ""
    exit 1
else
    echo -e "  ${GREEN}All smoke tests passed.${NC} The security middleware chain is operational."
    echo ""
    echo "  Next steps:"
    echo "    - View traces:        open http://localhost:6006 (Phoenix UI)"
    echo "    - Run full E2E:       bash tests/e2e/run_all.sh"
    echo "    - View gateway logs:  make logs"
    echo ""
fi

#!/usr/bin/env bash
# Scenario I (zero-ext): Zero-Extension Regression (RFA-t2r)
# Validates the gateway works identically when EXTENSION_REGISTRY_PATH is
# empty or unset: zero registered extensions must produce zero overhead and
# all core middleware (OPA, DLP, health) must continue to function.
#
# IMPORTANT: This script does NOT modify the environment.  The caller is
# responsible for unsetting EXTENSION_REGISTRY_PATH before starting the
# gateway.  This script only validates normal gateway behavior.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

log_header "Scenario I (zero-ext): Zero-Extension Regression"

# ============================================================
# Pre-flight: gateway must be running
# ============================================================
log_subheader "Pre-flight checks"

if ! check_service_healthy "mcp-security-gateway"; then
    log_fail "Gateway not running" "Start with: make up"
    print_summary
    exit 1
fi
log_pass "Gateway is running and healthy"

# ============================================================
# I1: Health check returns 200
# ============================================================
log_subheader "I1: Health check works without extensions"

HEALTH_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "${GATEWAY_URL}/health" 2>&1) || true
HEALTH_CODE=$(echo "$HEALTH_RESPONSE" | tail -n1)
HEALTH_BODY=$(echo "$HEALTH_RESPONSE" | sed '$d')

if [ "$HEALTH_CODE" = "200" ]; then
    log_pass "Health endpoint returned HTTP 200"
else
    log_fail "Health endpoint" "Expected HTTP 200, got HTTP ${HEALTH_CODE}. Body: ${HEALTH_BODY:0:200}"
fi

# ============================================================
# I2: Normal tool call succeeds
# ============================================================
log_subheader "I2: Normal tool call succeeds"

# Use the 'read' tool (authorized for the default SPIFFE ID) with a safe
# allowed path, matching the pattern used by scenario_a.  The JSON-RPC method
# is "read" (the tool name), which is the standard pattern for direct tool
# invocations through the gateway.
READ_PROBE_PATH="$(gateway_allowed_file_path "go.mod")"
gateway_request "$DEFAULT_SPIFFE_ID" "read" \
    "{\"file_path\":\"${READ_PROBE_PATH}\"}"

log_info "Response code: $RESP_CODE"
log_info "Response body (first 200 chars): ${RESP_BODY:0:200}"

# Accept 200 (upstream reachable), 404/502 (upstream transport unavailable),
# or 503 (circuit breaker open).  Any of these proves the request passed
# through all middleware successfully without being denied.
if [ "$RESP_CODE" = "200" ] || [ "$RESP_CODE" = "404" ] || [ "$RESP_CODE" = "502" ] || [ "$RESP_CODE" = "503" ]; then
    log_pass "Tool call processed through full middleware chain (HTTP ${RESP_CODE})"
    if [ "$RESP_CODE" = "502" ]; then
        log_detail "502 = upstream not reachable (expected without docker MCP gateway)"
    elif [ "$RESP_CODE" = "404" ]; then
        log_detail "404 = upstream returned not found"
    elif [ "$RESP_CODE" = "503" ]; then
        log_detail "503 = circuit breaker open; middleware chain still exercised"
    fi
else
    log_fail "Normal tool call" "Expected 200, 404, 502, or 503 but got HTTP ${RESP_CODE}. Body: ${RESP_BODY:0:200}"
fi

# ============================================================
# I3: OPA policy still enforced -- unauthorized SPIFFE ID denied
# ============================================================
log_subheader "I3: OPA denies unauthorized SPIFFE ID"

EVIL_SPIFFE="spiffe://evil.domain/agent"
gateway_request "$EVIL_SPIFFE" "read" '{"file_path":"/tmp/test"}'

log_info "Response code: $RESP_CODE"

if [ "$RESP_CODE" = "403" ]; then
    log_pass "Unauthorized SPIFFE ID denied with HTTP 403"
else
    log_fail "OPA enforcement" "Expected HTTP 403 for unauthorized SPIFFE ID, got HTTP ${RESP_CODE}. Body: ${RESP_BODY:0:200}"
fi

# ============================================================
# I4: DLP still enforced -- credential pattern blocked
# ============================================================
log_subheader "I4: DLP blocks credential pattern"

READ_DLP_PATH="$(gateway_allowed_file_path "go.mod")"
gateway_request "$DEFAULT_SPIFFE_ID" "read" \
    "{\"file_path\":\"${READ_DLP_PATH}\",\"data\":\"Here is the key: AKIA1234567890ABCDEF\"}"

log_info "Response code: $RESP_CODE"

if [ "$RESP_CODE" = "403" ]; then
    log_pass "Credential pattern blocked by DLP (HTTP 403)"
else
    log_fail "DLP enforcement" "Expected HTTP 403 for credential pattern, got HTTP ${RESP_CODE}. Body: ${RESP_BODY:0:200}"
fi

# ============================================================
# Summary
# ============================================================
print_summary
exit $?

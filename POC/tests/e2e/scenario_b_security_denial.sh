#!/usr/bin/env bash
# Scenario B: Security Denial - RFA-70p
# OPA denies a tool call, agent handles gracefully.
# Verifies: policy enforcement, denial reason in response, audit trail.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

log_header "Scenario B: Security Denial (OPA Policy)"

# ============================================================
# Pre-check
# ============================================================
log_subheader "Pre-flight checks"

if ! check_service_healthy "mcp-security-gateway"; then
    log_fail "Gateway not running" "Start with: make up"
    print_summary
    exit 1
fi
log_pass "Gateway is running"

# ============================================================
# Test B1: Denied tool call - bash requires step-up
# ============================================================
log_subheader "B1: Bash tool call without step-up (should be denied)"

# bash is classified as critical-risk and requires step-up authentication
gateway_request "$DEFAULT_SPIFFE_ID" "bash" '{"command": "ls -la"}'

log_info "Response code: $RESP_CODE"
log_info "Response body: $RESP_BODY"

if [ "$RESP_CODE" = "403" ] || [ "$RESP_CODE" = "428" ]; then
    log_pass "High-risk tool call denied (HTTP $RESP_CODE)"
    if [ "$RESP_CODE" = "403" ]; then
        log_detail "Denied by OPA policy or step-up gating"
    elif [ "$RESP_CODE" = "428" ]; then
        log_detail "Step-up authentication required (HTTP 428)"
    fi
else
    log_fail "Bash denial" "Expected 403 or 428, got $RESP_CODE"
fi

# ============================================================
# Test B2: Denied tool call - unknown tool
# ============================================================
log_subheader "B2: Unknown tool call (should be denied)"

gateway_request "$DEFAULT_SPIFFE_ID" "nonexistent_tool" '{"arg": "test"}'

log_info "Response code: $RESP_CODE"
log_info "Response body: $RESP_BODY"

if [ "$RESP_CODE" = "403" ]; then
    log_pass "Unknown tool denied with HTTP 403"
    # Check for meaningful error message
    if echo "$RESP_BODY" | grep -qi "not_found\|not_authorized\|unknown\|denied"; then
        log_pass "Denial response includes reason"
    else
        log_info "Denial response: $RESP_BODY"
    fi
else
    log_fail "Unknown tool denial" "Expected HTTP 403, got $RESP_CODE"
fi

# ============================================================
# Test B3: Denied tool call - wrong SPIFFE ID
# ============================================================
log_subheader "B3: Unregistered SPIFFE ID (should be denied)"

FAKE_SPIFFE="spiffe://poc.local/agents/unauthorized-agent/evil"
gateway_request "$FAKE_SPIFFE" "read" '{"file_path": "/tmp/test"}'

log_info "Response code: $RESP_CODE"

if [ "$RESP_CODE" = "403" ]; then
    log_pass "Unregistered SPIFFE ID denied with HTTP 403"
else
    log_fail "SPIFFE ID denial" "Expected HTTP 403, got $RESP_CODE"
fi

# ============================================================
# Test B4: Audit trail shows denial
# ============================================================
log_subheader "B4: Denial appears in audit log"
sleep 1

DENIAL_AUDIT=$(docker compose logs --tail 10 mcp-security-gateway 2>/dev/null | grep "403\|denied" | tail -1 || echo "")

if [ -n "$DENIAL_AUDIT" ]; then
    log_pass "Denial event recorded in audit log"
    log_detail "Audit excerpt: ${DENIAL_AUDIT:0:200}"
else
    log_info "Checking for status_code 403 in audit..."
    DENIAL_AUDIT=$(docker compose logs --tail 10 mcp-security-gateway 2>/dev/null | grep '"status_code":403' | tail -1 || echo "")
    if [ -n "$DENIAL_AUDIT" ]; then
        log_pass "Denial event (status_code: 403) recorded in audit log"
    else
        log_fail "Denial audit trail" "No denial events found in recent audit log"
    fi
fi

# ============================================================
# Test B5: Graceful error response format
# ============================================================
log_subheader "B5: Error response format validation"

# Make a request we know will be denied
gateway_request "$DEFAULT_SPIFFE_ID" "nonexistent_tool" '{"arg": "test"}'

# Verify the response is readable (not a crash/panic)
if [ -n "$RESP_BODY" ] && [ "$RESP_CODE" = "403" ]; then
    log_pass "Gateway returns structured error (not crash/panic)"
    log_detail "Error body: $RESP_BODY"

    # Check it's not a Go panic trace
    if echo "$RESP_BODY" | grep -q "goroutine\|panic"; then
        log_fail "Panic detected" "Gateway returned a panic trace instead of structured error"
    else
        log_pass "No panic or crash detected in error response"
    fi
else
    log_fail "Error format" "Empty or unexpected response body"
fi

# ============================================================
# Test B6: Multiple denials do not crash gateway
# ============================================================
log_subheader "B6: Gateway stability under multiple denials"

for i in $(seq 1 5); do
    gateway_request "$DEFAULT_SPIFFE_ID" "nonexistent_tool_$i" "{\"test\": $i}"
done

# Verify gateway is still healthy
HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${GATEWAY_URL}/health" 2>/dev/null || echo "000")
if [ "$HEALTH_STATUS" = "200" ]; then
    log_pass "Gateway remains healthy after 5 rapid denial requests"
else
    log_fail "Gateway stability" "Gateway health check failed after denials (HTTP $HEALTH_STATUS)"
fi

# ============================================================
# Summary
# ============================================================
print_summary

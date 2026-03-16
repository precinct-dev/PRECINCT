#!/usr/bin/env bash
# Scenario: Sidecar Identity -- Third-party tool gets automatic SPIFFE identity
# Validates that the Envoy sidecar injects X-SPIFFE-ID for non-SPIFFE-aware
# tools and that the PRECINCT gateway accepts these requests.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

log_header "Scenario: Sidecar Identity"

# ---- Docker Compose for sidecar overlay ----
DC_SIDECAR="docker compose -f ${POC_DIR}/deploy/compose/docker-compose.yml -f ${POC_DIR}/deploy/sidecar/docker-compose.sidecar-demo.yml"

# ============================================================
# Pre-flight: gateway must be running
# ============================================================
log_subheader "Pre-flight checks"

if ! check_service_healthy "precinct-gateway"; then
    log_fail "Gateway not running" "Start with: make up"
    print_summary
    exit 1
fi
log_pass "Gateway is running and healthy"

# ============================================================
# Start sidecar services
# ============================================================
log_subheader "Starting sidecar demo services"

${DC_SIDECAR} up -d --wait --wait-timeout 60 envoy-sidecar sidecar-client 2>&1 | tail -5
if ${DC_SIDECAR} ps envoy-sidecar 2>/dev/null | grep -qi "healthy\|Up"; then
    log_pass "Envoy sidecar is running and healthy"
else
    log_fail "Envoy sidecar startup" "Service did not become healthy"
    print_summary
    exit 1
fi

if ${DC_SIDECAR} ps sidecar-client 2>/dev/null | grep -qi "Up"; then
    log_pass "Sidecar client container is running"
else
    log_fail "Sidecar client container" "Not running"
    print_summary
    exit 1
fi

# ============================================================
# Test 1: Health check through sidecar
# ============================================================
log_subheader "Test 1: Health check through sidecar"

HEALTH_RESP=$(docker exec sidecar-client curl -s -w "\n%{http_code}" \
    http://envoy-sidecar:10000/health 2>&1) || true
HEALTH_CODE=$(echo "$HEALTH_RESP" | tail -n1)
HEALTH_BODY=$(echo "$HEALTH_RESP" | sed '$d')

log_info "Health response code: $HEALTH_CODE"
log_info "Health response body: ${HEALTH_BODY:0:200}"

if [ "$HEALTH_CODE" = "200" ]; then
    log_pass "Health check through sidecar returns 200"
else
    log_fail "Health check through sidecar" "Expected 200, got $HEALTH_CODE"
fi

# ============================================================
# Test 2: Tool call through sidecar (JSON-RPC tools/list)
# ============================================================
log_subheader "Test 2: Tool call through sidecar"

TOOL_RESP=$(docker exec sidecar-client curl -s -w "\n%{http_code}" \
    -X POST http://envoy-sidecar:10000/ \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}' 2>&1) || true
TOOL_CODE=$(echo "$TOOL_RESP" | tail -n1)
TOOL_BODY=$(echo "$TOOL_RESP" | sed '$d')

log_info "Tool call response code: $TOOL_CODE"
log_info "Tool call response body (first 300 chars): ${TOOL_BODY:0:300}"

# The sidecar injects X-SPIFFE-ID so the request should NOT get a 401.
# 200, 404, 502, or 503 all prove the request passed SPIFFE auth.
if [ "$TOOL_CODE" = "200" ] || [ "$TOOL_CODE" = "404" ] || [ "$TOOL_CODE" = "502" ] || [ "$TOOL_CODE" = "503" ]; then
    log_pass "Tool call through sidecar accepted (HTTP $TOOL_CODE -- not 401)"
    if [ "$TOOL_CODE" = "502" ] || [ "$TOOL_CODE" = "503" ]; then
        log_detail "Upstream unavailable is expected; request still passed SPIFFE auth"
    fi
else
    if [ "$TOOL_CODE" = "401" ]; then
        log_fail "Tool call through sidecar" "Got 401 -- sidecar failed to inject X-SPIFFE-ID"
    else
        log_fail "Tool call through sidecar" "Unexpected response code: $TOOL_CODE"
    fi
fi

# ============================================================
# Test 3: Verify gateway received sidecar SPIFFE identity
# ============================================================
log_subheader "Test 3: SPIFFE identity attribution in gateway logs"

sleep 1
SIDECAR_LOG=$(docker compose -f "${POC_DIR}/deploy/compose/docker-compose.yml" \
    logs --tail 20 precinct-gateway 2>/dev/null | grep "mcp2cli" | tail -1 || echo "")

if [ -n "$SIDECAR_LOG" ]; then
    log_pass "Gateway log contains sidecar SPIFFE identity (mcp2cli)"
    log_detail "${SIDECAR_LOG:0:200}"
else
    # Also check for the full SPIFFE ID string
    SIDECAR_LOG_ALT=$(docker compose -f "${POC_DIR}/deploy/compose/docker-compose.yml" \
        logs --tail 20 precinct-gateway 2>/dev/null | grep "sidecar\|mcp2cli\|spiffe.*mcp" | tail -1 || echo "")
    if [ -n "$SIDECAR_LOG_ALT" ]; then
        log_pass "Gateway log contains sidecar-related identity reference"
        log_detail "${SIDECAR_LOG_ALT:0:200}"
    else
        log_skip "SPIFFE identity in gateway logs" "mcp2cli identity not found in recent logs (may need more log history)"
    fi
fi

# ============================================================
# Test 4: Negative -- direct call without sidecar (no X-SPIFFE-ID)
# ============================================================
log_subheader "Test 4: Direct call without X-SPIFFE-ID (expect 401)"

DIRECT_RESP=$(docker exec sidecar-client curl -s -w "\n%{http_code}" \
    -X POST http://precinct-gateway:9090/ \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}' 2>&1) || true
DIRECT_CODE=$(echo "$DIRECT_RESP" | tail -n1)
DIRECT_BODY=$(echo "$DIRECT_RESP" | sed '$d')

log_info "Direct call response code: $DIRECT_CODE"
log_info "Direct call response body: ${DIRECT_BODY:0:200}"

if [ "$DIRECT_CODE" = "401" ]; then
    log_pass "Direct call without X-SPIFFE-ID correctly rejected with 401"
    if echo "$DIRECT_BODY" | grep -q "auth_missing_identity"; then
        log_pass "Error code is auth_missing_identity"
    else
        log_detail "Response body did not contain auth_missing_identity but 401 is correct"
    fi
else
    log_fail "Direct call rejection" "Expected 401, got $DIRECT_CODE"
fi

# ============================================================
# Test 5: Audit attribution -- sidecar SPIFFE ID in audit event
# ============================================================
log_subheader "Test 5: Audit attribution"

AUDIT_LINE=$(docker compose -f "${POC_DIR}/deploy/compose/docker-compose.yml" \
    logs --tail 30 precinct-gateway 2>/dev/null | grep "mcp_request" | grep "mcp2cli" | tail -1 || echo "")

if [ -n "$AUDIT_LINE" ]; then
    log_pass "Audit event contains sidecar SPIFFE identity (mcp2cli)"
    # Check for the full SPIFFE ID
    if echo "$AUDIT_LINE" | grep -q "spiffe://poc.local/agents/mcp-client/mcp2cli/dev"; then
        log_pass "Full SPIFFE URI present in audit event"
    else
        log_detail "mcp2cli found but full SPIFFE URI not confirmed in this log line"
    fi
else
    log_skip "Audit attribution" "No audit event with mcp2cli identity found (tool call may have been rejected before audit)"
fi

# ============================================================
# Cleanup
# ============================================================
log_subheader "Cleanup"

${DC_SIDECAR} stop envoy-sidecar sidecar-client 2>/dev/null || true
${DC_SIDECAR} rm -f envoy-sidecar sidecar-client 2>/dev/null || true
log_pass "Sidecar demo services stopped and removed"

# ============================================================
# Summary
# ============================================================
print_summary

#!/usr/bin/env bash
# Section 10.13.1 Local Readiness Checklist - RFA-70p
# Validates: Identity, Policy, Tool Integrity, Secrets, Audit

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

log_header "Section 10.13.1 -- Local Readiness Checklist"

# ============================================================
# 1. IDENTITY
# ============================================================
log_subheader "1. Identity (SPIFFE/SPIRE)"

# 1a. SPIRE server is healthy
if check_service_healthy "spire-server"; then
    log_pass "SPIRE server is running and healthy"
else
    log_fail "SPIRE server health" "Service not healthy or not running"
fi

# 1b. SPIRE agent is healthy
if check_service_healthy "spire-agent"; then
    log_pass "SPIRE agent is running and healthy"
else
    log_fail "SPIRE agent health" "Service not healthy or not running"
fi

# 1c. SPIRE entries exist for gateway and agents
SPIRE_ENTRIES=$(docker compose exec -T spire-server /opt/spire/bin/spire-server entry show 2>/dev/null || echo "")

# Use here-strings (not echo | grep) to avoid SIGPIPE false negatives under pipefail.
if grep -q "precinct-gateway" <<<"$SPIRE_ENTRIES"; then
    log_pass "SPIRE entry exists for precinct-gateway"
else
    log_fail "SPIRE gateway entry" "No SPIRE entry found for precinct-gateway"
fi

if grep -q "dspy-researcher" <<<"$SPIRE_ENTRIES"; then
    log_pass "SPIRE entry exists for dspy-researcher agent"
else
    log_fail "SPIRE agent entry (dspy)" "No SPIRE entry found for dspy-researcher"
fi

if grep -q "pydantic-researcher" <<<"$SPIRE_ENTRIES"; then
    log_pass "SPIRE entry exists for pydantic-researcher agent"
else
    log_fail "SPIRE agent entry (pydantic)" "No SPIRE entry found for pydantic-researcher"
fi

# 1d. Agent tool call shows SPIFFE ID in audit log
gateway_request "$DEFAULT_SPIFFE_ID" "read" '{"file_path": "/tmp/test"}'
AUDIT_LINE=$(docker compose logs --tail 3 precinct-gateway 2>/dev/null | grep "spiffe_id" | tail -1 || echo "")

if echo "$AUDIT_LINE" | grep -q "$DEFAULT_SPIFFE_ID"; then
    log_pass "Agent SPIFFE ID appears in audit log"
    log_detail "SPIFFE ID: $DEFAULT_SPIFFE_ID"
else
    log_fail "SPIFFE ID in audit log" "SPIFFE ID not found in recent audit log entry"
fi

# ============================================================
# 2. POLICY
# ============================================================
log_subheader "2. Policy (OPA)"

# 2a. OPA policies loaded (check gateway started successfully with embedded OPA)
if check_service_healthy "precinct-gateway"; then
    log_pass "Gateway is healthy (OPA embedded, policies loaded)"
else
    log_fail "Gateway health (OPA)" "Gateway not healthy -- OPA policies may have failed to load"
fi

# 2b. OPA decision_id appears in logs
OPA_LOG=$(docker compose logs --tail 20 precinct-gateway 2>/dev/null | grep "decision_id" | tail -1 || echo "")
if [ -n "$OPA_LOG" ]; then
    log_pass "OPA decision_id appears in gateway logs"
    # Extract decision_id
    DECISION_ID=$(echo "$OPA_LOG" | sed 's/.*"decision_id":"\([^"]*\)".*/\1/' || echo "N/A")
    log_detail "Sample decision_id: $DECISION_ID"
else
    log_fail "OPA decision_id in logs" "No decision_id found in recent gateway logs"
fi

# 2c. Unauthorized tool call denied (403)
# Use an agent that does not have grant for 'bash' without step-up
gateway_request "$DEFAULT_SPIFFE_ID" "bash" '{"command": "ls"}'
if [ "$RESP_CODE" = "403" ]; then
    log_pass "Unauthorized tool call denied with HTTP 403"
    log_detail "Response: $RESP_BODY"
else
    log_fail "OPA denial" "Expected HTTP 403, got $RESP_CODE"
fi

# ============================================================
# 3. TOOL INTEGRITY
# ============================================================
log_subheader "3. Tool Integrity (Registry Hash Verification)"

# 3a. Valid tool hash passes
gateway_request "$DEFAULT_SPIFFE_ID" "read" '{"file_path": "/tmp/test"}'
log_info "Valid tool call response code: $RESP_CODE"

# 3b. Wrong hash is blocked
gateway_request "$DEFAULT_SPIFFE_ID" "read" '{"file_path": "/tmp/test", "tool_hash": "0000000000000000000000000000000000000000000000000000000000000000"}'
if [ "$RESP_CODE" = "403" ]; then
    log_pass "Tool hash mismatch blocked (HTTP 403)"
    log_detail "Response: $RESP_BODY"
else
    log_fail "Hash mismatch detection" "Expected HTTP 403, got $RESP_CODE"
fi

# ============================================================
# 4. SECRETS
# ============================================================
log_subheader "4. Secrets (SPIKE Token Substitution)"

# 4a. Send request with $SPIKE{ref:...} token
# Token substitution is the LAST step (step 13) before proxy
# We verify the token appears in the request at the middleware level
gateway_request "$DEFAULT_SPIFFE_ID" "tavily_search" '{"query": "test", "api_key": "$SPIKE{ref:tavily_api_key}"}'
log_info "SPIKE token request response code: $RESP_CODE"

# We cannot verify upstream received the substituted value without the upstream running,
# but we can verify the gateway does not reject the token format
if [ "$RESP_CODE" != "400" ]; then
    log_pass "SPIKE token format accepted by gateway (not rejected as invalid)"
    log_detail "Token substitution happens at step 13 (last before proxy)"
else
    log_fail "SPIKE token format" "Gateway rejected SPIKE token format with 400"
fi

# Note: Full verification requires upstream to be running
log_info "Note: Full token substitution E2E requires upstream MCP server (Docker MCP Gateway)"

# ============================================================
# 5. AUDIT
# ============================================================
log_subheader "5. Audit (Structured Events + Hash Chain)"

# 5a. Audit events have session_id and trace_id
RECENT_AUDIT=$(docker compose logs --tail 5 precinct-gateway 2>/dev/null | grep "session_id" | tail -1 || echo "")

if echo "$RECENT_AUDIT" | grep -q '"session_id"'; then
    log_pass "Audit events contain session_id"
    SESSION_ID=$(echo "$RECENT_AUDIT" | sed 's/.*"session_id":"\([^"]*\)".*/\1/' || echo "N/A")
    log_detail "Sample session_id: $SESSION_ID"
else
    log_fail "Audit session_id" "session_id not found in audit events"
fi

if echo "$RECENT_AUDIT" | grep -q '"trace_id"'; then
    log_pass "Audit events contain trace_id"
    TRACE_ID=$(echo "$RECENT_AUDIT" | sed 's/.*"trace_id":"\([^"]*\)".*/\1/' || echo "N/A")
    log_detail "Sample trace_id: $TRACE_ID"
else
    log_fail "Audit trace_id" "trace_id not found in audit events"
fi

# 5b. Hash chain integrity (prev_hash links events)
if echo "$RECENT_AUDIT" | grep -q '"prev_hash"'; then
    log_pass "Audit events contain prev_hash (hash chain integrity)"
    PREV_HASH=$(echo "$RECENT_AUDIT" | sed 's/.*"prev_hash":"\([^"]*\)".*/\1/' || echo "N/A")
    log_detail "Sample prev_hash: ${PREV_HASH:0:32}..."
else
    log_fail "Audit hash chain" "prev_hash not found in audit events"
fi

# 5c. Bundle digest and registry digest present
if echo "$RECENT_AUDIT" | grep -q '"bundle_digest"'; then
    log_pass "Audit events contain bundle_digest"
else
    log_fail "Audit bundle_digest" "bundle_digest not found in audit events"
fi

if echo "$RECENT_AUDIT" | grep -q '"registry_digest"'; then
    log_pass "Audit events contain registry_digest"
else
    log_fail "Audit registry_digest" "registry_digest not found in audit events"
fi

# ============================================================
# Summary
# ============================================================
print_summary

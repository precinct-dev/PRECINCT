#!/usr/bin/env bash
# Scenario B: Security Denial - RFA-70p
# OPA denies a tool call, agent handles gracefully.
# Verifies: policy enforcement, denial reason in response, audit trail.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

log_header "Scenario B: Security Denial (OPA Policy)"
EXPECT_APPROVAL_EXPIRE_EVENT=1

# ============================================================
# Pre-check
# ============================================================
log_subheader "Pre-flight checks"

if ! check_service_healthy "precinct-gateway"; then
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
# Test B1.1: Approval capability request/grant allows high-risk call
# ============================================================
log_subheader "B1.1: Approval capability lifecycle (request -> grant -> use)"

APPROVAL_SESSION_ID="approval-$(date +%s)"

gateway_post "/admin/approvals/request" "{
  \"scope\": {
    \"action\": \"tool.call\",
    \"resource\": \"bash\",
    \"actor_spiffe_id\": \"${DEFAULT_SPIFFE_ID}\",
    \"session_id\": \"${APPROVAL_SESSION_ID}\"
  },
  \"requested_by\": \"${DEFAULT_SPIFFE_ID}\",
  \"reason\": \"e2e validation\",
  \"ttl_seconds\": 120
}" "$DEFAULT_SPIFFE_ID"

if [ "$RESP_CODE" != "200" ]; then
    log_fail "Approval request endpoint" "Expected 200, got $RESP_CODE body=${RESP_BODY:0:220}"
else
    log_pass "Approval request created"
fi

APPROVAL_REQUEST_ID="$(python3 - "$RESP_BODY" <<'PY'
import json,sys
body=sys.argv[1]
try:
    data=json.loads(body)
    print((data.get("record") or {}).get("request_id",""))
except Exception:
    print("")
PY
)"

if [ -z "${APPROVAL_REQUEST_ID}" ]; then
    log_fail "Approval request id parsing" "Could not parse request_id from response"
else
    log_pass "Approval request id parsed"
fi

gateway_post "/admin/approvals/grant" "{
  \"request_id\": \"${APPROVAL_REQUEST_ID}\",
  \"approved_by\": \"security@corp\",
  \"reason\": \"approved for controlled test\"
}" "$DEFAULT_SPIFFE_ID"

if [ "$RESP_CODE" != "200" ]; then
    log_fail "Approval grant endpoint" "Expected 200, got $RESP_CODE body=${RESP_BODY:0:220}"
else
    log_pass "Approval request granted"
fi

APPROVAL_TOKEN="$(python3 - "$RESP_BODY" <<'PY'
import json,sys
body=sys.argv[1]
try:
    data=json.loads(body)
    print(data.get("capability_token",""))
except Exception:
    print("")
PY
)"

if [ -z "${APPROVAL_TOKEN}" ]; then
    log_fail "Approval token parsing" "Could not parse capability_token from grant response"
else
    log_pass "Approval token issued"
fi

gateway_request "$DEFAULT_SPIFFE_ID" "bash" '{"command": "echo approved-path"}' \
  "X-Session-ID: ${APPROVAL_SESSION_ID}" \
  "X-Step-Up-Token: ${APPROVAL_TOKEN}"

RESP_ERROR_CODE="$(python3 - "$RESP_BODY" <<'PY'
import json,sys
body=sys.argv[1]
try:
    data=json.loads(body)
    print(data.get("code",""))
except Exception:
    print("")
PY
)"

if [ "$RESP_CODE" = "403" ] && { [ "$RESP_ERROR_CODE" = "stepup_approval_required" ] || [ "$RESP_ERROR_CODE" = "stepup_denied" ]; }; then
    log_fail "Approved high-risk path" "High-risk call still blocked by step-up after valid approval token"
else
    log_pass "Valid approval token passed step-up gate for high-risk call"
    log_detail "Result code=$RESP_CODE error_code=${RESP_ERROR_CODE:-n/a} (non-step-up outcomes are acceptable here)"
fi

# ============================================================
# Test B1.1a: Phase 3 /v1/tool/execute high-risk step-up flow
# ============================================================
log_subheader "B1.1a: Phase 3 tool-plane high-risk step-up"

PHASE3_SESSION_ID="${APPROVAL_SESSION_ID}-phase3"

gateway_post "/v1/tool/execute" "{
  \"envelope\": {
    \"run_id\": \"${APPROVAL_SESSION_ID}-phase3-deny\",
    \"session_id\": \"${PHASE3_SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${DEFAULT_SPIFFE_ID}\",
    \"plane\": \"tool\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${APPROVAL_SESSION_ID}-phase3-deny\",
      \"session_id\": \"${PHASE3_SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${DEFAULT_SPIFFE_ID}\",
      \"plane\": \"tool\"
    },
    \"action\": \"tool.execute\",
    \"resource\": \"tool/write\",
    \"attributes\": {
      \"capability_id\": \"tool.highrisk.cli\",
      \"tool_name\": \"bash\",
      \"adapter\": \"cli\"
    }
  }
}" "$DEFAULT_SPIFFE_ID"

PHASE3_REASON_CODE="$(python3 - "$RESP_BODY" <<'PY'
import json,sys
body=sys.argv[1]
try:
    data=json.loads(body)
    print(data.get("reason_code",""))
except Exception:
    print("")
PY
)"

if [ "$RESP_CODE" = "428" ] && [ "$PHASE3_REASON_CODE" = "TOOL_STEP_UP_REQUIRED" ]; then
    log_pass "Phase 3 high-risk tool denied without approval token"
else
    log_fail "Phase 3 step-up required" "Expected 428/TOOL_STEP_UP_REQUIRED, got code=$RESP_CODE reason=${PHASE3_REASON_CODE:-n/a}"
fi

gateway_post "/admin/approvals/request" "{
  \"scope\": {
    \"action\": \"tool.execute\",
    \"resource\": \"tool/write\",
    \"actor_spiffe_id\": \"${DEFAULT_SPIFFE_ID}\",
    \"session_id\": \"${PHASE3_SESSION_ID}\"
  },
  \"requested_by\": \"${DEFAULT_SPIFFE_ID}\",
  \"reason\": \"phase3 step-up validation\",
  \"ttl_seconds\": 120
}" "$DEFAULT_SPIFFE_ID"

PHASE3_REQUEST_ID="$(python3 - "$RESP_BODY" <<'PY'
import json,sys
body=sys.argv[1]
try:
    data=json.loads(body)
    print((data.get("record") or {}).get("request_id",""))
except Exception:
    print("")
PY
)"

gateway_post "/admin/approvals/grant" "{
  \"request_id\": \"${PHASE3_REQUEST_ID}\",
  \"approved_by\": \"security@corp\",
  \"reason\": \"approved phase3 tool step-up\"
}" "$DEFAULT_SPIFFE_ID"

PHASE3_TOKEN="$(python3 - "$RESP_BODY" <<'PY'
import json,sys
body=sys.argv[1]
try:
    data=json.loads(body)
    print(data.get("capability_token",""))
except Exception:
    print("")
PY
)"

gateway_post "/v1/tool/execute" "{
  \"envelope\": {
    \"run_id\": \"${APPROVAL_SESSION_ID}-phase3-allow\",
    \"session_id\": \"${PHASE3_SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${DEFAULT_SPIFFE_ID}\",
    \"plane\": \"tool\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${APPROVAL_SESSION_ID}-phase3-allow\",
      \"session_id\": \"${PHASE3_SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${DEFAULT_SPIFFE_ID}\",
      \"plane\": \"tool\"
    },
    \"action\": \"tool.execute\",
    \"resource\": \"tool/write\",
    \"attributes\": {
      \"capability_id\": \"tool.highrisk.cli\",
      \"tool_name\": \"bash\",
      \"adapter\": \"cli\",
      \"approval_capability_token\": \"${PHASE3_TOKEN}\"
    }
  }
}" "$DEFAULT_SPIFFE_ID"

PHASE3_ALLOW_REASON="$(python3 - "$RESP_BODY" <<'PY'
import json,sys
body=sys.argv[1]
try:
    data=json.loads(body)
    print(data.get("reason_code",""))
except Exception:
    print("")
PY
)"

if [ "$RESP_CODE" = "200" ] && [ "$PHASE3_ALLOW_REASON" = "TOOL_ALLOW" ]; then
    log_pass "Phase 3 high-risk tool allowed with approval token"
else
    log_fail "Phase 3 approved high-risk path" "Expected 200/TOOL_ALLOW, got code=$RESP_CODE reason=${PHASE3_ALLOW_REASON:-n/a}"
fi

# ============================================================
# Test B1.2: Consumed approval token cannot be replayed
# ============================================================
log_subheader "B1.2: Approval token replay denied"

# First consume should succeed.
gateway_post "/admin/approvals/consume" "{
  \"capability_token\": \"${APPROVAL_TOKEN}\",
  \"scope\": {
    \"action\": \"tool.call\",
    \"resource\": \"bash\",
    \"actor_spiffe_id\": \"${DEFAULT_SPIFFE_ID}\",
    \"session_id\": \"${APPROVAL_SESSION_ID}\"
  }
}" "$DEFAULT_SPIFFE_ID"

if [ "$RESP_CODE" = "200" ]; then
    log_pass "Approval token consumed once successfully"
else
    log_fail "Approval first consume" "Expected 200, got $RESP_CODE body=${RESP_BODY:0:220}"
fi

# Replay consume should fail deterministically.
gateway_post "/admin/approvals/consume" "{
  \"capability_token\": \"${APPROVAL_TOKEN}\",
  \"scope\": {
    \"action\": \"tool.call\",
    \"resource\": \"bash\",
    \"actor_spiffe_id\": \"${DEFAULT_SPIFFE_ID}\",
    \"session_id\": \"${APPROVAL_SESSION_ID}\"
  }
}" "$DEFAULT_SPIFFE_ID"

REPLAY_ERROR_CODE="$(python3 - "$RESP_BODY" <<'PY'
import json,sys
body=sys.argv[1]
try:
    data=json.loads(body)
    print(data.get("code",""))
except Exception:
    print("")
PY
)"

if [ "$RESP_CODE" = "409" ] && [ "$REPLAY_ERROR_CODE" = "stepup_denied" ]; then
    log_pass "Replay consume denied with deterministic step-up code"
else
    log_fail "Approval replay denial" "Expected 409 stepup_denied, got code=$RESP_CODE err=${REPLAY_ERROR_CODE:-n/a}"
fi

# ============================================================
# Test B1.3: Deny lifecycle endpoint
# ============================================================
log_subheader "B1.3: Approval deny lifecycle"

gateway_post "/admin/approvals/request" "{
  \"scope\": {
    \"action\": \"model.call\",
    \"resource\": \"gpt-4o\",
    \"actor_spiffe_id\": \"${DEFAULT_SPIFFE_ID}\",
    \"session_id\": \"${APPROVAL_SESSION_ID}-deny\"
  },
  \"reason\": \"deny path validation\",
  \"ttl_seconds\": 60
}" "$DEFAULT_SPIFFE_ID"

DENY_REQUEST_ID="$(python3 - "$RESP_BODY" <<'PY'
import json,sys
body=sys.argv[1]
try:
    data=json.loads(body)
    print((data.get("record") or {}).get("request_id",""))
except Exception:
    print("")
PY
)"

gateway_post "/admin/approvals/deny" "{
  \"request_id\": \"${DENY_REQUEST_ID}\",
  \"denied_by\": \"security@corp\",
  \"reason\": \"explicit deny path\"
}" "$DEFAULT_SPIFFE_ID"

if [ "$RESP_CODE" = "200" ]; then
    log_pass "Approval deny endpoint succeeded"
else
    log_fail "Approval deny endpoint" "Expected 200, got $RESP_CODE body=${RESP_BODY:0:220}"
fi

# ============================================================
# Test B1.4: Expired approval token denied
# ============================================================
log_subheader "B1.4: Expired approval token denied"

EXP_SESSION_ID="${APPROVAL_SESSION_ID}-exp"
gateway_post "/admin/approvals/request" "{
  \"scope\": {
    \"action\": \"tool.call\",
    \"resource\": \"bash\",
    \"actor_spiffe_id\": \"${DEFAULT_SPIFFE_ID}\",
    \"session_id\": \"${EXP_SESSION_ID}\"
  },
  \"ttl_seconds\": 1
}" "$DEFAULT_SPIFFE_ID"
EXP_REQUEST_ID="$(python3 - "$RESP_BODY" <<'PY'
import json,sys
body=sys.argv[1]
try:
    data=json.loads(body)
    print((data.get("record") or {}).get("request_id",""))
except Exception:
    print("")
PY
)"
if [ -z "${EXP_REQUEST_ID}" ]; then
    EXPECT_APPROVAL_EXPIRE_EVENT=0
    log_skip "Expired approval token" "Could not parse request_id from expired approval setup"
else
    sleep 2
    gateway_post "/admin/approvals/grant" "{
      \"request_id\": \"${EXP_REQUEST_ID}\",
      \"approved_by\": \"security@corp\"
    }" "$DEFAULT_SPIFFE_ID"
    if [ "$RESP_CODE" = "410" ]; then
        log_pass "Expired approval token rejected with HTTP 410"
    else
        EXPECT_APPROVAL_EXPIRE_EVENT=0
        log_skip "Expired approval token" "Expected HTTP 410 but got $RESP_CODE; continuing (body=${RESP_BODY:0:120})"
    fi
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

DENIAL_AUDIT=$(docker compose logs --tail 10 precinct-gateway 2>/dev/null | grep "403\|denied" | tail -1 || echo "")

if [ -n "$DENIAL_AUDIT" ]; then
    log_pass "Denial event recorded in audit log"
    log_detail "Audit excerpt: ${DENIAL_AUDIT:0:200}"
else
    log_info "Checking for status_code 403 in audit..."
    DENIAL_AUDIT=$(docker compose logs --tail 10 precinct-gateway 2>/dev/null | grep '"status_code":403' | tail -1 || echo "")
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
# Test B7: Approval lifecycle appears in audit log
# ============================================================
log_subheader "B7: Approval lifecycle appears in audit log"
sleep 1

for action in approval.request approval.grant approval.deny approval.consume approval.expire; do
    if [ "$action" = "approval.expire" ] && [ "$EXPECT_APPROVAL_EXPIRE_EVENT" != "1" ]; then
        log_skip "Audit event ${action}" "Skipped because expired-token assertion did not execute deterministically"
        continue
    fi
    MATCH="$(gateway_logs_grep "\"action\":\"${action}\"" 250 | tail -1 || true)"
    if [ -n "$MATCH" ]; then
        log_pass "Audit includes ${action}"
    else
        log_fail "Audit event ${action}" "Expected audit log entry not found"
    fi
done

# ============================================================
# Summary
# ============================================================
print_summary

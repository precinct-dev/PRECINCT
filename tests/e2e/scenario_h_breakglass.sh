#!/usr/bin/env bash
# Scenario H: Break-Glass Control Plane Lifecycle
# Verifies dual-authorization activation, scoped/time-bound override behavior,
# explicit incident metadata, and audit chain markers.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

log_header "Scenario H: Break-Glass Control Plane"

if ! check_service_healthy "mcp-security-gateway"; then
    log_fail "Gateway not running" "Start with: make up"
    print_summary
    exit 1
fi
log_pass "Gateway is running"

SESSION_ID="bg-session-$(date +%s)"
INCIDENT_ID="INC-BG-$(date +%s)"
SPIFFE_ID="${DEFAULT_SPIFFE_ID}"
MODEL_IN_SCOPE="gpt-4o"
MODEL_OUT_SCOPE="gpt-4o-mini"

model_call_body() {
    local run_id="$1"
    local model="$2"
    cat <<EOF
{
  "envelope": {
    "run_id": "${run_id}",
    "session_id": "${SESSION_ID}",
    "tenant": "tenant-a",
    "actor_spiffe_id": "${SPIFFE_ID}",
    "plane": "model"
  },
  "policy": {
    "envelope": {
      "run_id": "${run_id}",
      "session_id": "${SESSION_ID}",
      "tenant": "tenant-a",
      "actor_spiffe_id": "${SPIFFE_ID}",
      "plane": "model"
    },
    "action": "model.call",
    "resource": "model/inference",
    "attributes": {
      "provider": "openai",
      "model": "${model}",
      "risk_mode": "high"
    }
  }
}
EOF
}

json_field() {
    local body="$1"
    local expr="$2"
    python3 - "$body" "$expr" <<'PY'
import json,sys
body=sys.argv[1]
expr=sys.argv[2]
try:
    data=json.loads(body)
except Exception:
    print("")
    raise SystemExit(0)
cur=data
for part in expr.split("."):
    if isinstance(cur, dict):
        cur=cur.get(part, "")
    else:
        cur=""
        break
if cur is None:
    cur=""
print(cur)
PY
}

log_subheader "H1: Baseline high-risk model call denied"
gateway_post "/v1/model/call" "$(model_call_body "bg-deny-before" "${MODEL_IN_SCOPE}")" "${SPIFFE_ID}"
BASELINE_REASON="$(json_field "$RESP_BODY" "reason_code")"
if [ "$RESP_CODE" = "403" ] && [ "$BASELINE_REASON" = "MODEL_PROVIDER_RISK_MODE_DENIED" ]; then
    log_pass "Baseline denial reason is deterministic"
else
    log_fail "Baseline denial" "Expected 403/MODEL_PROVIDER_RISK_MODE_DENIED, got code=$RESP_CODE reason=$BASELINE_REASON body=${RESP_BODY:0:220}"
fi

log_subheader "H2: Break-glass lifecycle request/approve/activate"
gateway_post "/admin/breakglass/request" "{
  \"incident_id\": \"${INCIDENT_ID}\",
  \"scope\": {
    \"action\": \"model.call\",
    \"resource\": \"${MODEL_IN_SCOPE}\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\"
  },
  \"requested_by\": \"security@corp\",
  \"ttl_seconds\": 120,
  \"reason\": \"incident response override\"
}" "${SPIFFE_ID}"
REQUEST_ID="$(json_field "$RESP_BODY" "record.request_id")"
if [ "$RESP_CODE" = "200" ] && [ -n "$REQUEST_ID" ]; then
    log_pass "Break-glass request created"
else
    log_fail "Break-glass request" "Expected request_id with 200, got code=$RESP_CODE body=${RESP_BODY:0:220}"
fi

gateway_post "/admin/breakglass/approve" "{
  \"request_id\": \"${REQUEST_ID}\",
  \"approved_by\": \"security-1@corp\"
}" "${SPIFFE_ID}"
if [ "$RESP_CODE" = "200" ]; then
    log_pass "First approval accepted"
else
    log_fail "First approval" "Expected 200, got $RESP_CODE body=${RESP_BODY:0:220}"
fi

gateway_post "/admin/breakglass/activate" "{
  \"request_id\": \"${REQUEST_ID}\",
  \"activated_by\": \"ops@corp\"
}" "${SPIFFE_ID}"
DUAL_AUTH_CODE="$(json_field "$RESP_BODY" "code")"
if [ "$RESP_CODE" = "403" ] && [ "$DUAL_AUTH_CODE" = "authz_policy_denied" ]; then
    log_pass "Dual-authorization enforced before activation"
else
    log_fail "Dual-authorization enforcement" "Expected 403/authz_policy_denied before second approval, got code=$RESP_CODE err=${DUAL_AUTH_CODE:-n/a}"
fi

gateway_post "/admin/breakglass/approve" "{
  \"request_id\": \"${REQUEST_ID}\",
  \"approved_by\": \"security-2@corp\"
}" "${SPIFFE_ID}"
if [ "$RESP_CODE" = "200" ]; then
    log_pass "Second approval accepted"
else
    log_fail "Second approval" "Expected 200, got $RESP_CODE body=${RESP_BODY:0:220}"
fi

gateway_post "/admin/breakglass/activate" "{
  \"request_id\": \"${REQUEST_ID}\",
  \"activated_by\": \"ops@corp\"
}" "${SPIFFE_ID}"
ACTIVE_STATUS="$(json_field "$RESP_BODY" "record.status")"
if [ "$RESP_CODE" = "200" ] && [ "$ACTIVE_STATUS" = "active" ]; then
    log_pass "Break-glass activated with dual authorization"
else
    log_fail "Activation" "Expected active status after dual approval, got code=$RESP_CODE status=$ACTIVE_STATUS body=${RESP_BODY:0:220}"
fi

log_subheader "H3: In-scope operation allowed during active override"
gateway_post "/v1/model/call" "$(model_call_body "bg-allow-active" "${MODEL_IN_SCOPE}")" "${SPIFFE_ID}"
ALLOW_REASON="$(json_field "$RESP_BODY" "reason_code")"
ALLOW_INCIDENT="$(json_field "$RESP_BODY" "metadata.break_glass_incident_id")"
if [ "$RESP_CODE" = "200" ] && [ "$ALLOW_REASON" = "MODEL_ALLOW" ] && [ "$ALLOW_INCIDENT" = "${INCIDENT_ID}" ]; then
    log_pass "In-scope high-risk call allowed with incident metadata"
else
    log_fail "In-scope allow" "Expected 200/MODEL_ALLOW with incident metadata, got code=$RESP_CODE reason=$ALLOW_REASON incident=$ALLOW_INCIDENT body=${RESP_BODY:0:220}"
fi

log_subheader "H4: Out-of-scope operation remains denied"
gateway_post "/v1/model/call" "$(model_call_body "bg-deny-out-scope" "${MODEL_OUT_SCOPE}")" "${SPIFFE_ID}"
OUT_SCOPE_REASON="$(json_field "$RESP_BODY" "reason_code")"
if [ "$RESP_CODE" = "403" ] && [ "$OUT_SCOPE_REASON" = "MODEL_PROVIDER_RISK_MODE_DENIED" ]; then
    log_pass "Out-of-scope call remains denied"
else
    log_fail "Out-of-scope enforcement" "Expected 403/MODEL_PROVIDER_RISK_MODE_DENIED, got code=$RESP_CODE reason=$OUT_SCOPE_REASON body=${RESP_BODY:0:220}"
fi

log_subheader "H5: Revert disables override"
gateway_post "/admin/breakglass/revert" "{
  \"request_id\": \"${REQUEST_ID}\",
  \"reverted_by\": \"ops@corp\",
  \"reason\": \"incident stabilized\"
}" "${SPIFFE_ID}"
REVERT_STATUS="$(json_field "$RESP_BODY" "record.status")"
if [ "$RESP_CODE" = "200" ] && [ "$REVERT_STATUS" = "reverted" ]; then
    log_pass "Break-glass reverted"
else
    log_fail "Revert" "Expected reverted status, got code=$RESP_CODE status=$REVERT_STATUS body=${RESP_BODY:0:220}"
fi

gateway_post "/v1/model/call" "$(model_call_body "bg-deny-after-revert" "${MODEL_IN_SCOPE}")" "${SPIFFE_ID}"
POST_REVERT_REASON="$(json_field "$RESP_BODY" "reason_code")"
if [ "$RESP_CODE" = "403" ] && [ "$POST_REVERT_REASON" = "MODEL_PROVIDER_RISK_MODE_DENIED" ]; then
    log_pass "Post-revert high-risk call denied again"
else
    log_fail "Post-revert denial" "Expected 403/MODEL_PROVIDER_RISK_MODE_DENIED, got code=$RESP_CODE reason=$POST_REVERT_REASON body=${RESP_BODY:0:220}"
fi

log_subheader "H6: Audit chain includes elevated break-glass markers"
sleep 1
for action in breakglass.request breakglass.approve breakglass.activate breakglass.revert; do
    MATCH="$(gateway_logs_grep "\"action\":\"${action}\"" 250 | tail -1 || true)"
    if [ -n "$MATCH" ] && echo "$MATCH" | grep -q "elevated_audit=true"; then
        log_pass "Audit includes ${action} with elevated marker"
    else
        log_fail "Audit ${action}" "Expected elevated audit marker for ${action}"
    fi
done

print_summary

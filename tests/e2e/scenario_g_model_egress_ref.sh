#!/usr/bin/env bash
# Scenario G: Phase 3 model egress with SPIKE header reference
# Validates OpenAI-compatible gateway route + Authorization header token substitution.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

log_header "Scenario G: Model Egress via SPIKE Reference Header"

if ! check_service_healthy "precinct-gateway"; then
    log_fail "Gateway not running" "Start with: make up"
    print_summary
    exit 1
fi
log_pass "Gateway is running and healthy"

MODEL_BODY='{
  "model": "llama-3.3-70b-versatile",
  "messages": [
    {"role": "user", "content": "Return a short confirmation string."}
  ]
}'

FULL_RESP=$(curl -s -w "\n%{http_code}" -X POST "${GATEWAY_URL}/openai/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: ${DEFAULT_SPIFFE_ID}" \
  -H 'Authorization: Bearer $SPIKE{ref:deadbeef,exp:3600}' \
  -d "${MODEL_BODY}" 2>&1) || true

RESP_CODE="$(echo "$FULL_RESP" | tail -n1)"
RESP_BODY="$(echo "$FULL_RESP" | sed '$d')"

if [ "$RESP_CODE" = "200" ] && echo "$RESP_BODY" | grep -q "\"choices\""; then
    log_pass "OpenAI-compatible model route succeeded with SPIKE reference header"
else
    log_fail "Model egress with SPIKE header reference" "Expected HTTP 200 with choices; got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

AUDIT_HIT=$($DC logs --no-log-prefix --tail 250 precinct-gateway 2>/dev/null | grep "openai/v1/chat/completions" | grep "MODEL_" || true)
if [ -n "$AUDIT_HIT" ]; then
    log_pass "Audit includes model egress decision for OpenAI-compatible route"
else
    log_fail "Model egress audit evidence" "No model egress audit line found in gateway logs"
fi

print_summary

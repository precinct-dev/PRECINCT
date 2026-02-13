#!/usr/bin/env bash
# Scenario G: v2.4 Contract + Reason-Code Conformance
# Validates control-plane responses can be checked against the frozen v2.4 contract artifacts.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

CATALOG_PATH="${POC_DIR}/contracts/v2.4/reason-code-catalog.v2.4.json"

extract_json_field() {
    local body="$1"
    local key="$2"
    printf "%s" "$body" | python3 -c 'import json,sys
key = sys.argv[1]
try:
    obj = json.load(sys.stdin)
    val = obj.get(key, "")
    if isinstance(val, (dict, list)):
        print(json.dumps(val, sort_keys=True))
    else:
        print(val)
except Exception:
    print("")
' "$key"
}

is_reason_code_known() {
    local code="$1"
    python3 - "$CATALOG_PATH" "$code" <<'PY'
import json
import sys
path = sys.argv[1]
code = sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
codes = {entry["code"] for entry in data.get("codes", [])}
print("true" if code in codes else "false")
PY
}

assert_conformance_shape() {
    local body="$1"
    local endpoint="$2"

    local decision reason_code trace_id decision_id envelope
    decision="$(extract_json_field "$body" "decision")"
    reason_code="$(extract_json_field "$body" "reason_code")"
    trace_id="$(extract_json_field "$body" "trace_id")"
    decision_id="$(extract_json_field "$body" "decision_id")"
    envelope="$(extract_json_field "$body" "envelope")"

    [ -n "$decision" ] && log_pass "${endpoint}: decision field present" || log_fail "${endpoint}: decision field present" "missing decision"
    [ -n "$reason_code" ] && log_pass "${endpoint}: reason_code field present" || log_fail "${endpoint}: reason_code field present" "missing reason_code"
    [ -n "$trace_id" ] && log_pass "${endpoint}: trace_id field present" || log_fail "${endpoint}: trace_id field present" "missing trace_id"
    [ -n "$decision_id" ] && log_pass "${endpoint}: decision_id field present" || log_fail "${endpoint}: decision_id field present" "missing decision_id"
    [ -n "$envelope" ] && log_pass "${endpoint}: envelope field present" || log_fail "${endpoint}: envelope field present" "missing envelope"

    if [ -n "$reason_code" ]; then
        if [ "$(is_reason_code_known "$reason_code")" = "true" ]; then
            log_pass "${endpoint}: reason_code is in canonical v2.4 catalog"
        else
            log_fail "${endpoint}: reason_code is in canonical v2.4 catalog" "unknown reason code: ${reason_code}"
        fi
    fi
}

log_header "Scenario G: v2.4 Contract + Reason-Code Conformance"

if [ ! -f "$CATALOG_PATH" ]; then
    log_fail "Catalog file exists" "missing ${CATALOG_PATH}"
    print_summary
    exit 1
fi
log_pass "Catalog file exists"

if ! check_service_healthy "mcp-security-gateway"; then
    log_fail "Gateway running" "Start with: make -C POC up"
    print_summary
    exit 1
fi
log_pass "Gateway is running and healthy"

RUN_ID="phase3-contract-$(date +%s)"
SESSION_ID="phase3-contract-session-${RUN_ID}"
SPIFFE_ID="${DEFAULT_SPIFFE_ID}"
NOW_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# Ingress: prefer canonical /submit, fallback to legacy /admit for compatibility.
INGRESS_PATH="/v1/ingress/submit"
gateway_post "$INGRESS_PATH" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"ingress\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}\",
      \"session_id\": \"${SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${SPIFFE_ID}\",
      \"plane\": \"ingress\"
    },
    \"action\": \"ingress.admit\",
    \"resource\": \"ingress/event\",
    \"attributes\": {
      \"source_principal\": \"${SPIFFE_ID}\",
      \"event_id\": \"evt-${RUN_ID}\",
      \"event_timestamp\": \"${NOW_UTC}\"
    }
  }
}" "$SPIFFE_ID"

if [ "$RESP_CODE" = "404" ]; then
    INGRESS_PATH="/v1/ingress/admit"
    gateway_post "$INGRESS_PATH" "{
      \"envelope\": {
        \"run_id\": \"${RUN_ID}\",
        \"session_id\": \"${SESSION_ID}\",
        \"tenant\": \"tenant-a\",
        \"actor_spiffe_id\": \"${SPIFFE_ID}\",
        \"plane\": \"ingress\"
      },
      \"policy\": {
        \"envelope\": {
          \"run_id\": \"${RUN_ID}\",
          \"session_id\": \"${SESSION_ID}\",
          \"tenant\": \"tenant-a\",
          \"actor_spiffe_id\": \"${SPIFFE_ID}\",
          \"plane\": \"ingress\"
        },
        \"action\": \"ingress.admit\",
        \"resource\": \"ingress/event\",
        \"attributes\": {
          \"source_principal\": \"${SPIFFE_ID}\",
          \"event_id\": \"evt-${RUN_ID}\",
          \"event_timestamp\": \"${NOW_UTC}\"
        }
      }
    }" "$SPIFFE_ID"
    log_info "Ingress canonical path not available in current build; validated legacy alias /v1/ingress/admit"
fi

# If canonical /submit returns a non-plane envelope (e.g. proxy-layer error),
# fallback to /admit to validate current compatibility behavior.
if [ -z "$(extract_json_field "$RESP_BODY" "reason_code")" ]; then
    INGRESS_PATH="/v1/ingress/admit"
    gateway_post "$INGRESS_PATH" "{
      \"envelope\": {
        \"run_id\": \"${RUN_ID}\",
        \"session_id\": \"${SESSION_ID}\",
        \"tenant\": \"tenant-a\",
        \"actor_spiffe_id\": \"${SPIFFE_ID}\",
        \"plane\": \"ingress\"
      },
      \"policy\": {
        \"envelope\": {
          \"run_id\": \"${RUN_ID}\",
          \"session_id\": \"${SESSION_ID}\",
          \"tenant\": \"tenant-a\",
          \"actor_spiffe_id\": \"${SPIFFE_ID}\",
          \"plane\": \"ingress\"
        },
        \"action\": \"ingress.admit\",
        \"resource\": \"ingress/event\",
        \"attributes\": {
          \"source_principal\": \"${SPIFFE_ID}\",
          \"event_id\": \"evt-${RUN_ID}\",
          \"event_timestamp\": \"${NOW_UTC}\"
        }
      }
    }" "$SPIFFE_ID"
    log_info "Ingress /submit did not return phase-decision envelope; validated legacy alias /v1/ingress/admit"
fi

if [ "$RESP_CODE" = "200" ]; then
    log_pass "${INGRESS_PATH}: request accepted"
else
    log_fail "${INGRESS_PATH}: request accepted" "expected 200, got ${RESP_CODE} body=${RESP_BODY:0:200}"
fi
assert_conformance_shape "$RESP_BODY" "$INGRESS_PATH"

# Model deny path

gateway_post "/v1/model/call" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-model\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"model\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-model\",
      \"session_id\": \"${SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${SPIFFE_ID}\",
      \"plane\": \"model\"
    },
    \"action\": \"model.call\",
    \"resource\": \"model/inference\",
    \"attributes\": {
      \"provider\": \"openai\",
      \"model\": \"gpt-4o\",
      \"compliance_profile\": \"hipaa\",
      \"model_scope\": \"external\",
      \"prompt_has_phi\": true,
      \"prompt_action\": \"deny\",
      \"prompt\": \"Patient record with SSN 123-45-6789\"
    }
  }
}" "$SPIFFE_ID"

if [ "$RESP_CODE" = "403" ]; then
    log_pass "/v1/model/call: deny path returned expected status"
else
    log_fail "/v1/model/call: deny path returned expected status" "expected 403, got ${RESP_CODE} body=${RESP_BODY:0:200}"
fi
assert_conformance_shape "$RESP_BODY" "/v1/model/call"

print_summary

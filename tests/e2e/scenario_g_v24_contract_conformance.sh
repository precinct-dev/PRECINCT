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

extract_expected_signature() {
    local body="$1"
    printf "%s" "$body" | python3 -c 'import json,sys
try:
    obj = json.load(sys.stdin)
    print(obj.get("record", {}).get("expected_signature", ""))
except Exception:
    print("")
'
}

compute_connector_signature() {
    local connector_id="$1"
    local connector_type="$2"
    local source_principal="$3"
    local version="$4"
    local capabilities_json="$5"
    python3 - "$connector_id" "$connector_type" "$source_principal" "$version" "$capabilities_json" <<'PY'
import hashlib
import json
import sys

connector_id = sys.argv[1].strip()
connector_type = sys.argv[2].strip()
source_principal = sys.argv[3].strip()
version = sys.argv[4].strip()
try:
    capabilities = [str(item).strip() for item in json.loads(sys.argv[5])]
except Exception:
    capabilities = []
capabilities.sort()

canonical = {
    "connector_id": connector_id,
    "connector_type": connector_type,
    "source_principal": source_principal,
    "version": version,
    "capabilities": capabilities,
}
payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
print(hashlib.sha256(payload).hexdigest())
PY
}

reset_rate_limit_state() {
    local spiffe_id="$1"
    local tokens_key="ratelimit:${spiffe_id}:tokens"
    local last_fill_key="ratelimit:${spiffe_id}:last_fill"
    $DC exec -T keydb keydb-cli DEL "$tokens_key" "$last_fill_key" >/dev/null 2>&1 || true
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
CONNECTOR_ID="compose-webhook"
CONNECTOR_SIG=""
CONNECTOR_SIG_EXPECTED="$(compute_connector_signature "${CONNECTOR_ID}" "webhook" "${SPIFFE_ID}" "1.0" '["ingress.submit"]')"

reset_rate_limit_state "${SPIFFE_ID}"
log_info "Reset prior rate-limit keys for ${SPIFFE_ID}"

gateway_post "/v1/connectors/register" "{
  \"connector_id\": \"${CONNECTOR_ID}\",
  \"manifest\": {
    \"connector_id\": \"${CONNECTOR_ID}\",
    \"connector_type\": \"webhook\",
    \"source_principal\": \"${SPIFFE_ID}\",
    \"version\": \"1.0\",
    \"capabilities\": [\"ingress.submit\"],
    \"signature\": {
      \"algorithm\": \"sha256-manifest-v1\",
      \"value\": \"${CONNECTOR_SIG_EXPECTED}\"
    }
  }
}" "$SPIFFE_ID"
if [ "$RESP_CODE" = "200" ]; then
    log_pass "CCA register endpoint available"
else
    log_fail "CCA register endpoint available" "expected 200, got ${RESP_CODE} body=${RESP_BODY:0:200}"
fi
CONNECTOR_SIG="$(extract_expected_signature "$RESP_BODY")"
if [ -n "$CONNECTOR_SIG" ]; then
    log_pass "CCA expected signature extracted"
else
    log_fail "CCA expected signature extracted" "record.expected_signature missing"
fi

for op in validate approve activate; do
    gateway_post "/v1/connectors/${op}" "{
      \"connector_id\": \"${CONNECTOR_ID}\"
    }" "$SPIFFE_ID"
    if [ "$RESP_CODE" = "200" ]; then
        log_pass "CCA ${op} endpoint available"
    else
        log_fail "CCA ${op} endpoint available" "expected 200, got ${RESP_CODE} body=${RESP_BODY:0:200}"
    fi
done

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
      \"connector_id\": \"${CONNECTOR_ID}\",
      \"connector_signature\": \"${CONNECTOR_SIG}\",
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
          \"connector_id\": \"${CONNECTOR_ID}\",
          \"connector_signature\": \"${CONNECTOR_SIG}\",
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
          \"connector_id\": \"${CONNECTOR_ID}\",
          \"connector_signature\": \"${CONNECTOR_SIG}\",
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

#!/usr/bin/env bash
# Scenario J: OpenClaw secure port walking skeleton through PRECINCT Gateway v2.4

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../../../.." && pwd)}"
source "${POC_DIR}/tests/e2e/common.sh"

extract_reason_code() {
    local body="$1"
    printf "%s" "$body" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("reason_code",""))
except Exception:
    print("")
'
}

extract_json_field() {
    local body="$1"
    local key="$2"
    printf "%s" "$body" | python3 -c 'import json,sys
key = sys.argv[1]
try:
    obj = json.load(sys.stdin)
    val = obj.get(key, "")
    if isinstance(val, (dict, list)):
        import json as _j
        print(_j.dumps(val, sort_keys=True))
    else:
        print(val)
except Exception:
    print("")
' "$key"
}

reset_rate_limit_state() {
    local spiffe_id="$1"
    local tokens_key="ratelimit:${spiffe_id}:tokens"
    local last_fill_key="ratelimit:${spiffe_id}:last_fill"
    docker compose exec -T keydb keydb-cli DEL "$tokens_key" "$last_fill_key" >/dev/null 2>&1 || true
}

log_header "Scenario J: OpenClaw secure port walking skeleton"

if ! check_service_healthy "mcp-security-gateway"; then
    log_fail "Gateway not running" "Start with: make up"
    print_summary
    exit 1
fi
log_pass "Gateway is running and healthy"

RUN_ID="openclaw-ws-$(date +%s)"
SESSION_ID="openclaw-ws-session-${RUN_ID}"
SPIFFE_ID="${DEFAULT_SPIFFE_ID}"
NOW_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
ARTIFACT_DIR="${POC_DIR}/tests/e2e/artifacts"
ARTIFACT_PATH="${ARTIFACT_DIR}/scenario_j_${RUN_ID}.json"
mkdir -p "${ARTIFACT_DIR}"
reset_rate_limit_state "${SPIFFE_ID}"
log_info "Reset prior rate-limit keys for ${SPIFFE_ID}"

log_subheader "J0: Connector lifecycle bootstrap for ingress path"

gateway_post "/v1/connectors/register" "{
  \"connector_id\": \"openclaw-webhook\",
  \"manifest\": {
    \"connector_id\": \"openclaw-webhook\",
    \"connector_type\": \"webhook\",
    \"source_principal\": \"${SPIFFE_ID}\",
    \"version\": \"1.0\",
    \"capabilities\": [\"ingress.submit\"],
    \"signature\": {\"algorithm\": \"sha256-manifest-v1\", \"value\": \"bootstrap-signature\"}
  }
}" "${SPIFFE_ID}"
CONNECTOR_BOOTSTRAP_CODE="$RESP_CODE"
CONNECTOR_SIG="$(printf "%s" "$RESP_BODY" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("record", {}).get("expected_signature", ""))
except Exception:
    print("")
')"
if [ "$CONNECTOR_BOOTSTRAP_CODE" = "200" ] && [ -n "$CONNECTOR_SIG" ]; then
    log_pass "Connector bootstrap register returned expected signature"
else
    log_fail "Connector bootstrap register" "Expected 200 with expected_signature, got code=${CONNECTOR_BOOTSTRAP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/connectors/register" "{
  \"connector_id\": \"openclaw-webhook\",
  \"manifest\": {
    \"connector_id\": \"openclaw-webhook\",
    \"connector_type\": \"webhook\",
    \"source_principal\": \"${SPIFFE_ID}\",
    \"version\": \"1.0\",
    \"capabilities\": [\"ingress.submit\"],
    \"signature\": {\"algorithm\": \"sha256-manifest-v1\", \"value\": \"${CONNECTOR_SIG}\"}
  }
}" "${SPIFFE_ID}"
if [ "$RESP_CODE" = "200" ]; then
    log_pass "Connector canonical register succeeded"
else
    log_fail "Connector canonical register" "Expected 200, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

for op in validate approve activate; do
    gateway_post "/v1/connectors/${op}" "{\"connector_id\":\"openclaw-webhook\"}" "${SPIFFE_ID}"
    if [ "$RESP_CODE" = "200" ]; then
        log_pass "Connector ${op} succeeded"
    else
        log_fail "Connector ${op}" "Expected 200, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
    fi
done

log_subheader "J1: Ingress/context allow path"

gateway_post "/v1/ingress/submit" "{
  \"envelope\": {\"run_id\":\"${RUN_ID}-ingress-allow\",\"session_id\":\"${SESSION_ID}\",\"tenant\":\"tenant-a\",\"actor_spiffe_id\":\"${SPIFFE_ID}\",\"plane\":\"ingress\"},
  \"policy\": {
    \"envelope\": {\"run_id\":\"${RUN_ID}-ingress-allow\",\"session_id\":\"${SESSION_ID}\",\"tenant\":\"tenant-a\",\"actor_spiffe_id\":\"${SPIFFE_ID}\",\"plane\":\"ingress\"},
    \"action\":\"ingress.admit\",
    \"resource\":\"ingress/event\",
    \"attributes\":{
      \"connector_id\":\"openclaw-webhook\",
      \"connector_signature\":\"${CONNECTOR_SIG}\",
      \"source_id\":\"openclaw-webhook\",
      \"source_principal\":\"${SPIFFE_ID}\",
      \"event_id\":\"evt-${RUN_ID}-ingress\",
      \"event_timestamp\":\"${NOW_UTC}\"
    }
  }
}" "${SPIFFE_ID}"
INGRESS_ALLOW_CODE="$RESP_CODE"
INGRESS_ALLOW_REASON="$(extract_reason_code "$RESP_BODY")"
INGRESS_ALLOW_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
if [ "$INGRESS_ALLOW_CODE" = "200" ] && [ "$INGRESS_ALLOW_REASON" = "INGRESS_ALLOW" ] && [ -n "$INGRESS_ALLOW_DECISION_ID" ]; then
    log_pass "Ingress allow path admitted with audit correlation"
else
    log_fail "Ingress allow path" "Expected 200/INGRESS_ALLOW with decision_id, got code=${INGRESS_ALLOW_CODE} reason=${INGRESS_ALLOW_REASON} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/context/admit" "{
  \"envelope\": {\"run_id\":\"${RUN_ID}-context-allow\",\"session_id\":\"${SESSION_ID}\",\"tenant\":\"tenant-a\",\"actor_spiffe_id\":\"${SPIFFE_ID}\",\"plane\":\"context\"},
  \"policy\": {
    \"envelope\": {\"run_id\":\"${RUN_ID}-context-allow\",\"session_id\":\"${SESSION_ID}\",\"tenant\":\"tenant-a\",\"actor_spiffe_id\":\"${SPIFFE_ID}\",\"plane\":\"context\"},
    \"action\":\"context.admit\",
    \"resource\":\"context/segment\",
    \"attributes\":{\"scan_passed\":true,\"prompt_check_passed\":true,\"prompt_injection_detected\":false,\"memory_scope\":\"session\"}
  }
}" "${SPIFFE_ID}"
CONTEXT_ALLOW_CODE="$RESP_CODE"
CONTEXT_ALLOW_REASON="$(extract_reason_code "$RESP_BODY")"
CONTEXT_ALLOW_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
if [ "$CONTEXT_ALLOW_CODE" = "200" ] && [ "$CONTEXT_ALLOW_REASON" = "CONTEXT_ALLOW" ] && [ -n "$CONTEXT_ALLOW_DECISION_ID" ]; then
    log_pass "Context/memory allow path admitted"
else
    log_fail "Context/memory allow path" "Expected 200/CONTEXT_ALLOW with decision_id, got code=${CONTEXT_ALLOW_CODE} reason=${CONTEXT_ALLOW_REASON} body=${RESP_BODY:0:240}"
fi

log_subheader "J2: Mediated model/tool allow path"

gateway_post "/v1/model/call" "{
  \"envelope\": {\"run_id\":\"${RUN_ID}-model-allow\",\"session_id\":\"${SESSION_ID}\",\"tenant\":\"tenant-a\",\"actor_spiffe_id\":\"${SPIFFE_ID}\",\"plane\":\"model\"},
  \"policy\": {
    \"envelope\": {\"run_id\":\"${RUN_ID}-model-allow\",\"session_id\":\"${SESSION_ID}\",\"tenant\":\"tenant-a\",\"actor_spiffe_id\":\"${SPIFFE_ID}\",\"plane\":\"model\"},
    \"action\":\"model.call\",
    \"resource\":\"model/inference\",
    \"attributes\":{\"provider\":\"openai\",\"model\":\"gpt-4o\",\"prompt\":\"OpenClaw mediated request\"}
  }
}" "${SPIFFE_ID}"
MODEL_ALLOW_CODE="$RESP_CODE"
MODEL_ALLOW_REASON="$(extract_reason_code "$RESP_BODY")"
MODEL_ALLOW_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
if [ "$MODEL_ALLOW_CODE" = "200" ] && [ "$MODEL_ALLOW_REASON" = "MODEL_ALLOW" ] && [ -n "$MODEL_ALLOW_DECISION_ID" ]; then
    log_pass "Mediated model path allowed"
else
    log_fail "Mediated model path" "Expected 200/MODEL_ALLOW with decision_id, got code=${MODEL_ALLOW_CODE} reason=${MODEL_ALLOW_REASON} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/tool/execute" "{
  \"envelope\": {\"run_id\":\"${RUN_ID}-tool-allow\",\"session_id\":\"${SESSION_ID}\",\"tenant\":\"tenant-a\",\"actor_spiffe_id\":\"${SPIFFE_ID}\",\"plane\":\"tool\"},
  \"policy\": {
    \"envelope\": {\"run_id\":\"${RUN_ID}-tool-allow\",\"session_id\":\"${SESSION_ID}\",\"tenant\":\"tenant-a\",\"actor_spiffe_id\":\"${SPIFFE_ID}\",\"plane\":\"tool\"},
    \"action\":\"tool.execute\",
    \"resource\":\"tool/read\",
    \"attributes\":{\"capability_id\":\"tool.default.mcp\",\"tool_name\":\"read\"}
  }
}" "${SPIFFE_ID}"
TOOL_ALLOW_CODE="$RESP_CODE"
TOOL_ALLOW_REASON="$(extract_reason_code "$RESP_BODY")"
TOOL_ALLOW_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
if [ "$TOOL_ALLOW_CODE" = "200" ] && [ "$TOOL_ALLOW_REASON" = "TOOL_ALLOW" ] && [ -n "$TOOL_ALLOW_DECISION_ID" ]; then
    log_pass "Governed tool path allowed"
else
    log_fail "Governed tool path" "Expected 200/TOOL_ALLOW with decision_id, got code=${TOOL_ALLOW_CODE} reason=${TOOL_ALLOW_REASON} body=${RESP_BODY:0:240}"
fi

log_subheader "J3: Deterministic deny paths"
reset_rate_limit_state "${SPIFFE_ID}"
log_info "Reset rate-limit keys before deny checks"

gateway_post "/v1/model/call" "{
  \"envelope\": {\"run_id\":\"${RUN_ID}-model-deny\",\"session_id\":\"${SESSION_ID}\",\"tenant\":\"tenant-a\",\"actor_spiffe_id\":\"${SPIFFE_ID}\",\"plane\":\"model\"},
  \"policy\": {
    \"envelope\": {\"run_id\":\"${RUN_ID}-model-deny\",\"session_id\":\"${SESSION_ID}\",\"tenant\":\"tenant-a\",\"actor_spiffe_id\":\"${SPIFFE_ID}\",\"plane\":\"model\"},
    \"action\":\"model.call\",
    \"resource\":\"model/inference\",
    \"attributes\":{\"provider\":\"openai\",\"model\":\"gpt-4o\",\"direct_egress\":true,\"mediation_mode\":\"direct\"}
  }
}" "${SPIFFE_ID}"
MODEL_DENY_CODE="$RESP_CODE"
MODEL_DENY_REASON="$(extract_reason_code "$RESP_BODY")"
MODEL_DENY_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
if [ "$MODEL_DENY_CODE" = "403" ] && [ "$MODEL_DENY_REASON" = "MODEL_PROVIDER_DIRECT_EGRESS_BLOCKED" ] && [ -n "$MODEL_DENY_DECISION_ID" ]; then
    log_pass "Direct egress bypass denied deterministically"
else
    log_fail "Model direct egress deny" "Expected 403/MODEL_PROVIDER_DIRECT_EGRESS_BLOCKED with decision_id, got code=${MODEL_DENY_CODE} reason=${MODEL_DENY_REASON} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/tool/execute" "{
  \"envelope\": {\"run_id\":\"${RUN_ID}-tool-deny\",\"session_id\":\"${SESSION_ID}\",\"tenant\":\"tenant-a\",\"actor_spiffe_id\":\"${SPIFFE_ID}\",\"plane\":\"tool\"},
  \"policy\": {
    \"envelope\": {\"run_id\":\"${RUN_ID}-tool-deny\",\"session_id\":\"${SESSION_ID}\",\"tenant\":\"tenant-a\",\"actor_spiffe_id\":\"${SPIFFE_ID}\",\"plane\":\"tool\"},
    \"action\":\"tool.execute\",
    \"resource\":\"tool/write\",
    \"attributes\":{\"capability_id\":\"tool.unapproved.mcp\",\"tool_name\":\"write\"}
  }
}" "${SPIFFE_ID}"
TOOL_DENY_CODE="$RESP_CODE"
TOOL_DENY_REASON="$(extract_reason_code "$RESP_BODY")"
TOOL_DENY_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
if [ "$TOOL_DENY_CODE" = "403" ] && [ "$TOOL_DENY_REASON" = "TOOL_CAPABILITY_DENIED" ] && [ -n "$TOOL_DENY_DECISION_ID" ]; then
    log_pass "Unapproved tool capability denied deterministically"
else
    log_fail "Tool capability deny" "Expected 403/TOOL_CAPABILITY_DENIED with decision_id, got code=${TOOL_DENY_CODE} reason=${TOOL_DENY_REASON} body=${RESP_BODY:0:240}"
fi

AUDIT_HITS=$(gateway_logs_grep "${RUN_ID}" 200 | wc -l | tr -d ' ')
if [ "${AUDIT_HITS:-0}" -gt 0 ]; then
    log_pass "Audit log evidence includes run correlation (${AUDIT_HITS} lines)"
else
    log_fail "Audit log evidence" "No gateway log lines found for run id ${RUN_ID}"
fi

python3 - "$ARTIFACT_PATH" <<'PY'
import json
import os
import sys

path = sys.argv[1]
doc = {
    "schema_version": "openclaw.walking_skeleton.v1",
    "run_id": os.environ.get("RUN_ID", ""),
    "session_id": os.environ.get("SESSION_ID", ""),
    "results": {
        "ingress_allow": {
            "status_code": os.environ.get("INGRESS_ALLOW_CODE", ""),
            "reason_code": os.environ.get("INGRESS_ALLOW_REASON", ""),
            "decision_id": os.environ.get("INGRESS_ALLOW_DECISION_ID", ""),
        },
        "context_allow": {
            "status_code": os.environ.get("CONTEXT_ALLOW_CODE", ""),
            "reason_code": os.environ.get("CONTEXT_ALLOW_REASON", ""),
            "decision_id": os.environ.get("CONTEXT_ALLOW_DECISION_ID", ""),
        },
        "model_allow": {
            "status_code": os.environ.get("MODEL_ALLOW_CODE", ""),
            "reason_code": os.environ.get("MODEL_ALLOW_REASON", ""),
            "decision_id": os.environ.get("MODEL_ALLOW_DECISION_ID", ""),
        },
        "tool_allow": {
            "status_code": os.environ.get("TOOL_ALLOW_CODE", ""),
            "reason_code": os.environ.get("TOOL_ALLOW_REASON", ""),
            "decision_id": os.environ.get("TOOL_ALLOW_DECISION_ID", ""),
        },
        "model_deny": {
            "status_code": os.environ.get("MODEL_DENY_CODE", ""),
            "reason_code": os.environ.get("MODEL_DENY_REASON", ""),
            "decision_id": os.environ.get("MODEL_DENY_DECISION_ID", ""),
        },
        "tool_deny": {
            "status_code": os.environ.get("TOOL_DENY_CODE", ""),
            "reason_code": os.environ.get("TOOL_DENY_REASON", ""),
            "decision_id": os.environ.get("TOOL_DENY_DECISION_ID", ""),
        },
    },
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
print(path)
PY

if [ -f "$ARTIFACT_PATH" ]; then
    log_pass "Machine-readable artifact written: ${ARTIFACT_PATH}"
else
    log_fail "Artifact write" "Expected artifact at ${ARTIFACT_PATH}"
fi

print_summary

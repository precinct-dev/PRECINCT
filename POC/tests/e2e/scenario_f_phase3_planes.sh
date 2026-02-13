#!/usr/bin/env bash
# Scenario F: Phase 3 Multi-Plane Compose Validation (RFA-owgw.9)
# Validates success and denied paths across ingress/context/model/tool/loop
# using Phase 3 control-plane endpoints.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

extract_reason_code() {
    local body="$1"
    printf "%s" "$body" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("reason_code",""))
except Exception:
    print("")'
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
    docker compose exec -T keydb keydb-cli DEL "$tokens_key" "$last_fill_key" >/dev/null 2>&1 || true
}

log_header "Scenario F: Phase 3 Multi-Plane Compose Validation"

if ! check_service_healthy "mcp-security-gateway"; then
    log_fail "Gateway not running" "Start with: make up"
    print_summary
    exit 1
fi
log_pass "Gateway is running and healthy"

RUN_ID="phase3-compose-$(date +%s)"
SESSION_ID="phase3-compose-session-${RUN_ID}"
SPIFFE_ID="${DEFAULT_SPIFFE_ID}"
NOW_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
CONNECTOR_SIG_EXPECTED="$(compute_connector_signature "compose-webhook" "webhook" "${SPIFFE_ID}" "1.0" '["ingress.submit"]')"

reset_rate_limit_state "${SPIFFE_ID}"
log_info "Reset prior rate-limit keys for ${SPIFFE_ID}"

log_subheader "F0: Connector conformance lifecycle (register -> validate -> approve -> activate)"

gateway_post "/v1/connectors/register" "{
  \"connector_id\": \"compose-webhook\",
  \"manifest\": {
    \"connector_id\": \"compose-webhook\",
    \"connector_type\": \"webhook\",
    \"source_principal\": \"${SPIFFE_ID}\",
    \"version\": \"1.0\",
    \"capabilities\": [\"ingress.submit\"],
    \"signature\": {
      \"algorithm\": \"sha256-manifest-v1\",
      \"value\": \"${CONNECTOR_SIG_EXPECTED}\"
    }
  }
}" "${SPIFFE_ID}"

if [ "$RESP_CODE" = "200" ]; then
    log_pass "Connector register endpoint accepted manifest"
else
    log_fail "Connector register endpoint" "Expected 200, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

CONNECTOR_SIG="$(extract_expected_signature "$RESP_BODY")"
if [ -n "$CONNECTOR_SIG" ]; then
    log_pass "Connector expected signature available from CCA record"
else
    log_fail "Connector expected signature extraction" "record.expected_signature missing"
fi

for op in validate approve activate; do
  gateway_post "/v1/connectors/${op}" "{
    \"connector_id\": \"compose-webhook\"
  }" "${SPIFFE_ID}"
  if [ "$RESP_CODE" = "200" ]; then
      log_pass "Connector ${op} succeeded"
  else
      log_fail "Connector ${op}" "Expected 200, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
  fi
done

log_subheader "F1: Success path across ingress -> context -> model -> tool"

gateway_post "/v1/ingress/admit" "{
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
      \"connector_type\": \"webhook\",
      \"connector_id\": \"compose-webhook\",
      \"connector_signature\": \"${CONNECTOR_SIG}\",
      \"source_id\": \"compose-webhook\",
      \"source_principal\": \"${SPIFFE_ID}\",
      \"event_id\": \"event-${RUN_ID}\",
      \"nonce\": \"nonce-${RUN_ID}\",
      \"event_timestamp\": \"${NOW_UTC}\",
      \"payload\": {\"message\":\"compose phase3 event\"},
      \"requires_step_up\": false
    }
  }
}" "${SPIFFE_ID}"

if [ "$RESP_CODE" = "200" ] && [ "$(extract_reason_code "$RESP_BODY")" = "INGRESS_ALLOW" ]; then
    log_pass "Ingress admitted with reason code INGRESS_ALLOW"
else
    log_fail "Ingress phase3 success path" "Expected 200/INGRESS_ALLOW, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/context/admit" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"context\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}\",
      \"session_id\": \"${SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${SPIFFE_ID}\",
      \"plane\": \"context\"
    },
    \"action\": \"context.admit\",
    \"resource\": \"context/segment\",
    \"attributes\": {
      \"segment_id\": \"segment-${RUN_ID}\",
      \"content\": \"safe contextual facts\",
      \"scan_passed\": true,
      \"prompt_check_passed\": true,
      \"prompt_injection_detected\": false,
      \"dlp_classification\": \"clean\",
      \"model_egress\": true,
      \"memory_operation\": \"none\",
      \"memory_tier\": \"session\",
      \"provenance\": {
        \"source\": \"ingress\",
        \"connector\": \"webhook\",
        \"checksum\": \"sha256:phase3\",
        \"received_at\": \"${NOW_UTC}\"
      }
    }
  }
}" "${SPIFFE_ID}"

if [ "$RESP_CODE" = "200" ] && [ "$(extract_reason_code "$RESP_BODY")" = "CONTEXT_ALLOW" ]; then
    log_pass "Context admitted with reason code CONTEXT_ALLOW"
else
    log_fail "Context phase3 success path" "Expected 200/CONTEXT_ALLOW, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/model/call" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"model\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}\",
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
      \"residency_intent\": \"us\",
      \"risk_mode\": \"low\"
    }
  }
}" "${SPIFFE_ID}"

if [ "$RESP_CODE" = "200" ] && [ "$(extract_reason_code "$RESP_BODY")" = "MODEL_ALLOW" ]; then
    log_pass "Model mediated with reason code MODEL_ALLOW"
else
    log_fail "Model phase3 success path" "Expected 200/MODEL_ALLOW, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/tool/execute" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"tool\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}\",
      \"session_id\": \"${SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${SPIFFE_ID}\",
      \"plane\": \"tool\"
    },
    \"action\": \"tool.execute\",
    \"resource\": \"tool/read\",
    \"attributes\": {
      \"protocol\": \"mcp\",
      \"capability_id\": \"tool.default.mcp\",
      \"tool_name\": \"read\"
    }
  }
}" "${SPIFFE_ID}"

if [ "$RESP_CODE" = "200" ] && [ "$(extract_reason_code "$RESP_BODY")" = "TOOL_ALLOW" ]; then
    log_pass "Tool plane allowed with reason code TOOL_ALLOW"
else
    log_fail "Tool phase3 success path" "Expected 200/TOOL_ALLOW, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

log_subheader "F2: Denied unsafe paths with explicit reason codes"

gateway_post "/v1/model/call" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-deny-model\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"model\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-deny-model\",
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
}" "${SPIFFE_ID}"

if [ "$RESP_CODE" = "403" ] && [ "$(extract_reason_code "$RESP_BODY")" = "PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED" ]; then
    log_pass "Unsafe regulated prompt denied with explicit reason code"
else
    log_fail "Model denied path reason code" "Expected 403/PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/loop/check" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-deny-loop\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"loop\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-deny-loop\",
      \"session_id\": \"${SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${SPIFFE_ID}\",
      \"plane\": \"loop\"
    },
    \"action\": \"loop.check\",
    \"resource\": \"loop/external-governor\",
    \"attributes\": {
      \"event\": \"boundary\",
      \"limits\": {
        \"max_steps\": 2,
        \"max_tool_calls\": 5,
        \"max_model_calls\": 5,
        \"max_wall_time_ms\": 60000,
        \"max_egress_bytes\": 100000,
        \"max_model_cost_usd\": 2.0,
        \"max_provider_failovers\": 2,
        \"max_risk_score\": 0.8
      },
      \"usage\": {
        \"steps\": 3,
        \"tool_calls\": 1,
        \"model_calls\": 1,
        \"wall_time_ms\": 1000,
        \"egress_bytes\": 100,
        \"model_cost_usd\": 0.1,
        \"provider_failovers\": 0,
        \"risk_score\": 0.2
      }
    }
  }
}" "${SPIFFE_ID}"

if [ "$RESP_CODE" = "429" ] && [ "$(extract_reason_code "$RESP_BODY")" = "LOOP_HALT_MAX_STEPS" ]; then
    log_pass "Loop limit overflow denied with explicit reason code"
else
    log_fail "Loop denied path reason code" "Expected 429/LOOP_HALT_MAX_STEPS, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

log_subheader "F3: Revoked connector denied at ingress runtime gate"
reset_rate_limit_state "${SPIFFE_ID}"
log_info "Reset rate-limit keys before revoke/deny checks"

gateway_post "/v1/connectors/revoke" "{
  \"connector_id\": \"compose-webhook\"
}" "${SPIFFE_ID}"

if [ "$RESP_CODE" = "200" ]; then
    log_pass "Connector revoke succeeded"
else
    log_fail "Connector revoke" "Expected 200, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/ingress/admit" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-revoke\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"ingress\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-revoke\",
      \"session_id\": \"${SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${SPIFFE_ID}\",
      \"plane\": \"ingress\"
    },
    \"action\": \"ingress.admit\",
    \"resource\": \"ingress/event\",
    \"attributes\": {
      \"connector_id\": \"compose-webhook\",
      \"connector_signature\": \"${CONNECTOR_SIG}\",
      \"source_id\": \"compose-webhook\",
      \"source_principal\": \"${SPIFFE_ID}\",
      \"event_id\": \"event-${RUN_ID}-revoke\",
      \"event_timestamp\": \"${NOW_UTC}\"
    }
  }
}" "${SPIFFE_ID}"

if [ "$RESP_CODE" = "403" ] && [ "$(extract_reason_code "$RESP_BODY")" = "INGRESS_SOURCE_UNAUTHENTICATED" ]; then
    log_pass "Revoked connector blocked at ingress runtime gate"
else
    log_fail "Revoked connector ingress deny" "Expected 403/INGRESS_SOURCE_UNAUTHENTICATED, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

log_subheader "F4: Conformance report artifact includes audit references"

REPORT_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "${GATEWAY_URL}/v1/connectors/report" -H "X-SPIFFE-ID: ${SPIFFE_ID}")
REPORT_CODE=$(echo "$REPORT_RESPONSE" | tail -n1)
REPORT_BODY=$(echo "$REPORT_RESPONSE" | sed '$d')

if [ "$REPORT_CODE" = "200" ]; then
    log_pass "Connector conformance report endpoint returned JSON artifact"
else
    log_fail "Connector conformance report endpoint" "Expected 200, got code=${REPORT_CODE} body=${REPORT_BODY:0:240}"
fi

CONNECTOR_DECISION_ID=$(printf "%s" "$REPORT_BODY" | python3 -c 'import json,sys
try:
    report = json.load(sys.stdin)
    for row in report.get("connectors", []):
        if row.get("connector_id") == "compose-webhook":
            print(row.get("last_decision_id", ""))
            break
    else:
        print("")
except Exception:
    print("")
')
if [ -n "$CONNECTOR_DECISION_ID" ]; then
    log_pass "Conformance report links connector to audit decision id"
else
    log_fail "Conformance report audit linkage" "compose-webhook last_decision_id missing"
fi

log_subheader "F5: Audit evidence for multi-plane decisions"
sleep 1

AUDIT_LINES=$(docker compose logs --no-log-prefix --tail 400 mcp-security-gateway 2>/dev/null | grep "${RUN_ID}" || true)
if [ -n "$AUDIT_LINES" ]; then
    log_pass "Audit contains events correlated to Phase 3 run id"
else
    log_fail "Audit correlation" "No audit lines found for run id ${RUN_ID}"
fi

for reason in INGRESS_ALLOW CONTEXT_ALLOW MODEL_ALLOW TOOL_ALLOW PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED LOOP_HALT_MAX_STEPS INGRESS_SOURCE_UNAUTHENTICATED; do
    if echo "$AUDIT_LINES" | grep -q "$reason"; then
        log_pass "Audit includes reason code ${reason}"
    else
        log_fail "Audit reason code ${reason}" "Reason code not found in correlated audit lines"
    fi
done

if [ -n "$CONNECTOR_DECISION_ID" ] && docker compose logs --no-log-prefix --tail 400 mcp-security-gateway 2>/dev/null | grep -q "${CONNECTOR_DECISION_ID}"; then
    log_pass "Audit log contains conformance report decision id"
else
    log_fail "Audit linkage for conformance report decision id" "decision id ${CONNECTOR_DECISION_ID:-<empty>} not found in gateway audit logs"
fi

print_summary

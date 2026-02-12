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

log_subheader "F3: Audit evidence for multi-plane decisions"
sleep 1

AUDIT_LINES=$(docker compose logs --no-log-prefix --tail 250 mcp-security-gateway 2>/dev/null | grep "${RUN_ID}" || true)
if [ -n "$AUDIT_LINES" ]; then
    log_pass "Audit contains events correlated to Phase 3 run id"
else
    log_fail "Audit correlation" "No audit lines found for run id ${RUN_ID}"
fi

for reason in INGRESS_ALLOW CONTEXT_ALLOW MODEL_ALLOW TOOL_ALLOW PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED LOOP_HALT_MAX_STEPS; do
    if echo "$AUDIT_LINES" | grep -q "$reason"; then
        log_pass "Audit includes reason code ${reason}"
    else
        log_fail "Audit reason code ${reason}" "Reason code not found in correlated audit lines"
    fi
done

print_summary

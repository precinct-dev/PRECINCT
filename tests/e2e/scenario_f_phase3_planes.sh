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

extract_envelope_field() {
    local body="$1"
    local key="$2"
    printf "%s" "$body" | python3 -c 'import json,sys
key = sys.argv[1]
try:
    obj = json.load(sys.stdin)
    env = obj.get("envelope", {})
    val = env.get(key, "")
    if isinstance(val, (dict, list)):
        print(json.dumps(val, sort_keys=True))
    else:
        print(val)
except Exception:
    print("")
' "$key"
}

extract_profile_field() {
    local body="$1"
    local key="$2"
    printf "%s" "$body" | python3 -c 'import json,sys
key = sys.argv[1]
try:
    obj = json.load(sys.stdin)
    profile = obj.get("profile", {})
    val = profile.get(key, "")
    if isinstance(val, (dict, list)):
        print(json.dumps(val, sort_keys=True))
    else:
        print(val)
except Exception:
    print("")
' "$key"
}

assert_plane_correlation() {
    local label="$1"
    local body="$2"
    local expected_session="$3"
    local decision_id trace_id session_id

    decision_id="$(extract_json_field "$body" "decision_id")"
    trace_id="$(extract_json_field "$body" "trace_id")"
    session_id="$(extract_envelope_field "$body" "session_id")"

    if [ -n "$decision_id" ] && [ -n "$trace_id" ] && [ "$session_id" = "$expected_session" ]; then
        log_pass "${label}: correlation fields present and session linked"
    else
        log_fail "${label}: correlation fields present and session linked" "decision_id=${decision_id:-<empty>} trace_id=${trace_id:-<empty>} envelope.session_id=${session_id:-<empty>} expected=${expected_session}"
    fi
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

log_header "Scenario F: Phase 3 Multi-Plane Compose Validation"

if ! check_service_healthy "precinct-gateway"; then
    log_fail "Gateway not running" "Start with: make up"
    print_summary
    exit 1
fi
log_pass "Gateway is running and healthy"

RUN_ID="phase3-compose-$(date +%s)"
SESSION_ID="phase3-compose-session-${RUN_ID}"
SPIFFE_ID="${DEFAULT_SPIFFE_ID}"
NOW_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
STALE_UTC="$(python3 - <<'PY'
from datetime import datetime, timedelta, timezone
print((datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"
CONNECTOR_SIG_EXPECTED="$(compute_connector_signature "compose-webhook" "webhook" "${SPIFFE_ID}" "1.0" '["ingress.submit"]')"
ARTIFACT_DIR="${POC_DIR}/tests/e2e/artifacts"
ARTIFACT_PATH="${ARTIFACT_DIR}/scenario_f_${RUN_ID}.json"
mkdir -p "${ARTIFACT_DIR}"

reset_rate_limit_state "${SPIFFE_ID}"
log_info "Reset prior rate-limit keys for ${SPIFFE_ID}"

log_subheader "F0: Enforcement profile status and mediation/HIPAA gates"

gateway_get "/admin/profiles/status" "${SPIFFE_ID}"
PROFILE_STATUS_CODE="$RESP_CODE"
ACTIVE_PROFILE="$(extract_profile_field "$RESP_BODY" "name")"
PROFILE_MEDIATION_GATE="$(extract_profile_field "$RESP_BODY" "controls" | python3 -c 'import json,sys
try:
    controls = json.loads(sys.stdin.read() or "{}")
    print(str(bool(controls.get("enforce_model_mediation_gate", False))).lower())
except Exception:
    print("false")
')"
PROFILE_HIPAA_GATE="$(extract_profile_field "$RESP_BODY" "controls" | python3 -c 'import json,sys
try:
    controls = json.loads(sys.stdin.read() or "{}")
    print(str(bool(controls.get("enforce_hipaa_prompt_safety_gate", False))).lower())
except Exception:
    print("false")
')"

if [ "$PROFILE_STATUS_CODE" = "200" ] && [ -n "$ACTIVE_PROFILE" ]; then
    log_pass "Profile status endpoint returned machine-readable profile metadata (${ACTIVE_PROFILE})"
else
    log_fail "Profile status endpoint" "Expected 200 with profile metadata, got code=${PROFILE_STATUS_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/model/call" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-mediation-deny\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"model\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-mediation-deny\",
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
      \"direct_egress\": true,
      \"mediation_mode\": \"direct\"
    }
  }
}" "${SPIFFE_ID}"
PROFILE_MEDIATION_DENY_CODE="$RESP_CODE"
PROFILE_MEDIATION_DENY_REASON="$(extract_reason_code "$RESP_BODY")"
if [ "$PROFILE_MEDIATION_DENY_CODE" = "403" ] && [ "$PROFILE_MEDIATION_DENY_REASON" = "MODEL_PROVIDER_DIRECT_EGRESS_BLOCKED" ]; then
    log_pass "Profile mediation gate denied direct model egress"
else
    log_fail "Profile mediation gate" "Expected 403/MODEL_PROVIDER_DIRECT_EGRESS_BLOCKED, got code=${PROFILE_MEDIATION_DENY_CODE} reason=${PROFILE_MEDIATION_DENY_REASON} body=${RESP_BODY:0:240}"
fi

if [ "$PROFILE_HIPAA_GATE" = "true" ]; then
    gateway_post "/v1/model/call" "{
      \"envelope\": {
        \"run_id\": \"${RUN_ID}-hipaa-allow\",
        \"session_id\": \"${SESSION_ID}\",
        \"tenant\": \"tenant-a\",
        \"actor_spiffe_id\": \"${SPIFFE_ID}\",
        \"plane\": \"model\"
      },
      \"policy\": {
        \"envelope\": {
          \"run_id\": \"${RUN_ID}-hipaa-allow\",
          \"session_id\": \"${SESSION_ID}\",
          \"tenant\": \"tenant-a\",
          \"actor_spiffe_id\": \"${SPIFFE_ID}\",
          \"plane\": \"model\"
        },
        \"action\": \"model.call\",
        \"resource\": \"model/inference\",
        \"attributes\": {
          \"compliance_profile\": \"hipaa\",
          \"provider\": \"openai\",
          \"model\": \"gpt-4o\",
          \"prompt\": \"Summarize this non-sensitive wellness note.\"
        }
      }
    }" "${SPIFFE_ID}"
    if [ "$RESP_CODE" = "200" ] && [ "$(extract_reason_code "$RESP_BODY")" = "MODEL_ALLOW" ]; then
        log_pass "HIPAA profile allows safe mediated prompt"
    else
        log_fail "HIPAA safe prompt allow" "Expected 200/MODEL_ALLOW, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
    fi

    gateway_post "/v1/model/call" "{
      \"envelope\": {
        \"run_id\": \"${RUN_ID}-hipaa-deny\",
        \"session_id\": \"${SESSION_ID}\",
        \"tenant\": \"tenant-a\",
        \"actor_spiffe_id\": \"${SPIFFE_ID}\",
        \"plane\": \"model\"
      },
      \"policy\": {
        \"envelope\": {
          \"run_id\": \"${RUN_ID}-hipaa-deny\",
          \"session_id\": \"${SESSION_ID}\",
          \"tenant\": \"tenant-a\",
          \"actor_spiffe_id\": \"${SPIFFE_ID}\",
          \"plane\": \"model\"
        },
        \"action\": \"model.call\",
        \"resource\": \"model/inference\",
        \"attributes\": {
          \"compliance_profile\": \"hipaa\",
          \"provider\": \"openai\",
          \"model\": \"gpt-4o\",
          \"prompt_has_phi\": true,
          \"prompt\": \"Patient chart includes SSN 123-45-6789.\"
        }
      }
    }" "${SPIFFE_ID}"
    if [ "$RESP_CODE" = "403" ] && [ "$(extract_reason_code "$RESP_BODY")" = "PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED" ]; then
        log_pass "HIPAA profile prompt safety gate denied regulated content"
    else
        log_fail "HIPAA prompt safety gate" "Expected 403/PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
    fi
else
    log_skip "HIPAA prompt safety checks" "HIPAA prompt safety gate is disabled for active profile ${ACTIVE_PROFILE}"
fi

log_subheader "F0.5: Connector conformance lifecycle (register -> validate -> approve -> activate)"

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

gateway_post "/v1/ingress/submit" "{
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

INGRESS_ALLOW_CODE="$RESP_CODE"
INGRESS_ALLOW_REASON="$(extract_reason_code "$RESP_BODY")"
INGRESS_ALLOW_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
INGRESS_ALLOW_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Ingress allow" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "200" ] && [ "$INGRESS_ALLOW_REASON" = "INGRESS_ALLOW" ]; then
    log_pass "Ingress admitted with reason code INGRESS_ALLOW"
else
    log_fail "Ingress phase3 success path" "Expected 200/INGRESS_ALLOW, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

log_subheader "F1.1: Ingress replay/freshness checks on canonical /submit path"

gateway_post "/v1/ingress/submit" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-replay-primer\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"ingress\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-replay-primer\",
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
      \"event_id\": \"event-${RUN_ID}-replay\",
      \"event_timestamp\": \"${NOW_UTC}\"
    }
  }
}" "${SPIFFE_ID}"

if [ "$RESP_CODE" = "200" ] && [ "$(extract_reason_code "$RESP_BODY")" = "INGRESS_ALLOW" ]; then
    log_pass "Ingress replay primer accepted on canonical /submit"
else
    log_fail "Ingress replay primer" "Expected 200/INGRESS_ALLOW, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/ingress/submit" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-replay-deny\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"ingress\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-replay-deny\",
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
      \"event_id\": \"event-${RUN_ID}-replay\",
      \"event_timestamp\": \"${NOW_UTC}\"
    }
  }
}" "${SPIFFE_ID}"

INGRESS_REPLAY_CODE="$RESP_CODE"
INGRESS_REPLAY_REASON="$(extract_reason_code "$RESP_BODY")"
INGRESS_REPLAY_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
INGRESS_REPLAY_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Ingress replay deny" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "409" ] && [ "$INGRESS_REPLAY_REASON" = "INGRESS_REPLAY_DETECTED" ]; then
    log_pass "Ingress replay denied with deterministic reason code"
else
    log_fail "Ingress replay denied path" "Expected 409/INGRESS_REPLAY_DETECTED, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/ingress/submit" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-stale-deny\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"ingress\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-stale-deny\",
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
      \"event_id\": \"event-${RUN_ID}-stale\",
      \"event_timestamp\": \"${STALE_UTC}\"
    }
  }
}" "${SPIFFE_ID}"

INGRESS_STALE_CODE="$RESP_CODE"
INGRESS_STALE_REASON="$(extract_reason_code "$RESP_BODY")"
INGRESS_STALE_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
INGRESS_STALE_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Ingress stale deny" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "403" ] && [ "$INGRESS_STALE_REASON" = "INGRESS_FRESHNESS_STALE" ]; then
    log_pass "Ingress stale event denied with deterministic reason code"
else
    log_fail "Ingress stale denied path" "Expected 403/INGRESS_FRESHNESS_STALE, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

reset_rate_limit_state "${SPIFFE_ID}"
log_info "Reset rate-limit keys after ingress replay/freshness checks"

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
        \"received_at\": \"${NOW_UTC}\",
        \"verified\": true,
        \"verifier\": \"sigstore\",
        \"verification_method\": \"sha256+sigstore\"
      }
    }
  }
}" "${SPIFFE_ID}"

CONTEXT_ALLOW_CODE="$RESP_CODE"
CONTEXT_ALLOW_REASON="$(extract_reason_code "$RESP_BODY")"
CONTEXT_ALLOW_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
CONTEXT_ALLOW_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Context allow" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "200" ] && [ "$CONTEXT_ALLOW_REASON" = "CONTEXT_ALLOW" ]; then
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

MODEL_ALLOW_CODE="$RESP_CODE"
MODEL_ALLOW_REASON="$(extract_reason_code "$RESP_BODY")"
MODEL_ALLOW_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
MODEL_ALLOW_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Model allow" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "200" ] && [ "$MODEL_ALLOW_REASON" = "MODEL_ALLOW" ]; then
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

TOOL_ALLOW_CODE="$RESP_CODE"
TOOL_ALLOW_REASON="$(extract_reason_code "$RESP_BODY")"
TOOL_ALLOW_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
TOOL_ALLOW_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Tool allow" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "200" ] && [ "$TOOL_ALLOW_REASON" = "TOOL_ALLOW" ]; then
    log_pass "Tool plane allowed with reason code TOOL_ALLOW"
else
    log_fail "Tool phase3 success path" "Expected 200/TOOL_ALLOW, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/loop/check" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-allow-loop\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"loop\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-allow-loop\",
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
        \"max_steps\": 20,
        \"max_tool_calls\": 50,
        \"max_model_calls\": 50,
        \"max_wall_time_ms\": 600000,
        \"max_egress_bytes\": 1000000,
        \"max_model_cost_usd\": 10.0,
        \"max_provider_failovers\": 2,
        \"max_risk_score\": 0.9
      },
      \"usage\": {
        \"steps\": 3,
        \"tool_calls\": 1,
        \"model_calls\": 1,
        \"wall_time_ms\": 1500,
        \"egress_bytes\": 100,
        \"model_cost_usd\": 0.1,
        \"provider_failovers\": 0,
        \"risk_score\": 0.2
      }
    }
  }
}" "${SPIFFE_ID}"

LOOP_ALLOW_CODE="$RESP_CODE"
LOOP_ALLOW_REASON="$(extract_reason_code "$RESP_BODY")"
LOOP_ALLOW_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
LOOP_ALLOW_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Loop allow" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "200" ] && [ "$LOOP_ALLOW_REASON" = "LOOP_ALLOW" ]; then
    log_pass "Loop boundary admitted with reason code LOOP_ALLOW"
else
    log_fail "Loop allow path reason code" "Expected 200/LOOP_ALLOW, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

log_subheader "F2: Denied unsafe paths with explicit reason codes"
reset_rate_limit_state "${SPIFFE_ID}"
log_info "Reset rate-limit keys before denied-path checks"

gateway_post "/v1/context/admit" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-deny-context\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"context\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-deny-context\",
      \"session_id\": \"${SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${SPIFFE_ID}\",
      \"plane\": \"context\"
    },
    \"action\": \"context.admit\",
    \"resource\": \"context/segment\",
    \"attributes\": {
      \"segment_id\": \"segment-${RUN_ID}-deny\",
      \"content\": \"potentially unsafe context\",
      \"scan_passed\": false,
      \"prompt_check_passed\": false,
      \"prompt_injection_detected\": true
    }
  }
}" "${SPIFFE_ID}"

CONTEXT_DENY_CODE="$RESP_CODE"
CONTEXT_DENY_REASON="$(extract_reason_code "$RESP_BODY")"
CONTEXT_DENY_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
CONTEXT_DENY_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Context deny" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "403" ] && [ "$CONTEXT_DENY_REASON" = "CONTEXT_NO_SCAN_NO_SEND" ]; then
    log_pass "Context unsafe path denied with explicit reason code"
else
    log_fail "Context denied path reason code" "Expected 403/CONTEXT_NO_SCAN_NO_SEND, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/context/admit" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-deny-context-no-provenance\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"context\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-deny-context-no-provenance\",
      \"session_id\": \"${SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${SPIFFE_ID}\",
      \"plane\": \"context\"
    },
    \"action\": \"context.admit\",
    \"resource\": \"context/segment\",
    \"attributes\": {
      \"scan_passed\": true,
      \"prompt_check_passed\": true,
      \"memory_operation\": \"write\"
    }
  }
}" "${SPIFFE_ID}"
if [ "$RESP_CODE" = "403" ] && [ "$(extract_reason_code "$RESP_BODY")" = "CONTEXT_MEMORY_WRITE_DENIED" ]; then
    log_pass "Context no-provenance-no-persist denied with explicit reason code"
else
    log_fail "Context no-provenance-no-persist" "Expected 403/CONTEXT_MEMORY_WRITE_DENIED, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/context/admit" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-deny-context-no-verification\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"context\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-deny-context-no-verification\",
      \"session_id\": \"${SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${SPIFFE_ID}\",
      \"plane\": \"context\"
    },
    \"action\": \"context.admit\",
    \"resource\": \"context/segment\",
    \"attributes\": {
      \"scan_passed\": true,
      \"prompt_check_passed\": true,
      \"model_egress\": true,
      \"dlp_classification\": \"clean\",
      \"provenance\": {
        \"source\": \"ingress\",
        \"checksum\": \"sha256:context\",
        \"verified\": false
      }
    }
  }
}" "${SPIFFE_ID}"
if [ "$RESP_CODE" = "403" ] && [ "$(extract_reason_code "$RESP_BODY")" = "CONTEXT_SCHEMA_INVALID" ]; then
    log_pass "Context no-verification-no-load denied with explicit reason code"
else
    log_fail "Context no-verification-no-load" "Expected 403/CONTEXT_SCHEMA_INVALID, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/context/admit" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-deny-context-min-necessary\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"context\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-deny-context-min-necessary\",
      \"session_id\": \"${SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${SPIFFE_ID}\",
      \"plane\": \"context\"
    },
    \"action\": \"context.admit\",
    \"resource\": \"context/segment\",
    \"attributes\": {
      \"scan_passed\": true,
      \"prompt_check_passed\": true,
      \"model_egress\": true,
      \"dlp_classification\": \"phi\",
      \"content\": \"Patient chart with SSN 123-45-6789\",
      \"provenance\": {
        \"source\": \"ingress\",
        \"checksum\": \"sha256:context\",
        \"verified\": true,
        \"verifier\": \"sigstore\",
        \"verification_method\": \"sha256+sigstore\"
      }
    }
  }
}" "${SPIFFE_ID}"
if [ "$RESP_CODE" = "403" ] && [ "$(extract_reason_code "$RESP_BODY")" = "CONTEXT_DLP_CLASSIFICATION_DENIED" ]; then
    log_pass "Context minimum-necessary deny path enforced for sensitive model-bound context"
else
    log_fail "Context minimum-necessary deny path" "Expected 403/CONTEXT_DLP_CLASSIFICATION_DENIED, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/context/admit" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-allow-context-tokenize\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"context\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-allow-context-tokenize\",
      \"session_id\": \"${SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${SPIFFE_ID}\",
      \"plane\": \"context\"
    },
    \"action\": \"context.admit\",
    \"resource\": \"context/segment\",
    \"attributes\": {
      \"scan_passed\": true,
      \"prompt_check_passed\": true,
      \"model_egress\": true,
      \"dlp_classification\": \"phi\",
      \"minimum_necessary_outcome\": \"tokenize\",
      \"content\": \"Tokenized patient summary\",
      \"provenance\": {
        \"source\": \"ingress\",
        \"checksum\": \"sha256:context\",
        \"verified\": true,
        \"verifier\": \"sigstore\",
        \"verification_method\": \"sha256+sigstore\"
      }
    }
  }
}" "${SPIFFE_ID}"
if [ "$RESP_CODE" = "200" ] && [ "$(extract_reason_code "$RESP_BODY")" = "CONTEXT_ALLOW" ]; then
    log_pass "Context minimum-necessary tokenize path allowed with canonical reason code"
else
    log_fail "Context minimum-necessary tokenize path" "Expected 200/CONTEXT_ALLOW, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

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

MODEL_DENY_CODE="$RESP_CODE"
MODEL_DENY_REASON="$(extract_reason_code "$RESP_BODY")"
MODEL_DENY_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
MODEL_DENY_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Model deny" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "403" ] && [ "$MODEL_DENY_REASON" = "PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED" ]; then
    log_pass "Unsafe regulated prompt denied with explicit reason code"
else
    log_fail "Model denied path reason code" "Expected 403/PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/tool/execute" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-deny-tool\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"tool\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-deny-tool\",
      \"session_id\": \"${SESSION_ID}\",
      \"tenant\": \"tenant-a\",
      \"actor_spiffe_id\": \"${SPIFFE_ID}\",
      \"plane\": \"tool\"
    },
    \"action\": \"tool.execute\",
    \"resource\": \"tool/write\",
    \"attributes\": {
      \"protocol\": \"mcp\",
      \"capability_id\": \"tool.unapproved.mcp\",
      \"tool_name\": \"write\"
    }
  }
}" "${SPIFFE_ID}"

TOOL_DENY_CODE="$RESP_CODE"
TOOL_DENY_REASON="$(extract_reason_code "$RESP_BODY")"
TOOL_DENY_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
TOOL_DENY_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Tool deny" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "403" ] && [ "$TOOL_DENY_REASON" = "TOOL_CAPABILITY_DENIED" ]; then
    log_pass "Tool capability denied with explicit reason code"
else
    log_fail "Tool denied path reason code" "Expected 403/TOOL_CAPABILITY_DENIED, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
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

LOOP_DENY_CODE="$RESP_CODE"
LOOP_DENY_REASON="$(extract_reason_code "$RESP_BODY")"
LOOP_DENY_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
LOOP_DENY_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Loop deny" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "429" ] && [ "$LOOP_DENY_REASON" = "LOOP_HALT_MAX_STEPS" ]; then
    log_pass "Loop limit overflow denied with explicit reason code"
else
    log_fail "Loop denied path reason code" "Expected 429/LOOP_HALT_MAX_STEPS, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/loop/check" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-deny-loop-tool-calls\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"loop\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-deny-loop-tool-calls\",
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
        \"max_steps\": 20,
        \"max_tool_calls\": 1,
        \"max_model_calls\": 20,
        \"max_wall_time_ms\": 600000,
        \"max_egress_bytes\": 1000000,
        \"max_model_cost_usd\": 10.0,
        \"max_provider_failovers\": 2,
        \"max_risk_score\": 0.9
      },
      \"usage\": {
        \"steps\": 2,
        \"tool_calls\": 2,
        \"model_calls\": 1,
        \"wall_time_ms\": 1200,
        \"egress_bytes\": 120,
        \"model_cost_usd\": 0.2,
        \"provider_failovers\": 0,
        \"risk_score\": 0.2
      }
    }
  }
}" "${SPIFFE_ID}"

LOOP_DENY_TOOLCALLS_CODE="$RESP_CODE"
LOOP_DENY_TOOLCALLS_REASON="$(extract_reason_code "$RESP_BODY")"
LOOP_DENY_TOOLCALLS_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
LOOP_DENY_TOOLCALLS_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Loop deny tool_calls" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "429" ] && [ "$LOOP_DENY_TOOLCALLS_REASON" = "LOOP_HALT_MAX_TOOL_CALLS" ]; then
    log_pass "Loop max_tool_calls overflow denied with explicit reason code"
else
    log_fail "Loop tool_calls denied path reason code" "Expected 429/LOOP_HALT_MAX_TOOL_CALLS, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/loop/check" "{
  \"envelope\": {
    \"run_id\": \"${RUN_ID}-deny-loop-risk\",
    \"session_id\": \"${SESSION_ID}\",
    \"tenant\": \"tenant-a\",
    \"actor_spiffe_id\": \"${SPIFFE_ID}\",
    \"plane\": \"loop\"
  },
  \"policy\": {
    \"envelope\": {
      \"run_id\": \"${RUN_ID}-deny-loop-risk\",
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
        \"max_steps\": 20,
        \"max_tool_calls\": 20,
        \"max_model_calls\": 20,
        \"max_wall_time_ms\": 600000,
        \"max_egress_bytes\": 1000000,
        \"max_model_cost_usd\": 10.0,
        \"max_provider_failovers\": 2,
        \"max_risk_score\": 0.5
      },
      \"usage\": {
        \"steps\": 2,
        \"tool_calls\": 1,
        \"model_calls\": 1,
        \"wall_time_ms\": 1200,
        \"egress_bytes\": 120,
        \"model_cost_usd\": 0.2,
        \"provider_failovers\": 0,
        \"risk_score\": 0.8
      }
    }
  }
}" "${SPIFFE_ID}"

LOOP_DENY_RISK_CODE="$RESP_CODE"
LOOP_DENY_RISK_REASON="$(extract_reason_code "$RESP_BODY")"
LOOP_DENY_RISK_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
LOOP_DENY_RISK_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Loop deny risk" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "403" ] && [ "$LOOP_DENY_RISK_REASON" = "LOOP_HALT_MAX_RISK_SCORE" ]; then
    log_pass "Loop max_risk_score overflow denied with explicit reason code"
else
    log_fail "Loop risk denied path reason code" "Expected 403/LOOP_HALT_MAX_RISK_SCORE, got code=${RESP_CODE} body=${RESP_BODY:0:240}"
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

INGRESS_DENY_CODE="$RESP_CODE"
INGRESS_DENY_REASON="$(extract_reason_code "$RESP_BODY")"
INGRESS_DENY_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
INGRESS_DENY_TRACE_ID="$(extract_json_field "$RESP_BODY" "trace_id")"
assert_plane_correlation "Ingress deny" "$RESP_BODY" "${SESSION_ID}"

if [ "$RESP_CODE" = "403" ] && [ "$INGRESS_DENY_REASON" = "INGRESS_SOURCE_UNAUTHENTICATED" ]; then
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

log_subheader "F4.5: Admin RuleOps endpoint correlation metadata"

RULEOPS_ACTIVE_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "${GATEWAY_URL}/admin/dlp/rulesets/active" -H "X-SPIFFE-ID: ${SPIFFE_ID}")
RULEOPS_ACTIVE_CODE=$(echo "$RULEOPS_ACTIVE_RESPONSE" | tail -n1)
RULEOPS_ACTIVE_BODY=$(echo "$RULEOPS_ACTIVE_RESPONSE" | sed '$d')
RULEOPS_ACTIVE_DECISION_ID="$(extract_json_field "$RULEOPS_ACTIVE_BODY" "decision_id")"
RULEOPS_ACTIVE_TRACE_ID="$(extract_json_field "$RULEOPS_ACTIVE_BODY" "trace_id")"

if [ "$RULEOPS_ACTIVE_CODE" = "200" ] && [ -n "$RULEOPS_ACTIVE_DECISION_ID" ] && [ -n "$RULEOPS_ACTIVE_TRACE_ID" ]; then
    log_pass "RuleOps active endpoint returns decision_id and trace_id"
else
    log_fail "RuleOps active endpoint correlation metadata" "Expected 200 and non-empty decision/trace IDs, got code=${RULEOPS_ACTIVE_CODE} body=${RULEOPS_ACTIVE_BODY:0:240}"
fi

log_subheader "F5: Audit evidence for multi-plane decisions"
sleep 1

AUDIT_LINES=$($DC logs --no-log-prefix --tail 400 precinct-gateway 2>/dev/null | grep "${RUN_ID}" || true)
if [ -n "$AUDIT_LINES" ]; then
    log_pass "Audit contains events correlated to Phase 3 run id"
else
    log_fail "Audit correlation" "No audit lines found for run id ${RUN_ID}"
fi

for reason in INGRESS_ALLOW INGRESS_REPLAY_DETECTED INGRESS_FRESHNESS_STALE INGRESS_SOURCE_UNAUTHENTICATED CONTEXT_ALLOW CONTEXT_NO_SCAN_NO_SEND CONTEXT_MEMORY_WRITE_DENIED CONTEXT_SCHEMA_INVALID CONTEXT_DLP_CLASSIFICATION_DENIED MODEL_ALLOW PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED TOOL_ALLOW TOOL_CAPABILITY_DENIED LOOP_ALLOW LOOP_HALT_MAX_STEPS LOOP_HALT_MAX_TOOL_CALLS LOOP_HALT_MAX_RISK_SCORE; do
    if echo "$AUDIT_LINES" | grep -q "$reason"; then
        log_pass "Audit includes reason code ${reason}"
    else
        log_fail "Audit reason code ${reason}" "Reason code not found in correlated audit lines"
    fi
done

if [ -n "$CONNECTOR_DECISION_ID" ] && $DC logs --no-log-prefix --tail 400 precinct-gateway 2>/dev/null | grep -q "${CONNECTOR_DECISION_ID}"; then
    log_pass "Audit log contains conformance report decision id"
else
    log_fail "Audit linkage for conformance report decision id" "decision id ${CONNECTOR_DECISION_ID:-<empty>} not found in gateway audit logs"
fi

if [ -n "$RULEOPS_ACTIVE_DECISION_ID" ] && $DC logs --no-log-prefix --tail 400 precinct-gateway 2>/dev/null | grep -q "${RULEOPS_ACTIVE_DECISION_ID}"; then
    log_pass "Audit log contains RuleOps active decision id"
else
    log_fail "Audit linkage for RuleOps active decision id" "decision id ${RULEOPS_ACTIVE_DECISION_ID:-<empty>} not found in gateway audit logs"
fi

log_subheader "F6: Machine-readable artifact capture"

cat > "${ARTIFACT_PATH}" <<EOF
{
  "scenario": "scenario_f_phase3_planes",
  "run_id": "${RUN_ID}",
  "session_id": "${SESSION_ID}",
  "generated_at_utc": "${NOW_UTC}",
  "enforcement_profile": {
    "name": "${ACTIVE_PROFILE}",
    "mediation_gate": "${PROFILE_MEDIATION_GATE}",
    "hipaa_prompt_safety_gate": "${PROFILE_HIPAA_GATE}"
  },
  "decisions": [
    {"plane":"model","path":"profile_mediation_deny","status_code":${PROFILE_MEDIATION_DENY_CODE:-0},"reason_code":"${PROFILE_MEDIATION_DENY_REASON}","decision_id":"","trace_id":""},
    {"plane":"ingress","path":"allow","status_code":${INGRESS_ALLOW_CODE:-0},"reason_code":"${INGRESS_ALLOW_REASON}","decision_id":"${INGRESS_ALLOW_DECISION_ID}","trace_id":"${INGRESS_ALLOW_TRACE_ID}"},
    {"plane":"ingress","path":"replay_deny","status_code":${INGRESS_REPLAY_CODE:-0},"reason_code":"${INGRESS_REPLAY_REASON}","decision_id":"${INGRESS_REPLAY_DECISION_ID}","trace_id":"${INGRESS_REPLAY_TRACE_ID}"},
    {"plane":"ingress","path":"stale_deny","status_code":${INGRESS_STALE_CODE:-0},"reason_code":"${INGRESS_STALE_REASON}","decision_id":"${INGRESS_STALE_DECISION_ID}","trace_id":"${INGRESS_STALE_TRACE_ID}"},
    {"plane":"ingress","path":"deny","status_code":${INGRESS_DENY_CODE:-0},"reason_code":"${INGRESS_DENY_REASON}","decision_id":"${INGRESS_DENY_DECISION_ID}","trace_id":"${INGRESS_DENY_TRACE_ID}"},
    {"plane":"context","path":"allow","status_code":${CONTEXT_ALLOW_CODE:-0},"reason_code":"${CONTEXT_ALLOW_REASON}","decision_id":"${CONTEXT_ALLOW_DECISION_ID}","trace_id":"${CONTEXT_ALLOW_TRACE_ID}"},
    {"plane":"context","path":"deny","status_code":${CONTEXT_DENY_CODE:-0},"reason_code":"${CONTEXT_DENY_REASON}","decision_id":"${CONTEXT_DENY_DECISION_ID}","trace_id":"${CONTEXT_DENY_TRACE_ID}"},
    {"plane":"model","path":"allow","status_code":${MODEL_ALLOW_CODE:-0},"reason_code":"${MODEL_ALLOW_REASON}","decision_id":"${MODEL_ALLOW_DECISION_ID}","trace_id":"${MODEL_ALLOW_TRACE_ID}"},
    {"plane":"model","path":"deny","status_code":${MODEL_DENY_CODE:-0},"reason_code":"${MODEL_DENY_REASON}","decision_id":"${MODEL_DENY_DECISION_ID}","trace_id":"${MODEL_DENY_TRACE_ID}"},
    {"plane":"tool","path":"allow","status_code":${TOOL_ALLOW_CODE:-0},"reason_code":"${TOOL_ALLOW_REASON}","decision_id":"${TOOL_ALLOW_DECISION_ID}","trace_id":"${TOOL_ALLOW_TRACE_ID}"},
    {"plane":"tool","path":"deny","status_code":${TOOL_DENY_CODE:-0},"reason_code":"${TOOL_DENY_REASON}","decision_id":"${TOOL_DENY_DECISION_ID}","trace_id":"${TOOL_DENY_TRACE_ID}"},
    {"plane":"loop","path":"allow","status_code":${LOOP_ALLOW_CODE:-0},"reason_code":"${LOOP_ALLOW_REASON}","decision_id":"${LOOP_ALLOW_DECISION_ID}","trace_id":"${LOOP_ALLOW_TRACE_ID}"},
    {"plane":"loop","path":"deny","status_code":${LOOP_DENY_CODE:-0},"reason_code":"${LOOP_DENY_REASON}","decision_id":"${LOOP_DENY_DECISION_ID}","trace_id":"${LOOP_DENY_TRACE_ID}"},
    {"plane":"loop","path":"deny_tool_calls","status_code":${LOOP_DENY_TOOLCALLS_CODE:-0},"reason_code":"${LOOP_DENY_TOOLCALLS_REASON}","decision_id":"${LOOP_DENY_TOOLCALLS_DECISION_ID}","trace_id":"${LOOP_DENY_TOOLCALLS_TRACE_ID}"},
    {"plane":"loop","path":"deny_risk","status_code":${LOOP_DENY_RISK_CODE:-0},"reason_code":"${LOOP_DENY_RISK_REASON}","decision_id":"${LOOP_DENY_RISK_DECISION_ID}","trace_id":"${LOOP_DENY_RISK_TRACE_ID}"}
  ],
  "connector_conformance_report_decision_id": "${CONNECTOR_DECISION_ID}"
  ,"ruleops_active_decision_id": "${RULEOPS_ACTIVE_DECISION_ID}"
}
EOF

if [ -s "${ARTIFACT_PATH}" ]; then
    log_pass "Machine-readable artifact written to ${ARTIFACT_PATH}"
else
    log_fail "Machine-readable artifact capture" "artifact not written: ${ARTIFACT_PATH}"
fi

print_summary

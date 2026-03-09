#!/usr/bin/env bash
# Scenario K: Neuro-symbolic CSV ingestion hardening with provenance and admission checks

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

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
    print(val if not isinstance(val, (dict, list)) else "")
except Exception:
    print("")
' "$key"
}

log_header "Scenario K: Neuro-symbolic CSV ingestion hardening"

if ! check_service_healthy "mcp-security-gateway"; then
    log_fail "Gateway not running" "Start with: make up"
    print_summary
    exit 1
fi
log_pass "Gateway is running and healthy"

RUN_ID="neurosymbolic-csv-$(date +%s)"
SESSION_ID="neurosymbolic-csv-session-${RUN_ID}"
SPIFFE_ID="spiffe://poc.local/agents/mcp-client/dspy-reasoner/dev"
ARTIFACT_DIR="${POC_DIR}/tests/e2e/artifacts"
ARTIFACT_PATH="${ARTIFACT_DIR}/scenario_k_${RUN_ID}.json"
TMP_DIR="$(mktemp -d)"
mkdir -p "${ARTIFACT_DIR}"
trap 'rm -rf "${TMP_DIR}"' EXIT

SAFE_CSV="${TMP_DIR}/facts-safe.csv"
MALICIOUS_CSV="${TMP_DIR}/facts-malicious.csv"
SAFE_PAYLOAD="${TMP_DIR}/payload-safe.json"
MAL_PAYLOAD="${TMP_DIR}/payload-malicious.json"
TAMPER_PAYLOAD="${TMP_DIR}/payload-tampered.json"

cat > "${SAFE_CSV}" <<'CSV'
fact_id,subject,predicate,object,confidence
f1,bioactive-a,interacts,bioactive-b,0.92
f2,bioactive-c,inhibits,bioactive-d,0.86
CSV

cat > "${MALICIOUS_CSV}" <<'CSV'
fact_id,subject,predicate,object
f1,bioactive-a,interacts,=cmd|' /C calc'!A0
CSV

log_subheader "K1: Build context admission payloads from CSV uploads"

if (cd "${POC_DIR}" && go run ./cmd/neurocsv \
    --csv "${SAFE_CSV}" \
    --run-id "${RUN_ID}-allow" \
    --session-id "${SESSION_ID}" \
    --spiffe-id "${SPIFFE_ID}" \
    --source "upload://facts/safe.csv" > "${SAFE_PAYLOAD}"); then
    log_pass "Safe CSV payload generated"
else
    log_fail "Safe CSV payload generation" "go run ./cmd/neurocsv failed"
fi

if (cd "${POC_DIR}" && go run ./cmd/neurocsv \
    --csv "${MALICIOUS_CSV}" \
    --run-id "${RUN_ID}-deny-validation" \
    --session-id "${SESSION_ID}" \
    --spiffe-id "${SPIFFE_ID}" \
    --source "upload://facts/malicious.csv" > "${MAL_PAYLOAD}"); then
    log_pass "Malicious CSV payload generated"
else
    log_fail "Malicious CSV payload generation" "go run ./cmd/neurocsv failed"
fi

if (cd "${POC_DIR}" && go run ./cmd/neurocsv \
    --csv "${SAFE_CSV}" \
    --run-id "${RUN_ID}-deny-provenance" \
    --session-id "${SESSION_ID}" \
    --spiffe-id "${SPIFFE_ID}" \
    --source "upload://facts/tampered.csv" > "${TAMPER_PAYLOAD}"); then
    python3 - "${TAMPER_PAYLOAD}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as f:
    payload = json.load(f)
attrs = payload.get("policy", {}).get("attributes", {})
attrs["facts_hash"] = "sha256:deadbeef"
attrs["facts_hash_verified"] = True
prov = attrs.get("provenance", {})
prov["checksum"] = "sha256:feedface"
prov["verified"] = True
with open(path, 'w', encoding='utf-8') as f:
    json.dump(payload, f)
PY
    log_pass "Tampered provenance payload generated"
else
    log_fail "Tampered payload generation" "go run ./cmd/neurocsv failed"
fi

log_subheader "K2: Context admission outcomes (allow + deterministic deny)"

gateway_post "/v1/context/admit" "$(cat "${SAFE_PAYLOAD}")" "${SPIFFE_ID}"
ALLOW_CODE="$RESP_CODE"
ALLOW_REASON="$(extract_reason_code "$RESP_BODY")"
ALLOW_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
if [ "$ALLOW_CODE" = "200" ] && [ "$ALLOW_REASON" = "CONTEXT_ALLOW" ] && [ -n "$ALLOW_DECISION_ID" ]; then
    log_pass "Safe CSV admitted with canonical allow reason"
else
    log_fail "Safe CSV admission" "Expected 200/CONTEXT_ALLOW with decision_id, got code=${ALLOW_CODE} reason=${ALLOW_REASON} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/context/admit" "$(cat "${MAL_PAYLOAD}")" "${SPIFFE_ID}"
DENY_VALIDATION_CODE="$RESP_CODE"
DENY_VALIDATION_REASON="$(extract_reason_code "$RESP_BODY")"
DENY_VALIDATION_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
if [ "$DENY_VALIDATION_CODE" = "403" ] && [ "$DENY_VALIDATION_REASON" = "CONTEXT_FACTS_CSV_VALIDATION_FAILED" ] && [ -n "$DENY_VALIDATION_DECISION_ID" ]; then
    log_pass "Malicious CSV denied with canonical validation reason"
else
    log_fail "Malicious CSV deny" "Expected 403/CONTEXT_FACTS_CSV_VALIDATION_FAILED with decision_id, got code=${DENY_VALIDATION_CODE} reason=${DENY_VALIDATION_REASON} body=${RESP_BODY:0:240}"
fi

gateway_post "/v1/context/admit" "$(cat "${TAMPER_PAYLOAD}")" "${SPIFFE_ID}"
DENY_PROVENANCE_CODE="$RESP_CODE"
DENY_PROVENANCE_REASON="$(extract_reason_code "$RESP_BODY")"
DENY_PROVENANCE_DECISION_ID="$(extract_json_field "$RESP_BODY" "decision_id")"
if [ "$DENY_PROVENANCE_CODE" = "403" ] && [ "$DENY_PROVENANCE_REASON" = "CONTEXT_FACTS_PROVENANCE_INVALID" ] && [ -n "$DENY_PROVENANCE_DECISION_ID" ]; then
    log_pass "Tampered provenance denied with canonical reason"
else
    log_fail "Tampered provenance deny" "Expected 403/CONTEXT_FACTS_PROVENANCE_INVALID with decision_id, got code=${DENY_PROVENANCE_CODE} reason=${DENY_PROVENANCE_REASON} body=${RESP_BODY:0:240}"
fi

log_subheader "K3: Audit evidence"
AUDIT_HITS=$(gateway_logs_grep "${RUN_ID}" 240 | wc -l | tr -d ' ')
if [ "${AUDIT_HITS:-0}" -gt 0 ]; then
    log_pass "Audit logs contain run correlation evidence (${AUDIT_HITS} lines)"
else
    log_fail "Audit evidence" "No gateway log lines found for run id ${RUN_ID}"
fi

export RUN_ID SESSION_ID ALLOW_CODE ALLOW_REASON ALLOW_DECISION_ID
export DENY_VALIDATION_CODE DENY_VALIDATION_REASON DENY_VALIDATION_DECISION_ID
export DENY_PROVENANCE_CODE DENY_PROVENANCE_REASON DENY_PROVENANCE_DECISION_ID AUDIT_HITS
python3 - "${ARTIFACT_PATH}" <<'PY'
import json
import os
import sys

path = sys.argv[1]
report = {
    "schema_version": "neurosymbolic.csv_ingestion.v1",
    "run_id": os.environ.get("RUN_ID", ""),
    "session_id": os.environ.get("SESSION_ID", ""),
    "results": {
        "allow": {
            "status_code": os.environ.get("ALLOW_CODE", ""),
            "reason_code": os.environ.get("ALLOW_REASON", ""),
            "decision_id": os.environ.get("ALLOW_DECISION_ID", ""),
        },
        "deny_validation": {
            "status_code": os.environ.get("DENY_VALIDATION_CODE", ""),
            "reason_code": os.environ.get("DENY_VALIDATION_REASON", ""),
            "decision_id": os.environ.get("DENY_VALIDATION_DECISION_ID", ""),
        },
        "deny_provenance": {
            "status_code": os.environ.get("DENY_PROVENANCE_CODE", ""),
            "reason_code": os.environ.get("DENY_PROVENANCE_REASON", ""),
            "decision_id": os.environ.get("DENY_PROVENANCE_DECISION_ID", ""),
        },
    },
    "audit_log_hits": int(os.environ.get("AUDIT_HITS", "0") or 0),
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
print(path)
PY

if [ -f "${ARTIFACT_PATH}" ]; then
    log_pass "E2E artifact written: ${ARTIFACT_PATH}"
else
    log_fail "E2E artifact write" "Missing artifact at ${ARTIFACT_PATH}"
fi

print_summary

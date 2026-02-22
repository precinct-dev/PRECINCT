#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
TMP_DIR="$(mktemp -d)"

AGW_BIN="${AGW_BIN:-${ROOT_DIR}/build/bin/agw}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:9090}"
KEYDB_URL="${KEYDB_URL:-redis://127.0.0.1:6379}"
SPIFFE_ID="${SPIFFE_ID:-spiffe://poc.local/agents/mcp-client/dspy-researcher/dev}"
SESSION_ID="sid-agw-compliance-$(date +%s)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

log_header() {
  echo ""
  echo -e "${BOLD}=========================================${NC}"
  echo -e "${BOLD}  $1${NC}"
  echo -e "${BOLD}=========================================${NC}"
  echo ""
}

log_info() {
  echo -e "  [${CYAN}INFO${NC}] $1"
}

log_pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo -e "  [${GREEN}PASS${NC}] $1"
}

log_fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo -e "  [${RED}FAIL${NC}] $1"
  echo "         $2"
}

print_file() {
  local file="$1"
  local max_lines="${MAX_OUTPUT_LINES:-80}"
  local total_lines
  total_lines="$(wc -l <"$file" | tr -d ' ')"
  if [ "$total_lines" -le "$max_lines" ]; then
    sed 's/^/    /' "$file"
    return
  fi
  sed -n "1,${max_lines}p" "$file" | sed 's/^/    /'
  echo "    ... output truncated (${total_lines} lines total)"
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_fail "Required command check" "missing command: $cmd"
    exit 1
  fi
}

run_cmd() {
  local name="$1"
  shift
  local out_file="$TMP_DIR/${name}.out"
  local rc=0

  log_info "Command: $*"
  if "$@" >"$out_file" 2>&1; then
    :
  else
    rc=$?
  fi

  print_file "$out_file"

  if [ "$rc" -ne 0 ]; then
    log_fail "$name" "command failed with exit $rc"
    exit "$rc"
  fi

  log_pass "$name"
}

assert_json_expr() {
  local file="$1"
  local expr="$2"
  local label="$3"
  if python3 - "$file" "$expr" <<'PY'
import json
import sys

path = sys.argv[1]
expr = sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
scope = {"__builtins__": {}, "data": data, "len": len, "any": any, "all": all, "str": str}
ok = bool(eval(expr, scope, {}))
sys.exit(0 if ok else 1)
PY
  then
    log_pass "$label"
  else
    log_fail "$label" "json assertion failed: $expr"
    print_file "$file"
    exit 1
  fi
}

json_last_line_value() {
  local file="$1"
  python3 - "$file" <<'PY'
import sys

path = sys.argv[1]
value = ""
with open(path, "r", encoding="utf-8") as f:
    for raw in f:
        line = raw.strip()
        if line:
            value = line
print(value)
PY
}

redis_exec() {
  redis-cli -u "$KEYDB_URL" "$@"
}

print_final_summary() {
  local total
  total=$((PASS_COUNT + FAIL_COUNT))
  log_header "Results Summary"
  echo "  Total checks: $total"
  echo -e "  ${GREEN}PASS${NC}: $PASS_COUNT"
  echo -e "  ${RED}FAIL${NC}: $FAIL_COUNT"
  echo ""
  if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}test_agw_compliance.sh: FAIL${NC}"
    exit 1
  fi
  echo -e "${GREEN}test_agw_compliance.sh: PASS${NC}"
}

main() {
  log_header "E2E agw Compliance Validation"

  require_cmd docker
  require_cmd go
  require_cmd make
  require_cmd rg
  require_cmd python3
  require_cmd redis-cli
  require_cmd find

  if [ ! -x "$AGW_BIN" ]; then
    log_fail "agw binary check" "missing executable at $AGW_BIN (run: make compliance-demo)"
    exit 1
  fi
  log_pass "agw binary present"

  if ! curl -fsS "$GATEWAY_URL/health" >/dev/null 2>&1; then
    log_fail "gateway health" "gateway not reachable at ${GATEWAY_URL}/health"
    exit 1
  fi
  log_pass "gateway healthy"

  if ! redis_exec PING >/dev/null 2>&1; then
    log_fail "keydb health" "unable to reach keydb at ${KEYDB_URL}"
    exit 1
  fi
  log_pass "keydb reachable"

  log_header "1) Generate Audit Activity via E2E Demo"
  run_cmd "seed_audit_data" env AGW_BIN="$AGW_BIN" bash tests/e2e/test_agw_cli.sh

  log_header "2) Collect SOC2 Evidence Package"
  run_cmd "compliance_collect" "$AGW_BIN" compliance collect --framework soc2 --output-dir "$TMP_DIR/reports" --gateway-url "$GATEWAY_URL"
  EVIDENCE_DIR="$(json_last_line_value "$TMP_DIR/compliance_collect.out")"
  if [ -z "$EVIDENCE_DIR" ] || [ ! -d "$EVIDENCE_DIR" ]; then
    log_fail "compliance collect output dir" "expected evidence directory path in output, got: $EVIDENCE_DIR"
    exit 1
  fi
  log_pass "evidence directory created: $EVIDENCE_DIR"

  SOC2_DIR="${EVIDENCE_DIR}/soc2"
  SUMMARY_PATH="${SOC2_DIR}/evidence-summary.json"
  if [ ! -f "$SUMMARY_PATH" ]; then
    log_fail "evidence summary" "missing file: $SUMMARY_PATH"
    exit 1
  fi
  log_pass "evidence summary present"

  assert_json_expr "$SUMMARY_PATH" "data.get('framework') == 'soc2' and data.get('control_count', 0) > 0" "summary contains framework and control count"

  EXPECTED_SOC2_CONTROLS="$(awk '/^[[:space:]]+soc2:[[:space:]]*\[/{ if ($0 !~ /\[\]/) c++ } END { print c+0 }' tools/compliance/control_taxonomy.yaml)"
  ACTUAL_CONTROL_DIRS="$(find "$SOC2_DIR/controls" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
  if [ "$EXPECTED_SOC2_CONTROLS" != "$ACTUAL_CONTROL_DIRS" ]; then
    log_fail "taxonomy control coverage" "expected $EXPECTED_SOC2_CONTROLS SOC2 control dirs, found $ACTUAL_CONTROL_DIRS"
    exit 1
  fi
  log_pass "all SOC2 controls have evidence directories (${ACTUAL_CONTROL_DIRS})"

  log_header "3) Generate Compliance PDF Report"
  run_cmd "compliance_report_pdf" "$AGW_BIN" compliance report --framework soc2 --output pdf --output-dir "$TMP_DIR/reports"
  REPORT_PDF="$(json_last_line_value "$TMP_DIR/compliance_report_pdf.out")"
  if [ -z "$REPORT_PDF" ] || [ ! -f "$REPORT_PDF" ]; then
    log_fail "report pdf path" "expected generated pdf path, got: $REPORT_PDF"
    exit 1
  fi
  if [[ "$REPORT_PDF" != *.pdf ]]; then
    log_fail "report extension" "expected .pdf output, got: $REPORT_PDF"
    exit 1
  fi
  log_pass "pdf report generated: $REPORT_PDF"

  log_header "4) Export GDPR DSAR Package"
  run_cmd "gdpr_audit" "$AGW_BIN" gdpr audit "$SPIFFE_ID" --source docker --project-root "." --output-dir "$TMP_DIR/reports" --keydb-url "$KEYDB_URL" --format json
  assert_json_expr "$TMP_DIR/gdpr_audit.out" "all(data.get(k) for k in ['summary_path','audit_entries_path','session_data_path','rate_limit_data_path','identity_details_path','policy_grants_path'])" "gdpr audit output contains all package files"

  DSAR_DIR="$(python3 - "$TMP_DIR/gdpr_audit.out" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
print(data.get("package_dir", ""))
PY
)"
  if [ -z "$DSAR_DIR" ] || [ ! -d "$DSAR_DIR" ]; then
    log_fail "dsar package dir" "missing DSAR package directory: $DSAR_DIR"
    exit 1
  fi
  log_pass "DSAR package created: $DSAR_DIR"

  log_header "5) Right-to-Erasure + Deletion Verification"
  seeded_session_key="session:${SPIFFE_ID}:${SESSION_ID}"
  tokens_key="ratelimit:${SPIFFE_ID}:tokens"
  last_fill_key="ratelimit:${SPIFFE_ID}:last_fill"
  redis_exec SET "$seeded_session_key" '{"RiskScore":0.21}' EX 240 >/dev/null
  redis_exec RPUSH "${seeded_session_key}:actions" '{"Tool":"seed"}' >/dev/null
  redis_exec SET "$tokens_key" "7.0" EX 240 >/dev/null
  redis_exec SET "$last_fill_key" "$(date +%s%N)" EX 240 >/dev/null
  log_pass "seeded deterministic subject data before gdpr delete"

  run_cmd "gdpr_delete" "$AGW_BIN" gdpr delete "$SPIFFE_ID" --confirm --source docker --project-root "." --output-dir "$TMP_DIR/reports" --keydb-url "$KEYDB_URL" --format json
  assert_json_expr "$TMP_DIR/gdpr_delete.out" "len(str(data.get('deletion_certificate', ''))) == 64 and data.get('total_items_processed', 0) >= 3" "gdpr delete produced deletion certificate and processed records"

  subject_session_count="$(redis_exec --scan --pattern "session:${SPIFFE_ID}:*" | wc -l | tr -d ' ')"
  if [ "$subject_session_count" != "0" ]; then
    log_fail "session deletion verification" "expected zero session keys for subject, found $subject_session_count"
    exit 1
  fi
  log_pass "subject session keys removed from KeyDB"

  if [ "$(redis_exec EXISTS "$tokens_key")" != "0" ] || [ "$(redis_exec EXISTS "$last_fill_key")" != "0" ]; then
    log_fail "rate-limit deletion verification" "expected subject ratelimit keys deleted"
    exit 1
  fi
  log_pass "subject rate-limit keys removed from KeyDB"

  log_header "6) Stakeholder Summary"
  log_info "Claim: SOC2 evidence collection is complete for all taxonomy controls."
  log_info "Evidence: collected ${ACTUAL_CONTROL_DIRS}/${EXPECTED_SOC2_CONTROLS} SOC2 control directories in ${SOC2_DIR}."
  log_info "Claim: compliance reporting and GDPR operations are operational end-to-end."
  log_info "Evidence: PDF report path ${REPORT_PDF}, DSAR package ${DSAR_DIR}, GDPR deletion certificate emitted and KeyDB data removed."
  log_pass "stakeholder summary emitted"

  print_final_summary
}

main "$@"

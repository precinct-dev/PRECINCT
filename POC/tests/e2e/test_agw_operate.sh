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
KEYDB_URL="${KEYDB_URL:-redis://localhost:6379}"
SPIFFE_ID="${SPIFFE_ID:-spiffe://poc.local/agents/mcp-client/dspy-researcher/dev}"
TOOL_NAME="${TOOL_NAME:-tavily_search}"
SESSION_ID="sid-agw-operate-$(date +%s)"
RUNTIME_SESSION_ID="sid-agw-runtime-$(date +%s)"
DENIED_DECISION_ID=""

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

assert_contains_fixed() {
  local file="$1"
  local needle="$2"
  local label="$3"
  if rg -F -q "$needle" "$file"; then
    log_pass "$label"
  else
    log_fail "$label" "expected to find: $needle"
    print_file "$file"
    exit 1
  fi
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
ok = bool(eval(expr, {"__builtins__": {}}, {"data": data, "len": len, "any": any, "all": all}))
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

gateway_call() {
  local name="$1"
  local method="$2"
  local params_json="$3"
  local session_id="${4:-}"
  local body_file="$TMP_DIR/${name}.json"

  local headers=(
    -H "Content-Type: application/json"
    -H "X-Spiffe-Id: ${SPIFFE_ID}"
  )
  if [ -n "$session_id" ]; then
    headers+=(-H "X-Session-ID: ${session_id}")
  fi

  local response
  response="$(curl -sS -w '\n%{http_code}' -X POST "$GATEWAY_URL" "${headers[@]}" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params_json},\"id\":1}" || true)"

  GATEWAY_CODE="$(printf '%s\n' "$response" | tail -n1)"
  GATEWAY_BODY="$(printf '%s\n' "$response" | sed '$d')"
  printf '%s\n' "$GATEWAY_BODY" >"$body_file"

  log_info "Gateway call ${method} -> HTTP ${GATEWAY_CODE}"
  print_file "$body_file"
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
    echo -e "${RED}test_agw_operate.sh: FAIL${NC}"
    exit 1
  fi
  echo -e "${GREEN}test_agw_operate.sh: PASS${NC}"
}

main() {
  log_header "E2E agw Operate Validation"
  require_cmd docker
  require_cmd go
  require_cmd make
  require_cmd rg
  require_cmd python3
  require_cmd redis-cli

  if [ ! -x "$AGW_BIN" ]; then
    log_fail "agw binary check" "missing executable at $AGW_BIN (run: make agw-operate-demo)"
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

  log_header "1) Create Live Data (rate-limit/session/audit)"
  gateway_call "tools_list_bootstrap" "tools/list" "{}" "$SESSION_ID"
  if [ "$GATEWAY_CODE" -lt 200 ] || [ "$GATEWAY_CODE" -ge 500 ]; then
    log_fail "tools/list bootstrap" "expected HTTP 2xx-4xx, got $GATEWAY_CODE"
    exit 1
  fi
  log_pass "tools/list bootstrap request sent"

  gateway_call "allow_tavily" "$TOOL_NAME" '{"query":"agw operate demo seed"}' "$SESSION_ID"
  if [ "$GATEWAY_CODE" = "429" ]; then
    log_fail "allowed request seed" "unexpected 429 while seeding data"
    exit 1
  fi
  if [ "$GATEWAY_CODE" -ge 500 ] && [ "$GATEWAY_CODE" != "502" ] && [ "$GATEWAY_CODE" != "503" ]; then
    log_fail "allowed request seed" "unexpected HTTP status: $GATEWAY_CODE"
    exit 1
  fi
  log_pass "allowed request created rate-limit/session activity"

  gateway_call "deny_unknown_tool" "tool_does_not_exist_for_agw_operate_demo" '{"reason":"audit-seed"}' "$SESSION_ID"
  if [ "$GATEWAY_CODE" != "403" ]; then
    log_fail "denied request seed" "expected HTTP 403, got $GATEWAY_CODE"
    exit 1
  fi
  DENIED_DECISION_ID="$(python3 - "$TMP_DIR/deny_unknown_tool.json" <<'PY'
import json
import sys

try:
    data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
except Exception:
    print("")
    raise SystemExit(0)

decision_id = (data.get("error") or {}).get("decision_id", "")
if not decision_id:
    decision_id = data.get("decision_id", "")
print(decision_id)
PY
)"
  if [ -z "$DENIED_DECISION_ID" ]; then
    log_fail "decision id extraction" "denied response missing error.decision_id"
    exit 1
  fi
  log_pass "audit decision_id captured: $DENIED_DECISION_ID"

  log_header "2) Reset Rate-Limit and Verify Unblocked"
  tokens_key="ratelimit:${SPIFFE_ID}:tokens"
  last_fill_key="ratelimit:${SPIFFE_ID}:last_fill"
  now_nanos="$(date +%s%N)"
  redis_exec SET "$tokens_key" "0" EX 180 >/dev/null
  redis_exec SET "$last_fill_key" "$now_nanos" EX 180 >/dev/null
  log_pass "forced rate-limit counters to blocked state"

  gateway_call "rate_limited_before_reset" "$TOOL_NAME" '{"query":"agw rate limit before reset"}' "$SESSION_ID"
  if [ "$GATEWAY_CODE" != "429" ]; then
    log_fail "rate-limit blocked precondition" "expected HTTP 429 before reset, got $GATEWAY_CODE"
    exit 1
  fi
  log_pass "confirmed rate-limit blocking before reset"

  run_cmd "reset_rate_limit" "$AGW_BIN" reset rate-limit "$SPIFFE_ID" --confirm --keydb-url "$KEYDB_URL"
  assert_contains_fixed "$TMP_DIR/reset_rate_limit.out" "Deleted" "rate-limit reset output includes deleted key count"

  gateway_call "rate_limit_after_reset" "$TOOL_NAME" '{"query":"agw rate limit after reset"}' "$SESSION_ID"
  if [ "$GATEWAY_CODE" = "429" ]; then
    log_fail "rate-limit post-reset verification" "still blocked with HTTP 429 after reset"
    exit 1
  fi
  log_pass "rate-limit reset verified (request unblocked)"

  log_header "3) Reset Session and Verify Cleared"
  seeded_session_key="session:${SPIFFE_ID}:${SESSION_ID}"
  redis_exec SET "$seeded_session_key" '{"RiskScore":0.42}' EX 180 >/dev/null
  redis_exec RPUSH "${seeded_session_key}:actions" '{"Tool":"seed"}' >/dev/null
  log_pass "seeded deterministic session for reset verification"

  run_cmd "inspect_sessions_before" "$AGW_BIN" inspect sessions "$SPIFFE_ID" --keydb-url "$KEYDB_URL" --format json
  assert_json_expr "$TMP_DIR/inspect_sessions_before.out" "any(s.get('session_id') == '${SESSION_ID}' for s in data.get('sessions', []))" "session exists before reset"

  run_cmd "reset_session" "$AGW_BIN" reset session "$SPIFFE_ID" --confirm --keydb-url "$KEYDB_URL" --format json
  assert_json_expr "$TMP_DIR/reset_session.out" "data.get('deleted', 0) >= 1" "session reset deleted at least one key"

  run_cmd "inspect_sessions_after" "$AGW_BIN" inspect sessions "$SPIFFE_ID" --keydb-url "$KEYDB_URL" --format json
  assert_json_expr "$TMP_DIR/inspect_sessions_after.out" "all(s.get('session_id') != '${SESSION_ID}' for s in data.get('sessions', []))" "session removed after reset"

  log_header "4) Reset Circuit Breaker and Verify Closed"
  run_cmd "reset_circuit_breaker" "$AGW_BIN" reset circuit-breaker "$TOOL_NAME" --confirm --gateway-url "$GATEWAY_URL" --format json
  assert_json_expr "$TMP_DIR/reset_circuit_breaker.out" "len(data.get('reset', [])) >= 1 and data['reset'][0].get('tool') == '${TOOL_NAME}' and data['reset'][0].get('new_state') == 'closed'" "circuit-breaker reset reports closed state"

  run_cmd "inspect_circuit_breaker" "$AGW_BIN" inspect circuit-breaker "$TOOL_NAME" --gateway-url "$GATEWAY_URL" --format json
  assert_json_expr "$TMP_DIR/inspect_circuit_breaker.out" "len(data.get('circuit_breakers', [])) == 1 and data['circuit_breakers'][0].get('state') == 'closed'" "circuit-breaker state is closed after reset"

  log_header "5) Offline Policy Dry-Run (Allowed + Denied)"
  run_cmd "policy_test_offline_allowed" "$AGW_BIN" policy test "$SPIFFE_ID" "$TOOL_NAME" --params '{"query":"offline-allowed"}' --format json
  assert_json_expr "$TMP_DIR/policy_test_offline_allowed.out" "data.get('verdict') == 'ALLOWED' and len(data.get('layers', [])) == 6" "offline allowed dry-run returns 6 layers and ALLOWED"

  run_cmd "policy_test_offline_denied" "$AGW_BIN" policy test "$SPIFFE_ID" "tool_does_not_exist_for_policy_demo" --format json
  assert_json_expr "$TMP_DIR/policy_test_offline_denied.out" "data.get('verdict') == 'DENIED' and data.get('blocking_layer') == 4" "offline denied dry-run blocks at layer 4"

  log_header "6) Runtime Policy Dry-Run (13 Layers)"
  runtime_session_key="session:${SPIFFE_ID}:${RUNTIME_SESSION_ID}"
  redis_exec SET "$runtime_session_key" '{"RiskScore":0.15}' EX 180 >/dev/null
  redis_exec SET "$tokens_key" "55.0" EX 180 >/dev/null
  redis_exec SET "$last_fill_key" "$now_nanos" EX 180 >/dev/null
  log_pass "seeded runtime session and ratelimit state"

  run_cmd "policy_test_runtime" "$AGW_BIN" policy test "$SPIFFE_ID" "$TOOL_NAME" --runtime --session-id "$RUNTIME_SESSION_ID" --gateway-url "$GATEWAY_URL" --keydb-url "$KEYDB_URL" --params '{"query":"runtime-full"}' --format json
  assert_json_expr "$TMP_DIR/policy_test_runtime.out" "data.get('mode') == 'full' and data.get('verdict') == 'ALLOWED' and len(data.get('layers', [])) == 13" "runtime dry-run returns full 13-layer ALLOWED result"

  log_header "7) Policy List"
  run_cmd "policy_list" "$AGW_BIN" policy list --format json
  assert_json_expr "$TMP_DIR/policy_list.out" "len(data.get('grants', [])) >= 1" "policy list returned grants"

  log_header "8) Policy Reload"
  run_cmd "policy_reload" "$AGW_BIN" policy reload --confirm --gateway-url "$GATEWAY_URL" --format json
  assert_json_expr "$TMP_DIR/policy_reload.out" "data.get('status') == 'reloaded'" "policy reload succeeded"

  log_header "9) Identity List"
  run_cmd "identity_list" "$AGW_BIN" identity list --format json
  assert_json_expr "$TMP_DIR/identity_list.out" "len(data.get('entries', [])) >= 1" "identity list returned SPIRE entries"

  log_header "10) Secret List"
  run_cmd "secret_list" "$AGW_BIN" secret list --format json
  assert_json_expr "$TMP_DIR/secret_list.out" "len(data.get('secrets', [])) >= 1" "secret list returned SPIKE references"

  log_header "11) Stakeholder Summary"
  log_info "Claim: mutate-and-diagnose commands are operational against live stack."
  log_info "Evidence: reset rate-limit/session/circuit-breaker all executed with live verification."
  log_info "Claim: policy simulation is correct in offline and runtime modes."
  log_info "Evidence: offline ALLOWED+DENIED checks passed; runtime full mode returned 13 layers and ALLOWED."
  log_info "Claim: operational inventory endpoints are available for policy/identity/secret state."
  log_info "Evidence: policy list, policy reload, identity list, and secret list all passed."
  log_info "Audit linkage: denied decision_id=${DENIED_DECISION_ID}"
  log_pass "stakeholder summary emitted"

  print_final_summary
}

main "$@"

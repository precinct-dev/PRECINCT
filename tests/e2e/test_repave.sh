#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"
COMPOSE_FILE="${ROOT_DIR}/deploy/compose/docker-compose.yml"
DC="docker compose -f ${COMPOSE_FILE}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
TMP_DIR="$(mktemp -d)"
KEYDB_PROXY_CONTAINER=""
KEYDB_PROXY_PORT=""

PRECINCT_BIN="${PRECINCT_BIN:-${ROOT_DIR}/build/bin/precinct}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:9090}"
KEYDB_URL="${KEYDB_URL:-redis://127.0.0.1:6379}"
SPIFFE_ID="${SPIFFE_ID:-spiffe://poc.local/agents/mcp-client/dspy-researcher/dev}"
SESSION_ID="sid-repave-demo-$(date +%s)"

cleanup() {
  if [ -n "$KEYDB_PROXY_CONTAINER" ]; then
    docker rm -f "$KEYDB_PROXY_CONTAINER" >/dev/null 2>&1 || true
  fi
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
  local max_lines="${MAX_OUTPUT_LINES:-120}"
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

start_keydb_proxy() {
  local keydb_network
  local container_name
  container_name="agw-keydb-proxy-$$"
  keydb_network="$(docker inspect keydb --format '{{range $k, $_ := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | awk '{print $1}')"
  if [ -z "$keydb_network" ]; then
    log_fail "keydb proxy setup" "unable to discover KeyDB container network"
    exit 1
  fi

  docker rm -f "$container_name" >/dev/null 2>&1 || true
  for port in 16379 26379 36379 46379; do
    if docker run -d --rm \
      --name "$container_name" \
      -p "${port}:6379" \
      alpine/socat \
      TCP-LISTEN:6379,fork,reuseaddr TCP:keydb:6379 >/dev/null 2>&1; then
      if ! docker network connect "$keydb_network" "$container_name" >/dev/null 2>&1; then
        docker rm -f "$container_name" >/dev/null 2>&1 || true
        continue
      fi
      KEYDB_PROXY_CONTAINER="$container_name"
      KEYDB_PROXY_PORT="$port"
      KEYDB_URL="redis://127.0.0.1:${port}"
      for _ in $(seq 1 20); do
        if redis-cli -u "$KEYDB_URL" PING >/dev/null 2>&1; then
          log_info "KeyDB proxy active at ${KEYDB_URL} via ${KEYDB_PROXY_CONTAINER}"
          return 0
        fi
        sleep 0.5
      done
      docker rm -f "$KEYDB_PROXY_CONTAINER" >/dev/null 2>&1 || true
      KEYDB_PROXY_CONTAINER=""
      KEYDB_PROXY_PORT=""
    fi
  done

  log_fail "keydb proxy setup" "unable to start reachable KeyDB proxy container"
  exit 1
}

ensure_keydb_access() {
  if redis-cli -u "$KEYDB_URL" PING >/dev/null 2>&1; then
    log_info "Using host KeyDB endpoint ${KEYDB_URL}"
    return 0
  fi
  log_info "Host KeyDB endpoint ${KEYDB_URL} unreachable; using docker sidecar proxy"
  start_keydb_proxy
}

redis_exec() {
  redis-cli -u "$KEYDB_URL" "$@" | tr -d '\r'
}

gateway_call() {
  local name="$1"
  local method="$2"
  local params_json="$3"
  local body_file="$TMP_DIR/${name}.json"

  local response
  response="$(curl -sS -w '\n%{http_code}' -X POST "$GATEWAY_URL" \
    -H "Content-Type: application/json" \
    -H "X-Spiffe-Id: ${SPIFFE_ID}" \
    -H "X-Session-ID: ${SESSION_ID}" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params_json},\"id\":1}" || true)"

  GATEWAY_CODE="$(printf '%s\n' "$response" | tail -n1)"
  GATEWAY_BODY="$(printf '%s\n' "$response" | sed '$d')"
  printf '%s\n' "$GATEWAY_BODY" >"$body_file"

  log_info "Gateway call ${method} -> HTTP ${GATEWAY_CODE}"
  print_file "$body_file"
}

latest_spire_serial() {
  $DC exec -T spire-server /opt/spire/bin/spire-server agent list -output json \
    | jq -r '.agents | sort_by(.x509svid_expires_at|tonumber) | last | .x509svid_serial_number'
}

latest_report_file() {
  ls -1t reports/repave-*.md 2>/dev/null | head -n1 || true
}

assert_all_main_services_healthy() {
  local services
  services="spire-server spire-agent keydb spike-keeper-1 spike-nexus mock-mcp-server mock-guard-model mcp-security-gateway"
  local ps_out
  ps_out="$($DC ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null || true)"
  local s line state health
  for s in $services; do
    line="$(printf '%s\n' "$ps_out" | awk -v svc="$s" '$1==svc {print}')"
    state="$(printf '%s\n' "$line" | awk '{print $2}')"
    health="$(printf '%s\n' "$line" | awk '{print $3}')"
    if [ -z "$line" ] || [ "$state" != "running" ] || { [ -n "$health" ] && [ "$health" != "healthy" ]; }; then
      log_fail "compose health check" "service ${s} not healthy (state=${state} health=${health})"
      return 1
    fi
  done

  if ! curl -fsS "${GATEWAY_URL}/health" >/dev/null 2>&1; then
    log_fail "gateway health check" "gateway not reachable at ${GATEWAY_URL}/health"
    return 1
  fi
  if ! curl -fsS "http://localhost:6006/" >/dev/null 2>&1; then
    log_fail "phoenix health check" "phoenix not reachable at http://localhost:6006/"
    return 1
  fi
  if ! docker run --rm --network phoenix-observability-network curlimages/curl:8.5.0 -fsS "http://otel-collector:13133/" >/dev/null 2>&1; then
    log_fail "otel health check" "otel collector not reachable on :13133"
    return 1
  fi
  log_pass "all repave services healthy"
}

print_summary() {
  local total
  total=$((PASS_COUNT + FAIL_COUNT))
  log_header "Results Summary"
  echo "  Total checks: $total"
  echo -e "  ${GREEN}PASS${NC}: $PASS_COUNT"
  echo -e "  ${RED}FAIL${NC}: $FAIL_COUNT"
  echo ""
  if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}test_repave.sh: FAIL${NC}"
    exit 1
  fi
  echo -e "${GREEN}test_repave.sh: PASS${NC}"
}

main() {
  log_header "Epic 5 Repave E2E Validation"
  require_cmd docker
  require_cmd make
  require_cmd go
  require_cmd jq
  require_cmd curl
  require_cmd redis-cli
  require_cmd rg

  if [ ! -x "$PRECINCT_BIN" ]; then
    log_fail "precinct binary check" "missing executable at $PRECINCT_BIN"
    exit 1
  fi
  log_pass "precinct binary present"

  log_header "1) Start Full Stack"
  run_cmd "make_up" make up

  ensure_keydb_access
  if ! redis_exec PING | rg -x "PONG" >/dev/null; then
    log_fail "keydb readiness" "unable to reach KeyDB at ${KEYDB_URL}"
    exit 1
  fi
  log_pass "keydb reachable"

  if ! curl -fsS "${GATEWAY_URL}/health" >/dev/null 2>&1; then
    log_fail "gateway readiness" "gateway not reachable at ${GATEWAY_URL}/health"
    exit 1
  fi
  log_pass "gateway healthy"

  log_header "2) Generate Test Data"
  gateway_call "tools_list" "tools/list" "{}"
  if [ "$GATEWAY_CODE" -lt 200 ] || [ "$GATEWAY_CODE" -ge 500 ]; then
    log_fail "tools/list seed request" "unexpected status ${GATEWAY_CODE}"
    exit 1
  fi
  log_pass "tools/list request completed"

  gateway_call "seed_call" "tavily_search" '{"query":"repave demo seed"}'
  if [ "$GATEWAY_CODE" -eq "429" ] || [ "$GATEWAY_CODE" -ge 500 ]; then
    log_fail "tavily seed request" "unexpected status ${GATEWAY_CODE}"
    exit 1
  fi
  log_pass "seed traffic request completed"

  local session_key tokens_key last_fill_key tokens_before session_before
  local now_nanos
  session_key="session:${SPIFFE_ID}:${SESSION_ID}"
  tokens_key="ratelimit:${SPIFFE_ID}:tokens"
  last_fill_key="ratelimit:${SPIFFE_ID}:last_fill"
  now_nanos="$(date +%s%N)"

  redis_exec SET "$session_key" '{"RiskScore":0.42,"source":"repave-demo"}' EX 900 >/dev/null
  redis_exec RPUSH "${session_key}:actions" '{"Tool":"tavily_search"}' >/dev/null
  redis_exec SET "$tokens_key" "7.75" EX 900 >/dev/null
  redis_exec SET "$last_fill_key" "$now_nanos" EX 900 >/dev/null
  log_pass "deterministic session/rate-limit keys seeded"

  session_before="$(redis_exec GET "$session_key")"
  tokens_before="$(redis_exec GET "$tokens_key")"
  if [ -z "$session_before" ] || [ -z "$tokens_before" ]; then
    log_fail "pre-repave snapshot" "missing seeded KeyDB values before repave"
    exit 1
  fi
  log_pass "pre-repave KeyDB snapshot captured"

  run_cmd "compose_hash_snapshot" $DC ps --format json
  local spire_serial_before
  spire_serial_before="$(latest_spire_serial)"
  if [ -z "$spire_serial_before" ] || [ "$spire_serial_before" = "null" ]; then
    log_fail "spire snapshot" "could not capture pre-repave SPIRE agent serial"
    exit 1
  fi
  log_pass "pre-repave SPIRE serial captured (${spire_serial_before})"

  log_header "3) Single Repave (KeyDB)"
  run_cmd "repave_keydb" make repave COMPONENT=keydb

  if ! redis_exec PING | rg -x "PONG" >/dev/null; then
    log_fail "keydb health after single repave" "redis ping failed"
    exit 1
  fi
  if [ "$(redis_exec GET "$session_key")" != "$session_before" ]; then
    log_fail "session preservation after single repave" "session value changed after keydb repave"
    exit 1
  fi
  if [ "$(redis_exec GET "$tokens_key")" != "$tokens_before" ]; then
    log_fail "ratelimit preservation after single repave" "rate-limit value changed after keydb repave"
    exit 1
  fi
  if ! jq -e '.last_repave.keydb.timestamp != "" and .last_repave.keydb.health == "healthy"' .repave-state.json >/dev/null; then
    log_fail "single-repave state update" ".repave-state.json missing keydb healthy timestamp"
    exit 1
  fi
  log_pass "single KeyDB repave preserved data and updated state"

  log_header "4) Repave Status (KeyDB)"
  run_cmd "agw_repave_status_keydb" "$PRECINCT_BIN" repave status --format json
  if ! jq -e '.containers[] | select(.name=="keydb") | (.last_repave != "NEVER" and (.health=="healthy" or .health=="running"))' "$TMP_DIR/agw_repave_status_keydb.out" >/dev/null; then
    log_fail "precinct repave status keydb" "expected keydb last_repave and healthy status"
    exit 1
  fi
  log_pass "precinct repave status reports keydb repave"

  log_header "5) Full Stack Repave"
  run_cmd "repave_all" make repave
  assert_all_main_services_healthy || exit 1

  local spire_serial_after
  spire_serial_after="$(latest_spire_serial)"
  if [ -z "$spire_serial_after" ] || [ "$spire_serial_after" = "null" ]; then
    log_fail "spire snapshot after repave" "could not capture post-repave SPIRE serial"
    exit 1
  fi
  if [ "$spire_serial_after" = "$spire_serial_before" ]; then
    log_fail "spire re-issue check" "SPIRE serial did not change across full repave"
    exit 1
  fi
  log_pass "SPIRE identity re-issued across SPIRE repave (${spire_serial_before} -> ${spire_serial_after})"

  log_header "6) Repave Status (All Containers)"
  run_cmd "agw_repave_status_all" "$PRECINCT_BIN" repave status --format json
  if ! jq -e '.containers | length >= 9' "$TMP_DIR/agw_repave_status_all.out" >/dev/null; then
    log_fail "precinct repave status all" "expected at least 9 containers in status output"
    exit 1
  fi
  local expected
  expected="spire-server spire-agent keydb spike-keeper-1 spike-nexus mcp-security-gateway mock-mcp-server otel-collector phoenix"
  local svc
  for svc in $expected; do
    if ! jq -e --arg s "$svc" '.containers[] | select(.name==$s) | (.last_repave != "NEVER")' "$TMP_DIR/agw_repave_status_all.out" >/dev/null; then
      log_fail "precinct status container ${svc}" "missing repave timestamp for ${svc}"
      exit 1
    fi
  done
  log_pass "precinct repave status shows timestamps for all expected containers"

  log_header "7) Report + Data Preservation Checks"
  local report_file
  report_file="$(latest_report_file)"
  if [ -z "$report_file" ] || [ ! -f "$report_file" ]; then
    log_fail "repave report check" "missing reports/repave-<timestamp>.md"
    exit 1
  fi
  if ! rg -F "| Container | Image Hash Before | Image Hash After | Health | Duration |" "$report_file" >/dev/null; then
    log_fail "repave report format" "report missing expected table header"
    exit 1
  fi
  log_pass "repave report generated (${report_file})"

  if [ "$(redis_exec GET "$session_key")" != "$session_before" ]; then
    log_fail "session preservation after full repave" "session value changed after full repave"
    exit 1
  fi
  if [ "$(redis_exec GET "$tokens_key")" != "$tokens_before" ]; then
    log_fail "ratelimit preservation after full repave" "rate-limit value changed after full repave"
    exit 1
  fi
  log_pass "KeyDB session and rate-limit data preserved through full repave"

  log_header "8) End-to-End Demo Suite"
  run_cmd "demo_compose_after_repave" make demo-compose
  log_pass "make demo-compose passed after full repave"

  print_summary
}

main "$@"

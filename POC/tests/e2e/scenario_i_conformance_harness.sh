#!/usr/bin/env bash
# Scenario I: Conformance Harness (contracts, connectors, ruleops, profiles)
# Generates a machine-readable report artifact using the fixture-driven harness.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

log_header "Scenario I: Conformance Harness"

if ! check_service_healthy "mcp-security-gateway"; then
    log_fail "Gateway not running" "Start with: make up"
    print_summary
    exit 1
fi
log_pass "Gateway is running"

reset_rate_limit_state() {
    local spiffe_id="$1"
    local tokens_key="ratelimit:${spiffe_id}:tokens"
    local last_fill_key="ratelimit:${spiffe_id}:last_fill"
    docker compose exec -T keydb keydb-cli DEL "$tokens_key" "$last_fill_key" >/dev/null 2>&1 || true
}

REPORT_PATH="${POC_DIR}/tests/e2e/artifacts/conformance-report.json"
HARNESS_SPIFFE_ID="${SECONDARY_SPIFFE_ID}"

reset_rate_limit_state "${HARNESS_SPIFFE_ID}"
log_info "Reset rate-limit keys for harness SPIFFE: ${HARNESS_SPIFFE_ID}"

log_subheader "I1: Run conformance harness in live mode"
if (
    cd "${POC_DIR}" && \
    go run ./tests/conformance/cmd/harness \
      --live \
      --gateway-url "${GATEWAY_URL}" \
      --spiffe-id "${HARNESS_SPIFFE_ID}" \
      --output "${REPORT_PATH}"
); then
    log_pass "Conformance harness completed"
else
    log_fail "Conformance harness execution" "Harness command returned non-zero"
    print_summary
    exit 1
fi

if [ -f "${REPORT_PATH}" ]; then
    log_pass "Conformance report artifact generated"
    log_detail "${REPORT_PATH}"
else
    log_fail "Conformance report artifact" "Expected report at ${REPORT_PATH}"
fi

log_subheader "I2: Validate report schema markers and suite outcomes"
VALIDATION_OUTPUT=$(python3 - "${REPORT_PATH}" <<'PY'
import json,sys
path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as fh:
    data = json.load(fh)

required_suites = {"contracts", "connectors", "ruleops", "profiles"}
seen = {row.get("suite") for row in data.get("suites", [])}
missing = sorted(required_suites - seen)

if data.get("schema_version") != "conformance.report.v1":
    print("schema_version_mismatch")
    raise SystemExit(1)
if missing:
    print("missing_suites:" + ",".join(missing))
    raise SystemExit(1)
summary = data.get("summary", {})
if summary.get("suite_fail", 0) != 0 or summary.get("check_fail", 0) != 0:
    print("summary_failures_detected")
    raise SystemExit(1)
print("ok")
PY
) || true

if [ "${VALIDATION_OUTPUT}" = "ok" ]; then
    log_pass "Conformance report contains required schema version and passing suite/check summary"
else
    log_fail "Conformance report validation" "Validation output: ${VALIDATION_OUTPUT:-<empty>}"
fi

print_summary

#!/usr/bin/env bash
set -euo pipefail

STRICT_MODE=0
AUDIT_FILE=""
TRACE_FILE=""

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

warn() {
  echo "[WARN] $1" >&2
}

usage() {
  cat <<'EOF'
Usage: validate_observability_gate.sh [--strict] --audit-file <path> --trace-file <path>
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict)
      STRICT_MODE=1
      shift
      ;;
    --audit-file)
      AUDIT_FILE="${2:-}"
      shift 2
      ;;
    --trace-file)
      TRACE_FILE="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "${AUDIT_FILE}" ]] || fail "--audit-file is required"
[[ -n "${TRACE_FILE}" ]] || fail "--trace-file is required"

sink_available=1
if ! docker network inspect phoenix-observability-network >/dev/null 2>&1; then
  sink_available=0
fi
if ! docker ps --filter name=phoenix --filter status=running --format '{{.Names}}' 2>/dev/null | grep -q '^phoenix$'; then
  sink_available=0
fi
if ! docker ps --filter name=otel-collector --filter status=running --format '{{.Names}}' 2>/dev/null | grep -q '^otel-collector$'; then
  sink_available=0
fi

if [[ "${STRICT_MODE}" -eq 1 && "${sink_available}" -ne 1 ]]; then
  fail "required telemetry sinks unavailable (phoenix + otel-collector); strict observability gate denies campaign"
fi

if [[ "${STRICT_MODE}" -eq 1 ]]; then
  [[ -s "${AUDIT_FILE}" ]] || fail "audit evidence file missing or empty in strict mode: ${AUDIT_FILE}"
  [[ -s "${TRACE_FILE}" ]] || fail "trace evidence file missing or empty in strict mode: ${TRACE_FILE}"
  echo "[PASS] strict observability gate passed (sinks + audit/trace evidence present)"
  exit 0
fi

if [[ "${sink_available}" -ne 1 ]]; then
  warn "telemetry sinks unavailable; non-strict mode allows campaign to continue"
  exit 0
fi

if [[ ! -s "${AUDIT_FILE}" || ! -s "${TRACE_FILE}" ]]; then
  warn "telemetry sinks are up but audit/trace evidence files are incomplete; non-strict mode allows campaign to continue"
  exit 0
fi

echo "[PASS] non-strict observability gate passed"

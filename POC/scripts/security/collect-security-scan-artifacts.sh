#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
cd "${POC_DIR}"

OUTPUT_DIR="${SECURITY_SCAN_OUT_DIR:-build/security-scan/latest}"
STRICT_MODE="${SECURITY_SCAN_STRICT:-0}"
GATEWAY_SCAN_IMAGE="${GATEWAY_SCAN_IMAGE:-mcp-security-gateway:scan}"

RAW_DIR="${OUTPUT_DIR}/raw"
SUMMARY_DIR="${OUTPUT_DIR}/summaries"
MANIFEST_PATH="${OUTPUT_DIR}/security-scan-manifest.json"

mkdir -p "${RAW_DIR}" "${SUMMARY_DIR}"

timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

sha256_file() {
  local file="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print $1}'
  else
    sha256sum "${file}" | awk '{print $1}'
  fi
}

sarif_result_count() {
  local sarif_file="$1"
  if [ ! -s "${sarif_file}" ]; then
    echo 0
    return
  fi
  jq '[.runs[]?.results[]?] | length' "${sarif_file}" 2>/dev/null || echo 0
}

run_scan_command() {
  local command="$1"
  set +e
  bash -lc "${command}"
  local rc=$?
  set -e
  return ${rc}
}

emit_scan_summary() {
  local name="$1"
  local status="$2"
  local runner="$3"
  local command="$4"
  local message="$5"
  local sarif_path="$6"
  local json_path="$7"

  local result_count=0
  result_count="$(sarif_result_count "${sarif_path}")"

  jq -n \
    --arg name "${name}" \
    --arg status "${status}" \
    --arg runner "${runner}" \
    --arg command "${command}" \
    --arg message "${message}" \
    --arg generated_at "${timestamp}" \
    --arg sarif_path "${sarif_path}" \
    --arg json_path "${json_path}" \
    --argjson result_count "${result_count}" \
    '{
      scan: $name,
      status: $status,
      runner: $runner,
      command: $command,
      message: $message,
      generated_at: $generated_at,
      result_count: $result_count,
      artifacts: {
        sarif: $sarif_path,
        json: $json_path
      }
    }'
}

scan_gosec_status="skipped"
scan_gosec_runner="none"
scan_gosec_message="gosec unavailable"
scan_gosec_command=""
scan_gosec_sarif="${RAW_DIR}/gosec-results.sarif"

if command -v gosec >/dev/null 2>&1; then
  scan_gosec_runner="binary"
  scan_gosec_command="gosec -no-fail -fmt sarif -out '${scan_gosec_sarif}' ./..."
  if run_scan_command "${scan_gosec_command}"; then
    scan_gosec_status="pass"
    scan_gosec_message="gosec scan completed"
  else
    scan_gosec_status="failed"
    scan_gosec_message="gosec scan command failed"
  fi
elif command -v docker >/dev/null 2>&1; then
  scan_gosec_runner="docker"
  scan_gosec_command="docker run --rm -v '${POC_DIR}':/src -w /src securego/gosec:2.21.4 -no-fail -fmt sarif -out '/src/${scan_gosec_sarif}' ./..."
  if run_scan_command "${scan_gosec_command}"; then
    scan_gosec_status="pass"
    scan_gosec_message="gosec scan completed via container"
  else
    scan_gosec_status="failed"
    scan_gosec_message="gosec container scan failed"
  fi
fi

if [ "${scan_gosec_status}" = "pass" ] && [ ! -s "${scan_gosec_sarif}" ]; then
  scan_gosec_status="failed"
  scan_gosec_message="gosec scan did not produce sarif output"
fi

scan_trivy_fs_status="skipped"
scan_trivy_fs_runner="none"
scan_trivy_fs_message="trivy unavailable"
scan_trivy_fs_command=""
scan_trivy_fs_sarif="${RAW_DIR}/trivy-fs-results.sarif"
scan_trivy_fs_json="${RAW_DIR}/trivy-fs-results.json"

if command -v trivy >/dev/null 2>&1; then
  scan_trivy_fs_runner="binary"
  scan_trivy_fs_command="trivy fs --skip-dirs .beads --severity CRITICAL,HIGH,MEDIUM --exit-code 0 --format sarif --output '${scan_trivy_fs_sarif}' . && trivy fs --skip-dirs .beads --severity CRITICAL,HIGH,MEDIUM --exit-code 0 --format json --output '${scan_trivy_fs_json}' ."
  if run_scan_command "${scan_trivy_fs_command}"; then
    scan_trivy_fs_status="pass"
    scan_trivy_fs_message="trivy filesystem scan completed"
  else
    scan_trivy_fs_status="failed"
    scan_trivy_fs_message="trivy filesystem scan failed"
  fi
fi

if [ "${scan_trivy_fs_status}" = "pass" ] && { [ ! -s "${scan_trivy_fs_sarif}" ] || [ ! -s "${scan_trivy_fs_json}" ]; }; then
  scan_trivy_fs_status="failed"
  scan_trivy_fs_message="trivy filesystem scan did not produce required outputs"
fi

scan_trivy_image_status="skipped"
scan_trivy_image_runner="none"
scan_trivy_image_message="trivy and/or docker unavailable"
scan_trivy_image_command=""
scan_trivy_image_sarif="${RAW_DIR}/trivy-image-results.sarif"
scan_trivy_image_json="${RAW_DIR}/trivy-image-results.json"

if command -v trivy >/dev/null 2>&1 && command -v docker >/dev/null 2>&1; then
  scan_trivy_image_runner="binary"
  if ! docker image inspect "${GATEWAY_SCAN_IMAGE}" >/dev/null 2>&1; then
    echo "[INFO] building ${GATEWAY_SCAN_IMAGE} for image scan"
    docker build -f docker/Dockerfile.gateway -t "${GATEWAY_SCAN_IMAGE}" .
  fi
  scan_trivy_image_command="trivy image --severity CRITICAL,HIGH,MEDIUM --exit-code 0 --format sarif --output '${scan_trivy_image_sarif}' '${GATEWAY_SCAN_IMAGE}' && trivy image --severity CRITICAL,HIGH,MEDIUM --exit-code 0 --format json --output '${scan_trivy_image_json}' '${GATEWAY_SCAN_IMAGE}'"
  if run_scan_command "${scan_trivy_image_command}"; then
    scan_trivy_image_status="pass"
    scan_trivy_image_message="trivy image scan completed"
  else
    scan_trivy_image_status="failed"
    scan_trivy_image_message="trivy image scan failed"
  fi
fi

if [ "${scan_trivy_image_status}" = "pass" ] && { [ ! -s "${scan_trivy_image_sarif}" ] || [ ! -s "${scan_trivy_image_json}" ]; }; then
  scan_trivy_image_status="failed"
  scan_trivy_image_message="trivy image scan did not produce required outputs"
fi

emit_scan_summary "gosec" "${scan_gosec_status}" "${scan_gosec_runner}" "${scan_gosec_command}" "${scan_gosec_message}" "raw/gosec-results.sarif" "" > "${SUMMARY_DIR}/gosec-summary.json"
emit_scan_summary "trivy_fs" "${scan_trivy_fs_status}" "${scan_trivy_fs_runner}" "${scan_trivy_fs_command}" "${scan_trivy_fs_message}" "raw/trivy-fs-results.sarif" "raw/trivy-fs-results.json" > "${SUMMARY_DIR}/trivy-fs-summary.json"
emit_scan_summary "trivy_image" "${scan_trivy_image_status}" "${scan_trivy_image_runner}" "${scan_trivy_image_command}" "${scan_trivy_image_message}" "raw/trivy-image-results.sarif" "raw/trivy-image-results.json" > "${SUMMARY_DIR}/trivy-image-summary.json"

artifact_lines_file="${OUTPUT_DIR}/.artifact-lines.jsonl"
: > "${artifact_lines_file}"

while IFS= read -r rel; do
  [ -z "${rel}" ] && continue
  abs="${OUTPUT_DIR}/${rel}"
  if [ -s "${abs}" ]; then
    sha="$(sha256_file "${abs}")"
    size="$(wc -c < "${abs}" | tr -d ' ')"
    jq -n --arg path "${rel}" --arg sha256 "${sha}" --argjson size_bytes "${size}" '{path:$path,sha256:$sha256,size_bytes:$size_bytes}' >> "${artifact_lines_file}"
  fi
done <<'ARTIFACTS'
raw/gosec-results.sarif
raw/trivy-fs-results.sarif
raw/trivy-fs-results.json
raw/trivy-image-results.sarif
raw/trivy-image-results.json
summaries/gosec-summary.json
summaries/trivy-fs-summary.json
summaries/trivy-image-summary.json
ARTIFACTS

artifacts_json="[]"
if [ -s "${artifact_lines_file}" ]; then
  artifacts_json="$(jq -s '.' "${artifact_lines_file}")"
fi

jq -n \
  --arg schema_version "security_scan_evidence.v1" \
  --arg generated_at "${timestamp}" \
  --arg output_dir "${OUTPUT_DIR}" \
  --argjson strict_mode "$([ "${STRICT_MODE}" = "1" ] && echo true || echo false)" \
  --slurpfile gosec "${SUMMARY_DIR}/gosec-summary.json" \
  --slurpfile trivy_fs "${SUMMARY_DIR}/trivy-fs-summary.json" \
  --slurpfile trivy_image "${SUMMARY_DIR}/trivy-image-summary.json" \
  --argjson artifacts "${artifacts_json}" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    output_dir: $output_dir,
    strict_mode: $strict_mode,
    scans: {
      gosec: $gosec[0],
      trivy_fs: $trivy_fs[0],
      trivy_image: $trivy_image[0]
    },
    artifacts: $artifacts
  }' > "${MANIFEST_PATH}"

non_pass_count="$(jq '[.scans[] | select(.status != "pass")] | length' "${MANIFEST_PATH}")"

if [ "${STRICT_MODE}" = "1" ] && [ "${non_pass_count}" -gt 0 ]; then
  echo "[FAIL] strict security scan mode requires all scans to pass; non-pass count=${non_pass_count}" >&2
  exit 1
fi

if [ "${non_pass_count}" -gt 0 ]; then
  echo "[WARN] some scans were not pass (non-pass count=${non_pass_count}); inspect ${MANIFEST_PATH}" >&2
fi

echo "[PASS] security scan artifacts collected at ${OUTPUT_DIR}"
echo "[INFO] manifest: ${MANIFEST_PATH}"

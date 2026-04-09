#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
cd "${POC_DIR}"

OUTPUT_DIR="${SECURITY_SCAN_OUT_DIR:-build/security-scan/latest}"
STRICT_MODE="${SECURITY_SCAN_STRICT:-0}"
GATEWAY_SCAN_IMAGE="${GATEWAY_SCAN_IMAGE:-precinct-gateway:scan}"
REBUILD_GATEWAY_SCAN_IMAGE="${SECURITY_SCAN_REBUILD_IMAGE:-1}"
TRUFFLEHOG_VERSION="${TRUFFLEHOG_VERSION:-3.94.2}"

RAW_DIR="${OUTPUT_DIR}/raw"
SUMMARY_DIR="${OUTPUT_DIR}/summaries"
MANIFEST_PATH="${OUTPUT_DIR}/security-scan-manifest.json"
TRIVY_FS_SKIP_DIRS=(
  ".beads"
  ".cache"
  ".venv"
  ".vault"
  "build"
  "sample-agents/pydantic_researcher/.venv"
)

rm -rf "${OUTPUT_DIR}"
mkdir -p "${RAW_DIR}" "${SUMMARY_DIR}"

timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

build_trivy_fs_skip_flags() {
  local flags=()
  local dir
  for dir in "${TRIVY_FS_SKIP_DIRS[@]}"; do
    flags+=("--skip-dirs" "${dir}")
  done
  printf '%q ' "${flags[@]}"
}

build_gosec_target_args() {
  local targets=()
  mapfile -t targets < <(go list -f '{{.Dir}}' ./... | grep -Ev '/(\.cache|\.venv|\.vault)(/|$)')
  printf '%q ' "${targets[@]}"
}

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

jsonl_result_count() {
  local jsonl_file="$1"
  if [ ! -s "${jsonl_file}" ]; then
    echo 0
    return
  fi
  awk 'NF && $0 != "[]"{count++} END{print count+0}' "${jsonl_file}"
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

emit_json_scan_summary() {
  local name="$1"
  local status="$2"
  local runner="$3"
  local command="$4"
  local message="$5"
  local json_path="$6"

  local result_count=0
  result_count="$(jsonl_result_count "${json_path}")"

  jq -n \
    --arg name "${name}" \
    --arg status "${status}" \
    --arg runner "${runner}" \
    --arg command "${command}" \
    --arg message "${message}" \
    --arg generated_at "${timestamp}" \
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
  gosec_target_args="$(build_gosec_target_args)"
  scan_gosec_command="gosec -no-fail -fmt sarif -out '${scan_gosec_sarif}' ${gosec_target_args}"
  if run_scan_command "${scan_gosec_command}"; then
    scan_gosec_status="pass"
    scan_gosec_message="gosec scan completed"
  else
    scan_gosec_status="failed"
    scan_gosec_message="gosec scan command failed"
  fi
elif command -v docker >/dev/null 2>&1; then
  scan_gosec_runner="docker"
  gosec_target_args="$(build_gosec_target_args)"
  scan_gosec_command="docker run --rm -v '${POC_DIR}':/src -w /src securego/gosec:2.21.4 sh -lc \"gosec -no-fail -fmt sarif -out '/src/${scan_gosec_sarif}' ${gosec_target_args}\""
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
  trivy_fs_skip_flags="$(build_trivy_fs_skip_flags)"
  scan_trivy_fs_command="trivy fs ${trivy_fs_skip_flags}--severity CRITICAL,HIGH,MEDIUM --exit-code 0 --format sarif --output '${scan_trivy_fs_sarif}' . && trivy fs ${trivy_fs_skip_flags}--severity CRITICAL,HIGH,MEDIUM --exit-code 0 --format json --output '${scan_trivy_fs_json}' ."
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
  if [ "${REBUILD_GATEWAY_SCAN_IMAGE}" = "1" ] || ! docker image inspect "${GATEWAY_SCAN_IMAGE}" >/dev/null 2>&1; then
    echo "[INFO] building fresh ${GATEWAY_SCAN_IMAGE} for image scan"
    docker build -f deploy/compose/Dockerfile.gateway -t "${GATEWAY_SCAN_IMAGE}" .
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

scan_trufflehog_status="skipped"
scan_trufflehog_runner="none"
scan_trufflehog_message="trufflehog unavailable"
scan_trufflehog_command=""
scan_trufflehog_json="${RAW_DIR}/trufflehog-results.jsonl"

if [ -f "${POC_DIR}/.trufflehogignore" ]; then
  if command -v trufflehog >/dev/null 2>&1; then
    scan_trufflehog_runner="binary"
    scan_trufflehog_command="trufflehog filesystem --no-update --json --fail --exclude-paths '${POC_DIR}/.trufflehogignore' '${POC_DIR}' > '${scan_trufflehog_json}'"
    if run_scan_command "${scan_trufflehog_command}"; then
      scan_trufflehog_status="pass"
      scan_trufflehog_message="trufflehog filesystem scan completed"
    else
      scan_trufflehog_status="failed"
      scan_trufflehog_message="trufflehog filesystem scan found secrets or failed"
    fi
  elif command -v docker >/dev/null 2>&1; then
    scan_trufflehog_runner="docker"
    scan_trufflehog_command="docker run --rm -v '${POC_DIR}':/pwd -w /pwd trufflesecurity/trufflehog:${TRUFFLEHOG_VERSION} filesystem --no-update --json --fail --exclude-paths /pwd/.trufflehogignore /pwd > '${scan_trufflehog_json}'"
    if run_scan_command "${scan_trufflehog_command}"; then
      scan_trufflehog_status="pass"
      scan_trufflehog_message="trufflehog filesystem scan completed via container"
    else
      scan_trufflehog_status="failed"
      scan_trufflehog_message="trufflehog filesystem scan found secrets or failed"
    fi
  fi
else
  scan_trufflehog_message="missing .trufflehogignore"
fi

if [ "${scan_trufflehog_status}" = "pass" ]; then
  if [ ! -s "${scan_trufflehog_json}" ]; then
    printf '[]\n' > "${scan_trufflehog_json}"
  fi
  if [ "$(jsonl_result_count "${scan_trufflehog_json}")" -gt 0 ]; then
    scan_trufflehog_status="failed"
    scan_trufflehog_message="trufflehog produced findings"
  fi
fi

scan_hadolint_status="skipped"
scan_hadolint_runner="none"
scan_hadolint_message="hadolint unavailable"
scan_hadolint_command=""
scan_hadolint_sarif="${RAW_DIR}/hadolint-results.sarif"

if command -v hadolint >/dev/null 2>&1; then
  scan_hadolint_runner="binary"
  mapfile -t dockerfiles < <(find "${POC_DIR}" -name 'Dockerfile*' \
    -not -path '*/build/*' -not -path '*/.cache/*' | sort)
  if [ "${#dockerfiles[@]}" -gt 0 ]; then
    scan_hadolint_command="hadolint --format sarif ${dockerfiles[*]} > '${scan_hadolint_sarif}'"
    if run_scan_command "${scan_hadolint_command}"; then
      scan_hadolint_status="pass"
      scan_hadolint_message="hadolint scan completed (${#dockerfiles[@]} Dockerfiles)"
    else
      # hadolint exits non-zero when it finds warnings; check if SARIF was produced
      if [ -s "${scan_hadolint_sarif}" ]; then
        scan_hadolint_status="pass"
        scan_hadolint_message="hadolint scan completed with findings (${#dockerfiles[@]} Dockerfiles)"
      else
        scan_hadolint_status="failed"
        scan_hadolint_message="hadolint scan command failed"
      fi
    fi
  else
    scan_hadolint_status="pass"
    scan_hadolint_message="no Dockerfiles found to lint"
  fi
elif command -v docker >/dev/null 2>&1; then
  scan_hadolint_runner="docker"
  mapfile -t dockerfiles < <(find "${POC_DIR}" -name 'Dockerfile*' \
    -not -path '*/build/*' -not -path '*/.cache/*' | sort)
  if [ "${#dockerfiles[@]}" -gt 0 ]; then
    # For docker runner, lint files one at a time and merge SARIF
    hadolint_tmp_dir="$(mktemp -d)"
    hadolint_idx=0
    hadolint_docker_ok=true
    for df in "${dockerfiles[@]}"; do
      scan_hadolint_command="docker run --rm -i hadolint/hadolint hadolint --format sarif -"
      if ! docker run --rm -i hadolint/hadolint hadolint --format sarif - < "${df}" > "${hadolint_tmp_dir}/${hadolint_idx}.sarif" 2>/dev/null; then
        true  # hadolint exits non-zero on findings
      fi
      hadolint_idx=$((hadolint_idx + 1))
    done
    # Merge individual SARIF files
    jq -s '{ "$schema": .[0]."$schema", runs: [{ defaultSourceLanguage: "dockerfile", results: [.[].runs[].results[]?], tool: .[0].runs[0].tool }] }' "${hadolint_tmp_dir}"/*.sarif > "${scan_hadolint_sarif}" 2>/dev/null
    rm -rf "${hadolint_tmp_dir}"
    if [ -s "${scan_hadolint_sarif}" ]; then
      scan_hadolint_status="pass"
      scan_hadolint_message="hadolint scan completed via container (${#dockerfiles[@]} Dockerfiles)"
    else
      scan_hadolint_status="failed"
      scan_hadolint_message="hadolint container scan failed"
    fi
  else
    scan_hadolint_status="pass"
    scan_hadolint_message="no Dockerfiles found to lint"
  fi
fi

if [ "${scan_hadolint_status}" = "pass" ] && [ ! -s "${scan_hadolint_sarif}" ]; then
  scan_hadolint_status="failed"
  scan_hadolint_message="hadolint scan did not produce sarif output"
fi

emit_scan_summary "gosec" "${scan_gosec_status}" "${scan_gosec_runner}" "${scan_gosec_command}" "${scan_gosec_message}" "raw/gosec-results.sarif" "" > "${SUMMARY_DIR}/gosec-summary.json"
emit_scan_summary "trivy_fs" "${scan_trivy_fs_status}" "${scan_trivy_fs_runner}" "${scan_trivy_fs_command}" "${scan_trivy_fs_message}" "raw/trivy-fs-results.sarif" "raw/trivy-fs-results.json" > "${SUMMARY_DIR}/trivy-fs-summary.json"
emit_scan_summary "trivy_image" "${scan_trivy_image_status}" "${scan_trivy_image_runner}" "${scan_trivy_image_command}" "${scan_trivy_image_message}" "raw/trivy-image-results.sarif" "raw/trivy-image-results.json" > "${SUMMARY_DIR}/trivy-image-summary.json"
emit_json_scan_summary "trufflehog" "${scan_trufflehog_status}" "${scan_trufflehog_runner}" "${scan_trufflehog_command}" "${scan_trufflehog_message}" "raw/trufflehog-results.jsonl" > "${SUMMARY_DIR}/trufflehog-summary.json"
emit_scan_summary "hadolint" "${scan_hadolint_status}" "${scan_hadolint_runner}" "${scan_hadolint_command}" "${scan_hadolint_message}" "raw/hadolint-results.sarif" "" > "${SUMMARY_DIR}/hadolint-summary.json"

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
raw/trufflehog-results.jsonl
raw/hadolint-results.sarif
summaries/gosec-summary.json
summaries/trivy-fs-summary.json
summaries/trivy-image-summary.json
summaries/trufflehog-summary.json
summaries/hadolint-summary.json
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
  --slurpfile trufflehog "${SUMMARY_DIR}/trufflehog-summary.json" \
  --slurpfile hadolint "${SUMMARY_DIR}/hadolint-summary.json" \
  --argjson artifacts "${artifacts_json}" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    output_dir: $output_dir,
    strict_mode: $strict_mode,
    scans: {
      gosec: $gosec[0],
      trivy_fs: $trivy_fs[0],
      trivy_image: $trivy_image[0],
      trufflehog: $trufflehog[0],
      hadolint: $hadolint[0]
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

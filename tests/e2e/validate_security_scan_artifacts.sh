#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-${SECURITY_SCAN_OUT_DIR:-build/security-scan/latest}}"
MANIFEST_PATH="${OUTPUT_DIR}/security-scan-manifest.json"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

sha256_file() {
  local file="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print $1}'
  else
    sha256sum "${file}" | awk '{print $1}'
  fi
}

[ -f "${MANIFEST_PATH}" ] || fail "missing manifest: ${MANIFEST_PATH}"

for scan in gosec trivy_fs trivy_image trufflehog; do
  status="$(jq -r ".scans.${scan}.status" "${MANIFEST_PATH}")"
  [ "${status}" = "pass" ] || fail "scan ${scan} status=${status}; expected pass"
done

required_artifacts=(
  "raw/gosec-results.sarif"
  "raw/trivy-fs-results.sarif"
  "raw/trivy-fs-results.json"
  "raw/trivy-image-results.sarif"
  "raw/trivy-image-results.json"
  "raw/trufflehog-results.jsonl"
  "summaries/gosec-summary.json"
  "summaries/trivy-fs-summary.json"
  "summaries/trivy-image-summary.json"
  "summaries/trufflehog-summary.json"
)

for rel in "${required_artifacts[@]}"; do
  abs="${OUTPUT_DIR}/${rel}"
  [ -s "${abs}" ] || fail "missing or empty artifact: ${abs}"

  expected_sha="$(jq -r --arg path "${rel}" '.artifacts[] | select(.path == $path) | .sha256' "${MANIFEST_PATH}" | head -1)"
  [ -n "${expected_sha}" ] || fail "artifact ${rel} missing from manifest"

  actual_sha="$(sha256_file "${abs}")"
  [ "${actual_sha}" = "${expected_sha}" ] || fail "artifact hash mismatch for ${rel}"
done

echo "[PASS] security scan artifacts validated: ${OUTPUT_DIR}"

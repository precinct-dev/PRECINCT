#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TARGET_DIR="${POC_ROOT}/infra/eks/observability"
DEFAULT_OUTPUT="${POC_ROOT}/tests/e2e/artifacts/immutable-audit-sink-proof.json"

OUTPUT_PATH="${DEFAULT_OUTPUT}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      OUTPUT_PATH="${2}"
      shift 2
      ;;
    *)
      echo "Usage: $0 [--output <path>]" >&2
      exit 2
      ;;
  esac
done

if ! command -v kustomize >/dev/null 2>&1; then
  echo "kustomize is required but was not found in PATH" >&2
  exit 1
fi

mkdir -p "$(dirname "${OUTPUT_PATH}")"
manifest_file="$(mktemp)"
trap 'rm -f "${manifest_file}"' EXIT

kustomize build "${TARGET_DIR}" > "${manifest_file}"

configmap_present=false
if grep -q "name: audit-s3-config" "${manifest_file}"; then
  configmap_present=true
fi

irsa_annotation_present=false
if grep -q "eks.amazonaws.com/role-arn:" "${manifest_file}"; then
  irsa_annotation_present=true
fi

config_block="$(
  awk '
    BEGIN { RS="---"; ORS="\n---\n" }
    /kind:[[:space:]]*ConfigMap/ && /name:[[:space:]]*audit-s3-config/ { print; exit }
  ' "${manifest_file}"
)"
object_lock_mode="$(
  printf '%s\n' "${config_block}" \
    | grep -m1 -E '^[[:space:]]*mode:[[:space:]]*"' \
    | sed -E 's/.*"([A-Z_]+)".*/\1/' \
    || true
)"
retention_days="$(
  printf '%s\n' "${config_block}" \
    | grep -m1 -E '^[[:space:]]*retention_days:[[:space:]]*[0-9]+' \
    | awk '{print $2}' \
    || echo "0"
)"
hash_chain_enabled="$(
  printf '%s\n' "${config_block}" \
    | grep -A8 -m1 -E '^[[:space:]]*hash_chain:' \
    | grep -m1 -E '^[[:space:]]*enabled:' \
    | awk '{print $2}' \
    || echo "false"
)"

required_correlation_fields_present=false
if printf '%s\n' "${config_block}" | grep -q '"trace_id"' \
  && printf '%s\n' "${config_block}" | grep -q '"session_id"' \
  && printf '%s\n' "${config_block}" | grep -q '"decision_id"' \
  && printf '%s\n' "${config_block}" | grep -q '"spiffe_id"'; then
  required_correlation_fields_present=true
fi

status="pass"
if [[ "${configmap_present}" != "true" ]]; then
  status="fail"
fi
if [[ "${object_lock_mode}" != "COMPLIANCE" ]]; then
  status="fail"
fi
if [[ "${retention_days}" -lt 90 ]]; then
  status="fail"
fi
if [[ "${hash_chain_enabled}" != "true" ]]; then
  status="fail"
fi
if [[ "${irsa_annotation_present}" != "true" ]]; then
  status="fail"
fi
if [[ "${required_correlation_fields_present}" != "true" ]]; then
  status="fail"
fi

generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > "${OUTPUT_PATH}" <<EOF
{
  "schema_version": "audit.immutable_sink.v1",
  "generated_at": "${generated_at}",
  "kustomize_target": "infra/eks/observability",
  "immutable_sink_verification": {
    "configmap_present": ${configmap_present},
    "object_lock_mode": "${object_lock_mode}",
    "retention_days": ${retention_days},
    "hash_chain_enabled": ${hash_chain_enabled},
    "irsa_annotation_present": ${irsa_annotation_present},
    "required_correlation_fields_present": ${required_correlation_fields_present}
  },
  "status": "${status}",
  "compose_fallback_boundary": {
    "immutable_worm_storage_supported": false,
    "compensating_controls_required": [
      "hash_chain_verification",
      "off_host_log_shipping",
      "restricted_audit_file_permissions",
      "tamper_evidence_export_attestation"
    ]
  }
}
EOF

echo "immutable_audit_sink_proof: ${status}"
echo "artifact: ${OUTPUT_PATH}"

if [[ "${status}" != "pass" ]]; then
  exit 1
fi

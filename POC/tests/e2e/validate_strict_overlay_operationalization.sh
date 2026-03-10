#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
cd "${POC_DIR}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_cmd kustomize

echo "[INFO] Validating staging/prod overlay operationalization..."
for overlay in staging prod; do
  rendered="${TMP_DIR}/${overlay}.yaml"
  kustomize build "infra/eks/overlays/${overlay}" >"${rendered}"

  if grep -Eq 'ghcr\.io/OWNER/' "${rendered}"; then
    fail "${overlay}: placeholder image owner ghcr.io/OWNER detected in rendered manifests"
  fi

  if grep -Eq 'image:[[:space:]]*python:3\.12-slim' "${rendered}"; then
    fail "${overlay}: placeholder MCP server runtime image python:3.12-slim detected"
  fi

  if grep -Eq 'approval_signing_key:[[:space:]]*".+"' "${rendered}"; then
    fail "${overlay}: inline literal approval_signing_key detected in rendered manifests"
  fi

  grep -Eq 'image:[[:space:]]*ghcr\.io/[a-z0-9._-]+/agentic-ref-arch/mcp-security-gateway([:@][^[:space:]]+)?' "${rendered}" \
    || fail "${overlay}: gateway image is not set to a non-placeholder GHCR path"

  grep -Eq 'image:[[:space:]]*ghcr\.io/[a-z0-9._-]+/agentic-ref-arch/s3-mcp-server([:@][^[:space:]]+)?' "${rendered}" \
    || fail "${overlay}: MCP server image is not set to non-placeholder s3-mcp-server image"

  grep -Eq 'name:[[:space:]]*APPROVAL_SIGNING_KEY' "${rendered}" \
    || fail "${overlay}: APPROVAL_SIGNING_KEY env wiring missing"
  grep -Eq 'secretKeyRef:' "${rendered}" \
    || fail "${overlay}: APPROVAL_SIGNING_KEY must be sourced from secretKeyRef"
  grep -Eq 'name:[[:space:]]*gateway-runtime-secrets' "${rendered}" \
    || fail "${overlay}: gateway-runtime-secrets secret reference missing"
  grep -Eq 'key:[[:space:]]*approval_signing_key' "${rendered}" \
    || fail "${overlay}: approval_signing_key secret key reference missing"
done

for overlay in staging prod; do
  secret_file="infra/eks/overlays/${overlay}/gateway-runtime-secrets.yaml"
  if [ -f "${secret_file}" ]; then
    fail "${overlay}: ${secret_file} must not exist with in-repo literal runtime secrets"
  fi
done

echo "[PASS] Strict overlay operationalization validation passed"

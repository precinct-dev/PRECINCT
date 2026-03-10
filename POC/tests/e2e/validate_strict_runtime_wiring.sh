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

assert_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  grep -Eq "${pattern}" "${file}" || fail "${message}"
}

assert_not_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if grep -Eq "${pattern}" "${file}"; then
    fail "${message}"
  fi
}

require_cmd kustomize
require_cmd docker

echo "[INFO] Validating strict K8s runtime wiring (staging/prod overlays)..."
for overlay in staging prod; do
  out="${TMP_DIR}/${overlay}.yaml"
  kustomize build "infra/eks/overlays/${overlay}" >"${out}"

  assert_contains "${out}" 'name:[[:space:]]*ENFORCEMENT_PROFILE' "${overlay}: missing ENFORCEMENT_PROFILE env"
  assert_contains "${out}" 'value:[[:space:]]*"?prod_standard"?' "${overlay}: ENFORCEMENT_PROFILE must be prod_standard"
  assert_contains "${out}" 'name:[[:space:]]*MCP_TRANSPORT_MODE' "${overlay}: missing MCP_TRANSPORT_MODE env"
  assert_contains "${out}" 'value:[[:space:]]*"?mcp"?' "${overlay}: MCP_TRANSPORT_MODE must be mcp"
  assert_contains "${out}" 'name:[[:space:]]*ENFORCE_MODEL_MEDIATION_GATE' "${overlay}: missing ENFORCE_MODEL_MEDIATION_GATE env"
  assert_contains "${out}" 'value:[[:space:]]*"?true"?' "${overlay}: ENFORCE_MODEL_MEDIATION_GATE must be true"
  assert_contains "${out}" 'name:[[:space:]]*MODEL_POLICY_INTENT_PREPEND_ENABLED' "${overlay}: missing MODEL_POLICY_INTENT_PREPEND_ENABLED env"
  assert_contains "${out}" 'value:[[:space:]]*"?true"?' "${overlay}: MODEL_POLICY_INTENT_PREPEND_ENABLED must be true"
  assert_contains "${out}" 'name:[[:space:]]*SPIFFE_MODE' "${overlay}: missing SPIFFE_MODE env"
  assert_contains "${out}" 'value:[[:space:]]*"?prod"?' "${overlay}: SPIFFE_MODE must be prod"
  assert_contains "${out}" 'name:[[:space:]]*SPIFFE_LISTEN_PORT' "${overlay}: missing SPIFFE_LISTEN_PORT env"
  assert_contains "${out}" 'value:[[:space:]]*"?9090"?' "${overlay}: SPIFFE_LISTEN_PORT must be 9090 for in-cluster HTTPS listener"
  assert_contains "${out}" 'name:[[:space:]]*UPSTREAM_URL' "${overlay}: missing UPSTREAM_URL env"
  assert_contains "${out}" 'value:[[:space:]]*"?https://[^"[:space:]]+"?' "${overlay}: UPSTREAM_URL must be https in strict overlays"
  assert_contains "${out}" 'name:[[:space:]]*APPROVAL_SIGNING_KEY' "${overlay}: missing APPROVAL_SIGNING_KEY env"
  assert_contains "${out}" 'secretKeyRef:' "${overlay}: APPROVAL_SIGNING_KEY must come from secretKeyRef"
  assert_contains "${out}" 'name:[[:space:]]*gateway-runtime-secrets' "${overlay}: missing gateway-runtime-secrets reference"
  assert_contains "${out}" 'key:[[:space:]]*approval_signing_key' "${overlay}: secret key approval_signing_key is required"
  assert_contains "${out}" 'name:[[:space:]]*TOOL_REGISTRY_PUBLIC_KEY' "${overlay}: missing TOOL_REGISTRY_PUBLIC_KEY env"
  assert_contains "${out}" 'value:[[:space:]]*"?/config/attestation-ed25519\.pub"?' "${overlay}: TOOL_REGISTRY_PUBLIC_KEY must point to /config/attestation-ed25519.pub"
  assert_contains "${out}" 'name:[[:space:]]*MODEL_PROVIDER_CATALOG_PUBLIC_KEY' "${overlay}: missing MODEL_PROVIDER_CATALOG_PUBLIC_KEY env"
  assert_contains "${out}" 'value:[[:space:]]*"?/config/attestation-ed25519\.pub"?' "${overlay}: MODEL_PROVIDER_CATALOG_PUBLIC_KEY must point to /config/attestation-ed25519.pub"
  assert_contains "${out}" 'name:[[:space:]]*GUARD_ARTIFACT_PATH' "${overlay}: missing GUARD_ARTIFACT_PATH env"
  assert_contains "${out}" 'value:[[:space:]]*"?/config/guard-artifact\.bin"?' "${overlay}: GUARD_ARTIFACT_PATH must point to /config/guard-artifact.bin"
  assert_contains "${out}" 'name:[[:space:]]*GUARD_ARTIFACT_SHA256' "${overlay}: missing GUARD_ARTIFACT_SHA256 env"
  assert_contains "${out}" 'value:[[:space:]]*"?[a-f0-9]{64}"?' "${overlay}: GUARD_ARTIFACT_SHA256 must be a 64-char hex digest"
  assert_contains "${out}" 'name:[[:space:]]*GUARD_ARTIFACT_PUBLIC_KEY' "${overlay}: missing GUARD_ARTIFACT_PUBLIC_KEY env"
  assert_contains "${out}" 'value:[[:space:]]*"?/config/attestation-ed25519\.pub"?' "${overlay}: GUARD_ARTIFACT_PUBLIC_KEY must point to /config/attestation-ed25519.pub"
done

echo "[INFO] Validating strict Compose runtime wiring..."
export STRICT_UPSTREAM_URL="https://strict-upstream.example.com/mcp"
export APPROVAL_SIGNING_KEY="compose-approval-signing-key-material-at-least-32"
export UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://agentic-ref-arch.poc/ns/tools/sa/mcp-tool"
export KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://agentic-ref-arch.poc/ns/data/sa/keydb"

compose_out="${TMP_DIR}/compose-strict.yaml"
docker compose --profile strict -f docker-compose.yml -f docker-compose.strict.yml config >"${compose_out}"

assert_contains "${compose_out}" 'ENFORCEMENT_PROFILE:[[:space:]]*prod_standard' "compose strict: ENFORCEMENT_PROFILE must be prod_standard"
assert_contains "${compose_out}" 'MCP_TRANSPORT_MODE:[[:space:]]*mcp' "compose strict: MCP_TRANSPORT_MODE must be mcp"
assert_contains "${compose_out}" 'ENFORCE_MODEL_MEDIATION_GATE:[[:space:]]*"?true"?' "compose strict: ENFORCE_MODEL_MEDIATION_GATE must be true"
assert_contains "${compose_out}" 'MODEL_POLICY_INTENT_PREPEND_ENABLED:[[:space:]]*"?true"?' "compose strict: MODEL_POLICY_INTENT_PREPEND_ENABLED must be true"
assert_contains "${compose_out}" 'SPIFFE_MODE:[[:space:]]*prod' "compose strict: SPIFFE_MODE must be prod"
assert_contains "${compose_out}" 'SPIFFE_LISTEN_PORT:[[:space:]]*"?9443"?' "compose strict: SPIFFE_LISTEN_PORT must be 9443"
assert_contains "${compose_out}" 'target:[[:space:]]*9443' "compose strict: HTTPS listener port 9443 must be published"
assert_not_contains "${compose_out}" 'published:[[:space:]]*"9090"' "compose strict: dev HTTP listener port 9090 must not be published"
assert_contains "${compose_out}" 'UPSTREAM_URL:[[:space:]]*https://' "compose strict: UPSTREAM_URL must be https"
assert_contains "${compose_out}" 'APPROVAL_SIGNING_KEY:[[:space:]]+' "compose strict: APPROVAL_SIGNING_KEY must be set"
assert_contains "${compose_out}" 'UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS:[[:space:]]+' "compose strict: UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS must be set"
assert_contains "${compose_out}" 'KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS:[[:space:]]+' "compose strict: KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS must be set"
assert_contains "${compose_out}" 'TOOL_REGISTRY_PUBLIC_KEY:[[:space:]]+/config/attestation-ed25519\.pub' "compose strict: TOOL_REGISTRY_PUBLIC_KEY must point to /config/attestation-ed25519.pub"
assert_contains "${compose_out}" 'MODEL_PROVIDER_CATALOG_PUBLIC_KEY:[[:space:]]+/config/attestation-ed25519\.pub' "compose strict: MODEL_PROVIDER_CATALOG_PUBLIC_KEY must point to /config/attestation-ed25519.pub"
assert_contains "${compose_out}" 'GUARD_ARTIFACT_PATH:[[:space:]]+/config/guard-artifact\.bin' "compose strict: GUARD_ARTIFACT_PATH must point to /config/guard-artifact.bin"
assert_contains "${compose_out}" 'GUARD_ARTIFACT_SHA256:[[:space:]]+[a-f0-9]{64}' "compose strict: GUARD_ARTIFACT_SHA256 must be set to a 64-char hex digest"
assert_contains "${compose_out}" 'GUARD_ARTIFACT_PUBLIC_KEY:[[:space:]]+/config/attestation-ed25519\.pub' "compose strict: GUARD_ARTIFACT_PUBLIC_KEY must point to /config/attestation-ed25519.pub"
assert_not_contains "${compose_out}" 'ALLOW_INSECURE_DEV_MODE:' "compose strict: ALLOW_INSECURE_DEV_MODE must not be inherited"
assert_not_contains "${compose_out}" 'ALLOW_NON_LOOPBACK_DEV_BIND:' "compose strict: ALLOW_NON_LOOPBACK_DEV_BIND must not be inherited"
assert_not_contains "${compose_out}" 'DEMO_RUGPULL_ADMIN_ENABLED:' "compose strict: DEMO_RUGPULL_ADMIN_ENABLED must not be inherited"
assert_not_contains "${compose_out}" 'DEV_LISTEN_HOST:[[:space:]]*0\.0\.0\.0' "compose strict: DEV_LISTEN_HOST=0.0.0.0 must not be inherited"
assert_not_contains "${compose_out}" 'GUARD_MODEL_ENDPOINT:[[:space:]]*http://mock-guard-model:8080/openai/v1' "compose strict: mock guard endpoint must not be inherited"
assert_not_contains "${compose_out}" 'MODEL_PROVIDER_ENDPOINT_GROQ:[[:space:]]*http://mock-guard-model:8080/openai/v1/chat/completions' "compose strict: mock model provider endpoint must not be inherited"

echo "[PASS] Strict runtime wiring validation passed"

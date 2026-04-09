#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

pass() {
  echo "[PASS] $1"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

provider="${MANAGED_K8S_PROVIDER:-}"
context="${MANAGED_K8S_CONTEXT:-}"
required_namespaces="${MANAGED_K8S_REQUIRED_NAMESPACES:-gateway,spire-system,spike-system,data,tools}"

missing_vars=()
[[ -n "${provider}" ]] || missing_vars+=("MANAGED_K8S_PROVIDER")
[[ -n "${context}" ]] || missing_vars+=("MANAGED_K8S_CONTEXT")
if [[ "${#missing_vars[@]}" -gt 0 ]]; then
  fail "Missing required environment variables: ${missing_vars[*]} (set provider + managed staging kubectl context)"
fi

require_cmd kubectl

if ! kubectl --context "${context}" cluster-info >/dev/null 2>&1; then
  fail "Cannot reach managed context '${context}'. Verify kubeconfig credentials and cluster availability."
fi
pass "managed context reachable: ${context}"

missing=""
IFS=',' read -r -a ns_list <<<"${required_namespaces}"
for ns in "${ns_list[@]}"; do
  ns_trimmed="$(echo "${ns}" | xargs)"
  [[ -z "${ns_trimmed}" ]] && continue
  if ! kubectl --context "${context}" get ns "${ns_trimmed}" >/dev/null 2>&1; then
    if [[ -z "${missing}" ]]; then
      missing="${ns_trimmed}"
    else
      missing="${missing},${ns_trimmed}"
    fi
  fi
done

[[ -z "${missing}" ]] || fail "Managed context '${context}' is missing required namespaces: ${missing}"
pass "required namespaces exist: ${required_namespaces}"

echo "[PASS] Managed cloud bootstrap preflight passed"

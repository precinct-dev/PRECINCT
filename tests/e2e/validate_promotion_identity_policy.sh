#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
WORKFLOW="${REPO_ROOT}/.github/workflows/promote.yaml"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

[ -f "${WORKFLOW}" ] || fail "workflow not found: ${WORKFLOW}"

if grep -Eq -- '--certificate-identity-regexp="?\\.\\*"?|--certificate-identity-regexp="\\.\\*"' "${WORKFLOW}"; then
  fail "wildcard signer identity regex is not allowed in promote workflow"
fi

grep -Eq 'SOURCE_CERT_IDENTITY_REGEX:[[:space:]]*\^https://github\.com/\$\{\{ github\.repository \}\}/\.github/workflows/ci\.yaml@refs/heads/\(main\|epic/\.\+\)\$' "${WORKFLOW}" \
  || fail "SOURCE_CERT_IDENTITY_REGEX must restrict to this repo CI workflow on main/epic branches"

grep -Eq 'SOURCE_CERT_OIDC_ISSUER:[[:space:]]*https://token\.actions\.githubusercontent\.com' "${WORKFLOW}" \
  || fail "SOURCE_CERT_OIDC_ISSUER must be explicitly pinned"

grep -Eq -- '--certificate-identity-regexp="\$\{SOURCE_CERT_IDENTITY_REGEX\}"' "${WORKFLOW}" \
  || fail "cosign verify must use SOURCE_CERT_IDENTITY_REGEX"

grep -Eq -- '--certificate-oidc-issuer="\$\{SOURCE_CERT_OIDC_ISSUER\}"' "${WORKFLOW}" \
  || fail "cosign verify must use SOURCE_CERT_OIDC_ISSUER"

echo "[PASS] Promotion identity policy validation passed"

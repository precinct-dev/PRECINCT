#!/usr/bin/env bash
# compose-verify Dockerfile FROM pinning negative-path check (RFA-yprx)
#
# Proves compose-verify rejects unpinned third-party Dockerfile FROM references.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERIFY_SCRIPT="${ROOT_DIR}/scripts/compose-verify.sh"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

pass() {
  echo "[PASS] $1"
}

if [[ ! -x "${VERIFY_SCRIPT}" ]]; then
  fail "compose-verify script not found or not executable: ${VERIFY_SCRIPT}"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

bad_df="${tmp_dir}/Dockerfile.unpinned"
cat > "${bad_df}" <<'EOF'
FROM alpine:3.21
RUN echo "fixture"
EOF

out_file="${tmp_dir}/verify.out"
if COMPOSE_VERIFY_EXTRA_DOCKERFILES="${bad_df}" "${VERIFY_SCRIPT}" >"${out_file}" 2>&1; then
  fail "compose-verify unexpectedly passed with an unpinned Dockerfile FROM fixture"
fi

if ! grep -q "Found Dockerfile FROM references without digest pinning" "${out_file}"; then
  fail "compose-verify failed, but did not report Dockerfile FROM pinning error"
fi

if ! grep -q "${bad_df}" "${out_file}"; then
  fail "compose-verify output did not include failing Dockerfile path"
fi

pass "compose-verify rejects unpinned Dockerfile FROM references"
echo ""
echo "compose_verify_dockerfile_pin_check: PASS"


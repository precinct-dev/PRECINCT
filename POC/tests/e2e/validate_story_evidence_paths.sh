#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
REPO_ROOT="$(cd "${POC_DIR}/.." && pwd)"
STORY_ID="${1:-}"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

[[ -n "${STORY_ID}" ]] || fail "usage: $(basename "$0") <story-id>"

require_cmd bd
require_cmd jq
require_cmd rg

notes="$(bd show "${STORY_ID}" --json | jq -r '.[0].notes // empty')"
[[ -n "${notes}" ]] || fail "story ${STORY_ID} has no notes to validate"

mapfile -t candidates < <(
  while IFS= read -r line; do
    lower="$(printf '%s' "${line}" | tr '[:upper:]' '[:lower:]')"
    if printf '%s' "${lower}" | rg -q 'missing|absent|not present'; then
      continue
    fi
    printf '%s\n' "${line}" | rg -o 'POC/[A-Za-z0-9._/-]+' || true
  done < <(printf '%s\n' "${notes}") | sort -u
)
[[ "${#candidates[@]}" -gt 0 ]] || fail "no POC evidence paths found in notes for ${STORY_ID}"

missing=0
for rel in "${candidates[@]}"; do
  abs="${REPO_ROOT}/${rel}"
  if [[ -e "${abs}" ]]; then
    echo "[PASS] ${rel}"
  else
    echo "[MISSING] ${rel}"
    missing=$((missing + 1))
  fi
done

if [[ "${missing}" -gt 0 ]]; then
  fail "story ${STORY_ID} references ${missing} missing evidence path(s)"
fi

echo "[PASS] evidence paths validated for ${STORY_ID}"

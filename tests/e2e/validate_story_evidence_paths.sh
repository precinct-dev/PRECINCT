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

require_cmd nd
require_cmd jq
require_cmd rg

notes="$(nd show "${STORY_ID}" --json | jq -r '.Body // empty')"
[[ -n "${notes}" ]] || fail "story ${STORY_ID} has no notes to validate"

notes_section="$(printf '%s\n' "${notes}" | awk '
  /^## Notes$/ { in_notes = 1; next }
  in_notes && /^## History$/ { exit }
  in_notes { print }
')"

if [[ -z "${notes_section}" ]]; then
  notes_section="${notes}"
fi

authoritative_notes="$(printf '%s\n' "${notes_section}" | awk '
  /^## Implementation Evidence \(DELIVERED\)$/ { capture = 1; print; next }
  capture && /^## / { exit }
  capture { print }
')"

if [[ -z "${authoritative_notes}" ]]; then
  authoritative_notes="$(printf '%s\n' "${notes_section}" | awk '
    /^## nd_contract$/ { capture = 1; print; next }
    capture && /^## / { exit }
    capture { print }
  ')"
fi

if [[ -z "${authoritative_notes}" ]]; then
  authoritative_notes="${notes_section}"
fi

mapfile -t candidates < <(
  while IFS= read -r line; do
    lower="$(printf '%s' "${line}" | tr '[:upper:]' '[:lower:]')"
    if printf '%s' "${lower}" | rg -q 'missing|absent|not present'; then
      continue
    fi
    printf '%s\n' "${line}" | rg -o '(AGENTS\.md|README\.md|Makefile|(?:docs|tests|scripts|internal|infra|sdk|ports|config|deploy)/[A-Za-z0-9._/-]*\.[A-Za-z0-9]+)' || true
  done < <(printf '%s\n' "${authoritative_notes}") | sort -u
)
[[ "${#candidates[@]}" -gt 0 ]] || fail "no evidence paths found in notes for ${STORY_ID}"

missing=0
for rel in "${candidates[@]}"; do
  clean_rel="${rel}"
  abs="${POC_DIR}/${clean_rel}"
  if [[ -e "${abs}" ]]; then
    echo "[PASS] ${clean_rel}"
  else
    echo "[MISSING] ${clean_rel}"
    missing=$((missing + 1))
  fi
done

if [[ "${missing}" -gt 0 ]]; then
  fail "story ${STORY_ID} references ${missing} missing evidence path(s)"
fi

echo "[PASS] evidence paths validated for ${STORY_ID}"

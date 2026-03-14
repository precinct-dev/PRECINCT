#!/usr/bin/env bash

set -euo pipefail

if [[ -n "${AGW_KEYDB_URL:-}" ]]; then
  printf '%s\n' "$AGW_KEYDB_URL"
  exit 0
fi

if (echo > /dev/tcp/127.0.0.1/6379) >/dev/null 2>&1; then
  printf '%s\n' 'redis://127.0.0.1:6379'
  exit 0
fi

printf '%s\n' 'compose://keydb'

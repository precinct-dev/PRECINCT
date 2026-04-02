#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${OPENCLAW_BASE_URL:-${1:-}}"
TOKEN="${OPENCLAW_GATEWAY_TOKEN:-${2:-}}"
MESSAGE="${OPENCLAW_SMOKE_MESSAGE:-${3:-precinct-openclaw-k8s-smoke-$(date +%s)}}"
OPENCLAW_MODEL="${OPENCLAW_MODEL:-openclaw/default}"
OPENCLAW_BACKEND_MODEL="${OPENCLAW_BACKEND_MODEL:-openai/gpt-oss-120b}"

if [ -z "${BASE_URL}" ] || [ -z "${TOKEN}" ]; then
  echo "usage: OPENCLAW_BASE_URL=http://127.0.0.1:38789 OPENCLAW_GATEWAY_TOKEN=... $0 [base_url] [token] [message]" >&2
  exit 2
fi

payload="$(cat <<JSON
{
  "model": "${OPENCLAW_MODEL}",
  "messages": [
    {"role": "user", "content": "${MESSAGE}"}
  ]
}
JSON
)"

full_resp="$(
  curl -sS -w '\n%{http_code}' \
    -X POST "${BASE_URL%/}/v1/chat/completions" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -H "x-openclaw-model: ${OPENCLAW_BACKEND_MODEL}" \
    -d "${payload}"
)"

resp_code="$(printf '%s' "${full_resp}" | tail -n1)"
resp_body="$(printf '%s' "${full_resp}" | sed '$d')"

if [ "${resp_code}" != "200" ]; then
  echo "OpenClaw HTTP smoke failed with status ${resp_code}" >&2
  printf '%s\n' "${resp_body}" >&2
  exit 1
fi

assistant_text="$(
  printf '%s' "${resp_body}" | python3 -c 'import json,sys
try:
    obj=json.load(sys.stdin)
    print((obj.get("choices") or [{}])[0].get("message", {}).get("content", ""))
except Exception:
    print("")
'
)"

if [ -z "${assistant_text}" ]; then
  echo "OpenClaw HTTP smoke returned 200 but no assistant text" >&2
  printf '%s\n' "${resp_body}" >&2
  exit 1
fi

printf '{\n  "ok": true,\n  "user_text": %s,\n  "assistant_text": %s\n}\n' \
  "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${MESSAGE}")" \
  "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${assistant_text}")"

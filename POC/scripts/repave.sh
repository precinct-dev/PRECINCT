#!/usr/bin/env bash
set -euo pipefail

component="${COMPONENT:-${1:-}}"
if [[ -z "${component}" ]]; then
  echo "Usage: make repave COMPONENT=<component> (ex: make repave COMPONENT=keydb)" >&2
  exit 2
fi

if [[ "${component}" != "keydb" ]]; then
  echo "ERROR: only COMPONENT=keydb is supported in this walking skeleton (got: ${component})" >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
poc_dir="$(cd -- "${script_dir}/.." && pwd)"
cd "${poc_dir}"

service="${component}"
state_file="${poc_dir}/.repave-state.json"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is required" >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose is required" >&2
  exit 1
fi

cid="$(docker compose ps -q "${service}" || true)"
if [[ -z "${cid}" ]]; then
  echo "ERROR: compose service '${service}' is not running; start it first (ex: docker compose up -d --wait ${service})" >&2
  exit 1
fi

image_ref="$(docker compose config --images "${service}" 2>/dev/null | head -n1 || true)"
if [[ -z "${image_ref}" ]]; then
  echo "ERROR: could not determine image ref for compose service '${service}'" >&2
  exit 1
fi

before_image_hash="$(docker inspect --format '{{.Image}}' "${cid}" 2>/dev/null || true)"
if [[ -z "${before_image_hash}" ]]; then
  echo "ERROR: could not inspect current image hash for container '${cid}'" >&2
  exit 1
fi

echo "[repave] component=${component}"
echo "[repave] service=${service}"
echo "[repave] image_ref=${image_ref}"
echo "[repave] current_image_hash=${before_image_hash}"

echo "[repave] pulling fresh image (same tag)..."
docker compose pull "${service}"

echo "[repave] stopping container..."
docker compose stop "${service}"

echo "[repave] removing container (preserving volumes)..."
docker compose rm -f "${service}"

echo "[repave] starting new container and waiting for health..."
docker compose up -d --wait --wait-timeout 180 "${service}"

new_cid="$(docker compose ps -q "${service}" || true)"
if [[ -z "${new_cid}" ]]; then
  echo "ERROR: compose service '${service}' did not start (no container id found)" >&2
  exit 1
fi

health_status="$(docker inspect --format '{{.State.Health.Status}}' "${new_cid}" 2>/dev/null || echo "unknown")"
if [[ "${health_status}" != "healthy" ]]; then
  echo "ERROR: health check failed after repave (health=${health_status}); aborting" >&2
  exit 1
fi

ping_out="$(docker compose exec -T "${service}" keydb-cli ping | tr -d '\r' || true)"
if [[ "${ping_out}" != "PONG" ]]; then
  echo "ERROR: connectivity check failed after repave (expected PONG, got: ${ping_out}); aborting" >&2
  exit 1
fi

after_image_hash="$(docker inspect --format '{{.Image}}' "${new_cid}" 2>/dev/null || true)"
if [[ -z "${after_image_hash}" ]]; then
  echo "ERROR: could not inspect new image hash after repave" >&2
  exit 1
fi

timestamp="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

echo "[repave] new_image_hash=${after_image_hash}"
echo "[repave] writing repave state: ${state_file}"

# AC7 requirement: state update happens only after health + connectivity checks pass.
if command -v jq >/dev/null 2>&1; then
  base='{}'
  if [[ -f "${state_file}" ]]; then
    base="$(cat "${state_file}")"
  fi
  tmp="$(mktemp)"
  printf '%s' "${base}" | jq -S \
    --arg comp "${component}" \
    --arg ts "${timestamp}" \
    --arg img "${after_image_hash}" \
    --arg health "${health_status}" \
    '.last_repave = (.last_repave // {}) | .last_repave[$comp] = {timestamp: $ts, image_hash: $img, health: $health}' \
    > "${tmp}"
  mv "${tmp}" "${state_file}"
else
  echo "ERROR: jq is required to update ${state_file} deterministically" >&2
  exit 1
fi

echo "[repave] OK"


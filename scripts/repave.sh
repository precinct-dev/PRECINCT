#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  make repave                     # repave full stack in dependency order (RFA-67xd)
  make repave COMPONENT=keydb      # repave a single component (walking skeleton, RFA-4ldp)

Direct invocation:
  scripts/repave.sh --all
  scripts/repave.sh <component>

Test hooks:
  REPAVE_SIMULATE_HEALTH_FAIL_COMPONENT=<component>  # force health failure for a component (for integration tests)
EOF
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
poc_dir="$(cd -- "${script_dir}/.." && pwd)"
cd "${poc_dir}"

state_file="${poc_dir}/.repave-state.json"
reports_dir="${poc_dir}/reports"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is required" >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose is required" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required (used for deterministic state + report generation)" >&2
  exit 1
fi

arg="${1:-}"
if [[ -z "${arg}" ]]; then
  usage
  exit 2
fi

compose_main=(docker compose -f "${poc_dir}/deploy/compose/docker-compose.yml")
compose_phoenix=(docker compose -f docker-compose.phoenix.yml)

now_utc_iso() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }
now_utc_compact() { date -u +'%Y-%m-%d-%H%M%S'; }

container_id_for() {
  local svc="$1"
  if [[ "${svc}" == "phoenix" || "${svc}" == "otel-collector" ]]; then
    "${compose_phoenix[@]}" ps -q "${svc}" 2>/dev/null || true
  else
    "${compose_main[@]}" ps -q "${svc}" 2>/dev/null || true
  fi
}

image_ref_for() {
  local svc="$1"
  if [[ "${svc}" == "phoenix" || "${svc}" == "otel-collector" ]]; then
    "${compose_phoenix[@]}" config --images "${svc}" 2>/dev/null | head -n1 || true
  else
    "${compose_main[@]}" config --images "${svc}" 2>/dev/null | head -n1 || true
  fi
}

inspect_image_hash() {
  local cid="$1"
  docker inspect --format '{{.Image}}' "${cid}" 2>/dev/null || true
}

inspect_health_status() {
  local cid="$1"
  docker inspect --format '{{.State.Health.Status}}' "${cid}" 2>/dev/null || echo "unknown"
}

update_state() {
  local comp="$1" ts="$2" img="$3" health="$4"
  local base='{}'
  if [[ -f "${state_file}" ]]; then
    base="$(cat "${state_file}")"
  fi
  local tmp
  tmp="$(mktemp)"
  printf '%s' "${base}" | jq -S \
    --arg comp "${comp}" \
    --arg ts "${ts}" \
    --arg img "${img}" \
    --arg health "${health}" \
    '.last_repave = (.last_repave // {}) | .last_repave[$comp] = {timestamp: $ts, image_hash: $img, health: $health}' \
    > "${tmp}"
  mv "${tmp}" "${state_file}"
}

ensure_running() {
  local svc="$1"
  local cid
  cid="$(container_id_for "${svc}")"
  if [[ -n "${cid}" ]]; then
    return 0
  fi
  echo "[repave] service ${svc} not running; starting it..."
  if [[ "${svc}" == "phoenix" || "${svc}" == "otel-collector" ]]; then
    "${compose_phoenix[@]}" up -d --wait --wait-timeout 180 "${svc}"
  elif [[ "${svc}" == "mcp-security-gateway" ]]; then
    # Gateway repave must not block on one-shot bootstrap services that may remain
    # in long-running/retry states after prior incidents.
    "${compose_main[@]}" up -d --no-deps --wait --wait-timeout 180 "${svc}" || true

    cid="$(container_id_for "${svc}")"
    if [[ -z "${cid}" ]]; then
      local created_cid created_state
      created_cid="$("${compose_main[@]}" ps -aq "${svc}" 2>/dev/null || true)"
      if [[ -n "${created_cid}" ]]; then
        created_state="$(docker inspect --format '{{.State.Status}}' "${created_cid}" 2>/dev/null || true)"
        if [[ "${created_state}" == "created" ]]; then
          echo "[repave] gateway remained in created state after compose up; forcing docker start"
          docker start "${created_cid}" >/dev/null
        fi
      fi
    fi

    local deadline
    deadline=$((SECONDS + 90))
    while (( SECONDS < deadline )); do
      if verify_gateway_health; then
        return 0
      fi
      sleep 2
    done
    echo "ERROR: gateway did not become healthy while ensuring running state" >&2
    return 1
  else
    "${compose_main[@]}" up -d --wait --wait-timeout 180 "${svc}"
  fi
}

verify_spire_server_agent_list() {
  # Story requires: spire-server agent list returns entries.
  # We tolerate transient reconnect delays after spire-server restart.
  local deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    # Use spire-server CLI inside the container.
    # Output includes a header line; require at least one agent row.
    local out
    out="$("${compose_main[@]}" exec -T spire-server /opt/spire/bin/spire-server agent list 2>/dev/null || true)"
    # Heuristic: spire-server prints "Found 0 agents" when empty; avoid parsing brittle formats.
    if [[ -n "${out}" && "${out}" != *"Found 0 agents"* && "${out}" == *"SPIFFE ID"* ]]; then
      return 0
    fi
    sleep 2
  done
  echo "ERROR: spire-server agent list did not return entries within timeout" >&2
  return 1
}

verify_keydb_ping() {
  local pong
  pong="$("${compose_main[@]}" exec -T keydb keydb-cli ping | tr -d '\r' || true)"
  [[ "${pong}" == "PONG" ]]
}

verify_gateway_health() {
  # Host port mapping for gateway is 9090:9090 in docker-compose.yml.
  curl -fsS "http://localhost:9090/health" >/dev/null 2>&1
}

verify_phoenix_health() {
  curl -fsS "http://localhost:6006/" >/dev/null 2>&1
}

verify_otel_collector_health() {
  # otel-collector image is FROM scratch, so we probe from a tiny curl container
  # attached to the phoenix-observability-network.
  docker run --rm --network phoenix-observability-network curlimages/curl:8.5.0 -fsS \
    "http://otel-collector:13133/" >/dev/null
}

wait_for_spike_keeper_shard_resync() {
  # SPIKE Nexus periodically pushes shards back to Keeper.
  # After Keeper repave, wait long enough for at least one sync cycle before
  # repaving SPIKE Nexus (which needs Keeper shard availability at startup).
  local wait_seconds="${REPAVE_SPIKE_KEEPER_RECOVERY_WAIT_SECONDS:-20}"
  if ! [[ "${wait_seconds}" =~ ^[0-9]+$ ]]; then
    echo "ERROR: REPAVE_SPIKE_KEEPER_RECOVERY_WAIT_SECONDS must be an integer number of seconds" >&2
    return 1
  fi

  echo "[repave-all] waiting ${wait_seconds}s for SPIKE shard re-sync (nexus -> keeper)"
  sleep "${wait_seconds}"
}

repave_one_main() {
  local svc="$1"
  ensure_running "${svc}"

  local cid image_ref before_hash after_hash ts health duration_s start_s
  cid="$(container_id_for "${svc}")"
  image_ref="$(image_ref_for "${svc}")"
  before_hash="$(inspect_image_hash "${cid}")"
  if [[ -z "${before_hash}" || -z "${image_ref}" ]]; then
    echo "ERROR: could not determine current image hash or image ref for ${svc}" >&2
    return 1
  fi

  echo "[repave] component=${svc}"
  echo "[repave] service=${svc}"
  echo "[repave] image_ref=${image_ref}"
  echo "[repave] current_image_hash=${before_hash}"

  echo "[repave] pulling fresh image (same tag)..."
  "${compose_main[@]}" pull "${svc}"

  start_s="${SECONDS}"
  echo "[repave] stopping container..."
  "${compose_main[@]}" stop "${svc}"

  echo "[repave] removing container (preserving volumes)..."
  "${compose_main[@]}" rm -f "${svc}"

  echo "[repave] starting new container and waiting for health..."
  if [[ "${svc}" == "mcp-security-gateway" ]]; then
    # Gateway depends on one-shot init jobs that may already have completed;
    # avoid re-triggering those dependencies during repave.
    # In practice, compose --wait can report unhealthy before the gateway's
    # dependency graph fully settles; fall back to explicit /health polling.
    if ! "${compose_main[@]}" up -d --no-deps --wait --wait-timeout 300 "${svc}"; then
      echo "[repave] gateway compose wait reported unhealthy; retrying with readiness polling"
      "${compose_main[@]}" up -d --no-deps "${svc}" >/dev/null 2>&1 || true
    fi
  else
    "${compose_main[@]}" up -d --wait --wait-timeout 300 "${svc}"
  fi

  cid="$(container_id_for "${svc}")"
  if [[ -z "${cid}" ]]; then
    echo "ERROR: compose service '${svc}' did not start (no container id found)" >&2
    return 1
  fi

  health="$(inspect_health_status "${cid}")"
  if [[ "${svc}" == "mcp-security-gateway" ]]; then
    local gateway_ready=0
    local deadline=$((SECONDS + 120))
    while (( SECONDS < deadline )); do
      if verify_gateway_health; then
        gateway_ready=1
        break
      fi
      sleep 2
    done
    if [[ "${gateway_ready}" -ne 1 ]]; then
      echo "ERROR: gateway /health check failed after repave (health=${health})" >&2
      "${compose_main[@]}" ps "${svc}" >&2 || true
      docker logs --tail 100 "${svc}" >&2 || true
      return 1
    fi
  elif [[ "${health}" != "healthy" ]]; then
    echo "ERROR: health check failed after repave (health=${health})" >&2
    return 1
  fi

  # Additional per-component verifications (RFA-67xd health verification section).
  case "${svc}" in
    spire-server)
      verify_spire_server_agent_list
      ;;
    spire-agent)
      # docker healthcheck is the primary signal; nothing extra.
      ;;
    keydb)
      if ! verify_keydb_ping; then
        echo "ERROR: keydb connectivity check failed after repave (expected PONG)" >&2
        return 1
      fi
      ;;
    mcp-security-gateway)
      if ! verify_gateway_health; then
        echo "ERROR: gateway /health check failed after repave" >&2
        return 1
      fi
      ;;
    mock-mcp-server)
      # docker healthcheck is sufficient (wget /health inside container).
      ;;
    spike-keeper-1|spike-nexus)
      # docker healthcheck (from Dockerfile) is sufficient.
      ;;
    *)
      ;;
  esac

  if [[ "${REPAVE_SIMULATE_HEALTH_FAIL_COMPONENT:-}" == "${svc}" ]]; then
    echo "ERROR: simulated health failure for ${svc} (REPAVE_SIMULATE_HEALTH_FAIL_COMPONENT)" >&2
    return 1
  fi

  after_hash="$(inspect_image_hash "${cid}")"
  if [[ -z "${after_hash}" ]]; then
    echo "ERROR: could not inspect new image hash after repave for ${svc}" >&2
    return 1
  fi

  duration_s=$((SECONDS - start_s))
  ts="$(now_utc_iso)"
  update_state "${svc}" "${ts}" "${after_hash}" "healthy"

  echo "[repave] new_image_hash=${after_hash}"
  echo "[repave] OK component=${svc} duration_s=${duration_s}"

  # Return data for reporting via global vars (bash doesn't have real structs).
  REPAIRED_BEFORE_HASH="${before_hash}"
  REPAIRED_AFTER_HASH="${after_hash}"
  REPAIRED_HEALTH="OK"
  REPAIRED_DURATION="${duration_s}"
  return 0
}

repave_one_phoenix() {
  local svc="$1"
  ensure_running "${svc}"

  local cid image_ref before_hash after_hash duration_s start_s ts
  cid="$(container_id_for "${svc}")"
  image_ref="$(image_ref_for "${svc}")"
  before_hash="$(inspect_image_hash "${cid}")"
  if [[ -z "${before_hash}" || -z "${image_ref}" ]]; then
    echo "ERROR: could not determine current image hash or image ref for ${svc}" >&2
    return 1
  fi

  echo "[repave] component=${svc}"
  echo "[repave] service=${svc}"
  echo "[repave] image_ref=${image_ref}"
  echo "[repave] current_image_hash=${before_hash}"

  echo "[repave] pulling fresh image (same tag)..."
  "${compose_phoenix[@]}" pull "${svc}"

  start_s="${SECONDS}"
  echo "[repave] stopping container..."
  "${compose_phoenix[@]}" stop "${svc}"

  echo "[repave] removing container (preserving volumes)..."
  "${compose_phoenix[@]}" rm -f "${svc}"

  echo "[repave] starting new container and waiting for health..."
  "${compose_phoenix[@]}" up -d --wait --wait-timeout 300 "${svc}"

  cid="$(container_id_for "${svc}")"
  if [[ -z "${cid}" ]]; then
    echo "ERROR: compose service '${svc}' did not start (no container id found)" >&2
    return 1
  fi

  # Phoenix has a Docker healthcheck. OTel does not; verify via health_check extension endpoint.
  if [[ "${svc}" == "phoenix" ]]; then
    if ! verify_phoenix_health; then
      echo "ERROR: phoenix health check failed (GET :6006)" >&2
      return 1
    fi
  elif [[ "${svc}" == "otel-collector" ]]; then
    if ! verify_otel_collector_health; then
      echo "ERROR: otel-collector health check failed (GET :13133)" >&2
      return 1
    fi
  fi

  if [[ "${REPAVE_SIMULATE_HEALTH_FAIL_COMPONENT:-}" == "${svc}" ]]; then
    echo "ERROR: simulated health failure for ${svc} (REPAVE_SIMULATE_HEALTH_FAIL_COMPONENT)" >&2
    return 1
  fi

  after_hash="$(inspect_image_hash "${cid}")"
  if [[ -z "${after_hash}" ]]; then
    echo "ERROR: could not inspect new image hash after repave for ${svc}" >&2
    return 1
  fi

  duration_s=$((SECONDS - start_s))
  ts="$(now_utc_iso)"
  update_state "${svc}" "${ts}" "${after_hash}" "healthy"

  echo "[repave] new_image_hash=${after_hash}"
  echo "[repave] OK component=${svc} duration_s=${duration_s}"

  REPAIRED_BEFORE_HASH="${before_hash}"
  REPAIRED_AFTER_HASH="${after_hash}"
  REPAIRED_HEALTH="OK"
  REPAIRED_DURATION="${duration_s}"
  return 0
}

repave_all() {
  local total_duration_s
  ts_start="$(now_utc_iso)"
  ts_compact="$(now_utc_compact)"
  mkdir -p "${reports_dir}"
  report_file="${reports_dir}/repave-${ts_compact}.md"
  start_s="${SECONDS}"

  # Build rows as we go so we can emit a report even on failure.
  rows_json='[]'
  failed_component=""
  failed_reason=""

  finalize_report() {
    local ts_end dur
    ts_end="$(now_utc_iso)"
    dur=$((SECONDS - start_s))

    {
      echo "# Repave Report"
      echo "Timestamp: ${ts_start}"
      echo "Duration: ${dur}s"
      echo ""
      if [[ -n "${failed_component}" ]]; then
        echo "Status: FAILED"
        echo "Failed Component: ${failed_component}"
        echo "Reason: ${failed_reason}"
      else
        echo "Status: OK"
      fi
      echo ""
      echo "| Container | Image Hash Before | Image Hash After | Health | Duration |"
      echo "|-----------|------------------|------------------|--------|----------|"
      printf '%s' "${rows_json}" | jq -r '.[] | "| \(.container) | \(.before) | \(.after) | \(.health) | \(.duration)s |"'
      echo ""
    } > "${report_file}"
  }

  trap 'finalize_report' EXIT

  local order=(spire-server spire-agent keydb spike-keeper-1 spike-nexus mcp-security-gateway mock-mcp-server otel-collector phoenix)
  local i total
  total="${#order[@]}"

  echo "[repave-all] starting (components=${total})"

  for i in "${!order[@]}"; do
    local svc
    svc="${order[$i]}"
    echo "[repave-all] step $((i+1))/${total} repaving ${svc}"

    local ok=0
    if [[ "${svc}" == "phoenix" || "${svc}" == "otel-collector" ]]; then
      if repave_one_phoenix "${svc}"; then ok=1; fi
    else
      if repave_one_main "${svc}"; then ok=1; fi
    fi

    if [[ "${ok}" -ne 1 ]]; then
      failed_component="${svc}"
      failed_reason="health verification failed (see output)"
      echo "ERROR: stop-on-failure: ${svc} failed; aborting remaining repave steps" >&2
      # Add a failure row for visibility.
      rows_json="$(printf '%s' "${rows_json}" | jq -c \
        --arg c "${svc}" \
        --arg b "${REPAIRED_BEFORE_HASH:-}" \
        --arg a "${REPAIRED_AFTER_HASH:-}" \
        --arg h "FAIL" \
        --arg d "${REPAIRED_DURATION:-0}" \
        '. + [{container:$c, before:$b, after:$a, health:$h, duration:($d|tonumber)}]')"
      exit 1
    fi

    rows_json="$(printf '%s' "${rows_json}" | jq -c \
      --arg c "${svc}" \
      --arg b "${REPAIRED_BEFORE_HASH}" \
      --arg a "${REPAIRED_AFTER_HASH}" \
      --arg h "${REPAIRED_HEALTH}" \
      --arg d "${REPAIRED_DURATION}" \
      '. + [{container:$c, before:$b, after:$a, health:$h, duration:($d|tonumber)}]')"

    if [[ "${svc}" == "spike-keeper-1" ]]; then
      if ! wait_for_spike_keeper_shard_resync; then
        failed_component="${svc}"
        failed_reason="failed while waiting for shard re-sync"
        echo "ERROR: stop-on-failure: keeper shard re-sync wait failed; aborting remaining repave steps" >&2
        exit 1
      fi
    fi
  done

  total_duration_s=$((SECONDS - start_s))
  echo "[repave-all] OK duration_s=${total_duration_s} report=${report_file}"
}

repave_single() {
  local component="$1"
  if [[ "${component}" != "keydb" ]]; then
    echo "ERROR: only COMPONENT=keydb is supported for single-component repave in the walking skeleton (got: ${component})" >&2
    exit 2
  fi
  repave_one_main "keydb"
}

case "${arg}" in
  --all)
    repave_all
    ;;
  -h|--help)
    usage
    ;;
  *)
    repave_single "${arg}"
    ;;
esac

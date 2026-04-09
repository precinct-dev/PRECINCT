#!/bin/bash
# KeyDB SVID-to-PEM Helper (RFA-8z8.2)
#
# KeyDB does not speak the SPIRE Workload API natively. This script:
# 1. Fetches the X.509 SVID from SPIRE Agent via the Workload API
# 2. Writes PEM files to a shared volume (/certs/)
# 3. KeyDB reads these PEM files for TLS configuration
#
# Run modes:
# - init: Fetch initial SVID and write PEM files (one-shot, exit 0)
# - watch: Continuously refresh PEM files before SVID expiry (sidecar mode)
#
# The SPIRE Agent socket must be mounted at SPIFFE_ENDPOINT_SOCKET.
# PEM files are written to CERT_DIR (default: /certs).

set -euo pipefail

CERT_DIR="${CERT_DIR:-/certs}"
SVID_CERT="${CERT_DIR}/svid.pem"
SVID_KEY="${CERT_DIR}/svid-key.pem"
TRUST_BUNDLE="${CERT_DIR}/bundle.pem"
REFRESH_INTERVAL="${REFRESH_INTERVAL:-1800}"  # 30 minutes (SVIDs are 1 hour)
MODE="${1:-init}"
SPIRE_AGENT_BIN="${SPIRE_AGENT_BIN:-}"

if [ -z "${SPIRE_AGENT_BIN}" ]; then
    if command -v spire-agent >/dev/null 2>&1; then
        SPIRE_AGENT_BIN="$(command -v spire-agent)"
    elif [ -x "/opt/spire/bin/spire-agent" ]; then
        SPIRE_AGENT_BIN="/opt/spire/bin/spire-agent"
    else
        echo "[ERROR] $(date -u '+%Y-%m-%dT%H:%M:%SZ') spire-agent binary not found in PATH or /opt/spire/bin/spire-agent" >&2
        exit 1
    fi
fi

log_info() {
    echo "[INFO] $(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
}

log_error() {
    echo "[ERROR] $(date -u '+%Y-%m-%dT%H:%M:%SZ') $*" >&2
}

# Fetch SVID from SPIRE Agent and write PEM files
fetch_and_write_svid() {
    log_info "Fetching X.509 SVID from SPIRE Agent..."

    # Use spire-agent api fetch x509 to get the SVID
    # This outputs the SVID cert, key, and trust bundle as PEM files
    local tmpdir
    tmpdir=$(mktemp -d)

    if ! "${SPIRE_AGENT_BIN}" api fetch x509 \
        -socketPath "${SPIFFE_ENDPOINT_SOCKET}" \
        -write "${tmpdir}" 2>/dev/null; then
        log_error "Failed to fetch X.509 SVID from SPIRE Agent"
        rm -rf "${tmpdir}"
        return 1
    fi

    # spire-agent writes: svid.0.pem, svid.0.key, bundle.0.pem
    if [ ! -f "${tmpdir}/svid.0.pem" ] || [ ! -f "${tmpdir}/svid.0.key" ] || [ ! -f "${tmpdir}/bundle.0.pem" ]; then
        log_error "SPIRE Agent did not produce expected PEM files"
        ls -la "${tmpdir}/" >&2
        rm -rf "${tmpdir}"
        return 1
    fi

    # Atomic write: write to temp files, then rename
    mkdir -p "${CERT_DIR}"
    cp "${tmpdir}/svid.0.pem" "${SVID_CERT}.tmp"
    cp "${tmpdir}/svid.0.key" "${SVID_KEY}.tmp"
    cp "${tmpdir}/bundle.0.pem" "${TRUST_BUNDLE}.tmp"

    mv "${SVID_CERT}.tmp" "${SVID_CERT}"
    mv "${SVID_KEY}.tmp" "${SVID_KEY}"
    mv "${TRUST_BUNDLE}.tmp" "${TRUST_BUNDLE}"

    # Set permissions: key file readable only by owner
    chmod 644 "${SVID_CERT}" "${TRUST_BUNDLE}"
    chmod 600 "${SVID_KEY}"

    rm -rf "${tmpdir}"

    log_info "SVID PEM files written to ${CERT_DIR}/"
    log_info "  cert:   ${SVID_CERT}"
    log_info "  key:    ${SVID_KEY}"
    log_info "  bundle: ${TRUST_BUNDLE}"
}

case "${MODE}" in
    init)
        log_info "KeyDB SVID helper: init mode (one-shot)"
        attempt=1
        max_attempts=30
        until fetch_and_write_svid; do
            if [ "${attempt}" -ge "${max_attempts}" ]; then
                log_error "Init failed after ${max_attempts} attempts"
                exit 1
            fi
            attempt=$((attempt + 1))
            sleep 2
        done
        log_info "Init complete. KeyDB can now start with TLS."
        exit 0
        ;;

    watch)
        log_info "KeyDB SVID helper: watch mode (sidecar, refresh every ${REFRESH_INTERVAL}s)"

        # Initial fetch
        attempt=1
        max_attempts=30
        until fetch_and_write_svid; do
            if [ "${attempt}" -ge "${max_attempts}" ]; then
                log_error "Initial watch fetch failed after ${max_attempts} attempts"
                exit 1
            fi
            attempt=$((attempt + 1))
            sleep 2
        done

        # Refresh loop
        while true; do
            sleep "${REFRESH_INTERVAL}"
            log_info "Refreshing SVID..."
            if ! fetch_and_write_svid; then
                log_error "SVID refresh failed! KeyDB is using stale certificates."
                # Do NOT exit -- stale certs are better than no certs.
                # The SVID will be refreshed on the next cycle.
            fi
        done
        ;;

    *)
        log_error "Unknown mode: ${MODE}. Use 'init' or 'watch'."
        exit 1
        ;;
esac

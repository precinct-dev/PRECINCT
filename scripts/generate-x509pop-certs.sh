#!/bin/bash
# Generate x509pop CA and agent certificate for compose SPIRE attestation.
#
# These are NOT SVID certificates. They are node attestation bootstrap material --
# the CA and agent cert exist solely to let the SPIRE agent prove its identity to
# the SPIRE server on startup via x509pop attestation.
#
# Usage:
#   bash scripts/generate-x509pop-certs.sh           # generate if missing
#   FORCE=1 bash scripts/generate-x509pop-certs.sh   # regenerate unconditionally

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/deploy/compose/data/x509pop"

CA_KEY="${OUTPUT_DIR}/ca.key"
CA_CERT="${OUTPUT_DIR}/ca.crt"
CA_BUNDLE="${OUTPUT_DIR}/ca-bundle.crt"
AGENT_KEY="${OUTPUT_DIR}/agent.key"
AGENT_CERT="${OUTPUT_DIR}/agent.crt"

FORCE="${FORCE:-0}"

# --- helpers ---------------------------------------------------------------

log() {
    echo "[x509pop] $*"
}

certs_exist() {
    [ -f "${CA_KEY}" ] && [ -f "${CA_CERT}" ] && [ -f "${AGENT_KEY}" ] && [ -f "${AGENT_CERT}" ]
}

certs_valid() {
    # Verify the CA cert is parseable and the agent cert chains to it.
    openssl x509 -in "${CA_CERT}" -noout 2>/dev/null || return 1
    openssl x509 -in "${AGENT_CERT}" -noout 2>/dev/null || return 1
    openssl verify -CAfile "${CA_CERT}" "${AGENT_CERT}" >/dev/null 2>&1 || return 1
    return 0
}

# --- idempotency check ----------------------------------------------------

if [ "${FORCE}" != "1" ] && certs_exist && certs_valid; then
    log "Certificates already exist and are valid in ${OUTPUT_DIR}"
    log "Skipping generation. Use FORCE=1 to regenerate."
    exit 0
fi

# --- generate --------------------------------------------------------------

log "Creating output directory ${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

# 1. Root CA (self-signed, EC P-256, 10-year validity)
log "Generating self-signed root CA (EC P-256, 3650 days)..."
openssl ecparam -genkey -name prime256v1 -noout -out "${CA_KEY}" 2>/dev/null
openssl req -new -x509 \
    -key "${CA_KEY}" \
    -out "${CA_CERT}" \
    -days 3650 \
    -subj "/CN=PRECINCT Compose x509pop CA/O=PRECINCT/OU=Dev" \
    -sha256

# 2. Agent certificate (signed by CA, EC P-256, 1-year validity)
log "Generating agent certificate (EC P-256, 365 days)..."
openssl ecparam -genkey -name prime256v1 -noout -out "${AGENT_KEY}" 2>/dev/null

AGENT_CSR=$(mktemp)
AGENT_EXT=$(mktemp)
trap 'rm -f "${AGENT_CSR}" "${AGENT_EXT}"' EXIT

openssl req -new \
    -key "${AGENT_KEY}" \
    -out "${AGENT_CSR}" \
    -subj "/CN=spire-agent/O=PRECINCT/OU=Dev" \
    -sha256

# x509pop attestor requires digitalSignature key usage for the challenge-response
# handshake. Without it the SPIRE server rejects the agent with:
#   "certificate not intended for digital signature use"
cat > "${AGENT_EXT}" <<EXTEOF
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EXTEOF

openssl x509 -req \
    -in "${AGENT_CSR}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${AGENT_CERT}" \
    -days 365 \
    -sha256 \
    -extfile "${AGENT_EXT}" 2>/dev/null

# Clean up the serial file that openssl x509 -CAcreateserial produces.
rm -f "${OUTPUT_DIR}/ca.srl"

# 3. CA bundle (explicit copy for SPIRE config clarity)
log "Creating CA bundle..."
cp "${CA_CERT}" "${CA_BUNDLE}"

# 4. Permissions
log "Setting file permissions..."
chmod 600 "${CA_KEY}" "${AGENT_KEY}"
chmod 644 "${CA_CERT}" "${AGENT_CERT}" "${CA_BUNDLE}"

# 5. Verification
log "Verifying certificate chain..."
if openssl verify -CAfile "${CA_CERT}" "${AGENT_CERT}" >/dev/null 2>&1; then
    log "Agent certificate verified against CA."
else
    log "ERROR: Agent certificate verification failed."
    exit 1
fi

log "Certificate generation complete."
log "  CA cert:      ${CA_CERT}"
log "  CA key:       ${CA_KEY}"
log "  CA bundle:    ${CA_BUNDLE}"
log "  Agent cert:   ${AGENT_CERT}"
log "  Agent key:    ${AGENT_KEY}"

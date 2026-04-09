#!/usr/bin/env bash
# Generate self-signed TLS cert for the policy-controller webhook (local dev).
# Creates a K8s TLS secret and patches the ValidatingWebhookConfiguration
# with the CA bundle so the API server trusts the webhook.
set -euo pipefail

NAMESPACE="cosign-system"
SECRET_NAME="policy-controller-webhook-tls"
SERVICE_NAME="policy-controller-webhook"
TMPDIR=$(mktemp -d)

trap 'rm -rf "$TMPDIR"' EXIT

echo "Generating self-signed TLS cert for ${SERVICE_NAME}..."

# Generate CA key and cert
openssl genrsa -out "${TMPDIR}/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "${TMPDIR}/ca.key" \
  -subj "/CN=policy-controller-ca" -days 365 \
  -out "${TMPDIR}/ca.crt" 2>/dev/null

# Generate server key and CSR
openssl genrsa -out "${TMPDIR}/tls.key" 2048 2>/dev/null
openssl req -new -key "${TMPDIR}/tls.key" \
  -subj "/CN=${SERVICE_NAME}.${NAMESPACE}.svc" \
  -out "${TMPDIR}/tls.csr" 2>/dev/null

# Sign server cert with CA (include SANs)
cat > "${TMPDIR}/san.cnf" <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${SERVICE_NAME}
DNS.2 = ${SERVICE_NAME}.${NAMESPACE}
DNS.3 = ${SERVICE_NAME}.${NAMESPACE}.svc
DNS.4 = ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
EOF

openssl x509 -req -in "${TMPDIR}/tls.csr" \
  -CA "${TMPDIR}/ca.crt" -CAkey "${TMPDIR}/ca.key" \
  -CAcreateserial -days 365 \
  -extfile "${TMPDIR}/san.cnf" -extensions v3_req \
  -out "${TMPDIR}/tls.crt" 2>/dev/null

# Wait for namespace to exist
echo "Waiting for namespace ${NAMESPACE}..."
timeout=30
while ! kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; do
  timeout=$((timeout - 1))
  if [ $timeout -le 0 ]; then
    echo "ERROR: namespace ${NAMESPACE} not found"
    exit 1
  fi
  sleep 1
done

# Create/update the TLS secret
kubectl -n "${NAMESPACE}" create secret tls "${SECRET_NAME}" \
  --cert="${TMPDIR}/tls.crt" --key="${TMPDIR}/tls.key" \
  --dry-run=client -o yaml | kubectl apply -f -

# Patch the ValidatingWebhookConfiguration with the CA bundle
CA_BUNDLE=$(base64 < "${TMPDIR}/ca.crt" | tr -d '\n')
kubectl patch validatingwebhookconfiguration policy-controller-validating \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/webhooks/0/clientConfig/caBundle\",\"value\":\"${CA_BUNDLE}\"}]"

echo "TLS cert generated and webhook patched."

#!/bin/sh
# Wrapper script to clear stale agent data and start SPIRE agent.
# Supports both:
# - Compose/local x509pop-style startup (no join token mounted)
# - Local K8s join_token bootstrap (join token mounted at /token/join-token)
# This runs inside the custom spire-agent container with busybox shell.

set -e

echo "SPIRE Agent Wrapper: Starting..."

# Local Docker Desktop K8s reliability:
# The local SPIRE server CA can be recreated (or the bundle can change) between runs.
# If the agent persists state across runs, it can get stuck failing TLS verification
# against a new server CA/bundle. We safely wipe persisted agent state on startup to
# keep k8s-up and demo-k8s deterministic.
rm -f /opt/spire/data/agent/agent-data.json /opt/spire/data/agent/keys.json 2>/dev/null || true

JOIN_TOKEN_FILE="/token/join-token"
if [ -s "$JOIN_TOKEN_FILE" ]; then
    JOIN_TOKEN="$(tr -d '\r\n' < "$JOIN_TOKEN_FILE")"
    if [ -n "$JOIN_TOKEN" ]; then
        echo "Starting SPIRE agent with join_token attestation..."
        exec /opt/spire/bin/spire-agent run \
            -joinToken "$JOIN_TOKEN" \
            -config /opt/spire/conf/agent/agent.conf
    fi
fi

echo "Starting SPIRE agent with configured attestation..."
exec /opt/spire/bin/spire-agent run \
    -config /opt/spire/conf/agent/agent.conf

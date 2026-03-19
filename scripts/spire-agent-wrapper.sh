#!/bin/sh
# Wrapper script to clear stale agent data and start SPIRE agent with x509pop attestation
# This runs inside the custom spire-agent container with busybox shell

set -e

echo "SPIRE Agent Wrapper: Starting..."

# Local Docker Desktop K8s reliability:
# The local SPIRE server CA can be recreated (or the bundle can change) between runs.
# If the agent persists state across runs, it can get stuck failing TLS verification
# against a new server CA/bundle. We safely wipe persisted agent state on startup to
# keep k8s-up and demo-k8s deterministic.
rm -f /opt/spire/data/agent/agent-data.json /opt/spire/data/agent/keys.json 2>/dev/null || true

echo "Starting SPIRE agent with x509pop attestation..."
exec /opt/spire/bin/spire-agent run \
    -config /opt/spire/conf/agent/agent.conf

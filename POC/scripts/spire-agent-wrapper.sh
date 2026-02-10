#!/bin/sh
# Wrapper script to read join token from file and start SPIRE agent
# This runs inside the custom spire-agent container with busybox shell

set -e

echo "SPIRE Agent Wrapper: Starting..."

# Read the join token from the shared volume
if [ ! -f /token/join-token ]; then
    echo "ERROR: Join token file not found at /token/join-token"
    echo "The token generator init container should have created this file"
    exit 1
fi

TOKEN=$(cat /token/join-token)

if [ -z "$TOKEN" ]; then
    echo "ERROR: Join token file is empty"
    exit 1
fi

echo "Successfully read join token from /token/join-token"

# Local Docker Desktop K8s reliability:
# The local SPIRE server CA can be recreated (or the bundle can change) between runs.
# If the agent persists state across runs, it can get stuck failing TLS verification
# against a new server CA/bundle. Since the local overlay always provisions a fresh
# join token, we can safely wipe persisted agent state on startup to keep k8s-up and
# demo-k8s deterministic.
rm -f /opt/spire/data/agent/agent-data.json /opt/spire/data/agent/keys.json 2>/dev/null || true

# Start SPIRE agent with the fresh token (only used if no existing SVID)
echo "Starting SPIRE agent with join token..."
exec /opt/spire/bin/spire-agent run \
    -config /opt/spire/conf/agent/agent.conf \
    -joinToken "$TOKEN"

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

# Note: We do NOT clean agent data. The join token is only needed for initial
# attestation. After the first successful attestation, the agent persists its
# SVID and uses that for future startups. Cleaning the data would force
# re-attestation with a stale token.

# Start SPIRE agent with the fresh token (only used if no existing SVID)
echo "Starting SPIRE agent with join token..."
exec /opt/spire/bin/spire-agent run \
    -config /opt/spire/conf/agent/agent.conf \
    -joinToken "$TOKEN"

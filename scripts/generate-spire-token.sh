#!/bin/sh
# This script runs in a one-shot init container to generate a fresh SPIRE join token
# The token is written to a shared volume for the spire-agent to consume

set -e

echo "SPIRE Token Generator: Starting..."

# Wait for SPIRE server to be healthy
echo "Waiting for SPIRE server to be healthy..."
MAX_WAIT=60
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
    # Try to reach the server health endpoint
    if wget -q -O /dev/null --timeout=2 http://spire-server:8080/live 2>/dev/null; then
        echo "SPIRE server is healthy"
        break
    fi
    echo "Waiting for SPIRE server... (${ELAPSED}s/${MAX_WAIT}s)"
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo "ERROR: SPIRE server did not become healthy within ${MAX_WAIT} seconds"
    exit 1
fi

# Additional wait to ensure server is fully ready for token generation
sleep 5

# Generate a fresh join token using the server's registration API socket
echo "Generating fresh join token from SPIRE server..."
TOKEN_OUTPUT=$(/opt/spire/bin/spire-server token generate \
    -spiffeID spiffe://poc.local/spire-agent \
    -socketPath /tmp/spire-server/private/api.sock \
    -output json)

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to generate join token"
    echo "$TOKEN_OUTPUT"
    exit 1
fi

# Extract token value from JSON
TOKEN=$(echo "$TOKEN_OUTPUT" | grep -o '"value":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo "ERROR: Failed to parse join token from output:"
    echo "$TOKEN_OUTPUT"
    exit 1
fi

# Write token to shared volume
echo "$TOKEN" > /token/join-token
chmod 644 /token/join-token

echo "Successfully generated and saved join token to /token/join-token"
echo "Token: ${TOKEN}"

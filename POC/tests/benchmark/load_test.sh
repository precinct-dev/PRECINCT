#!/usr/bin/env bash
# Load test for the MCP Security Gateway 13-middleware chain (RFA-lo1.2).
#
# Tests the full Docker Compose stack under concurrent load.
# Requires: hey (https://github.com/rakyll/hey) and a running Docker Compose stack.
#
# Usage:
#   bash tests/benchmark/load_test.sh [gateway_url]
#
# Default gateway URL: http://localhost:9090

set -euo pipefail

# Configuration
GATEWAY_URL="${1:-http://localhost:9090}"
CONCURRENCY=100
DURATION=30  # seconds
REQUESTS=0   # 0 = unlimited (use duration)
CONTENT_TYPE="application/json"
SPIFFE_ID="spiffe://poc.local/agents/benchmark/dev"

# MCP JSON-RPC body for a valid tools/list request
REQUEST_BODY='{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}'

echo "================================================================================"
echo "  MCP Security Gateway -- Load Test"
echo "================================================================================"
echo ""
echo "  Target:        ${GATEWAY_URL}"
echo "  Concurrency:   ${CONCURRENCY} connections"
echo "  Duration:      ${DURATION} seconds"
echo "  Request:       POST / (tools/list)"
echo ""

# Check prerequisites
if ! command -v hey >/dev/null 2>&1; then
    echo "ERROR: 'hey' is not installed."
    echo "Install with: go install github.com/rakyll/hey@latest"
    echo "Or:           brew install hey"
    exit 1
fi

# Check gateway is reachable
echo "  Checking gateway health..."
HEALTH_RESP=$(curl -s -o /dev/null -w "%{http_code}" "${GATEWAY_URL}/health" 2>/dev/null || echo "000")
if [ "$HEALTH_RESP" != "200" ]; then
    echo "  WARNING: Gateway health check returned ${HEALTH_RESP}"
    echo "  Is the Docker Compose stack running? (make up)"
    echo "  Continuing anyway..."
    echo ""
else
    echo "  Gateway health: OK (200)"
    echo ""
fi

echo "  Running load test (${DURATION}s at ${CONCURRENCY} concurrent connections)..."
echo "  -------------------------------------------------------------------------"
echo ""

# Run hey with the specified parameters
# -z: duration (30s)
# -c: concurrency (100)
# -m: method (POST)
# -H: headers
# -d: body
# -T: content type
hey \
    -z "${DURATION}s" \
    -c "${CONCURRENCY}" \
    -m POST \
    -H "X-SPIFFE-ID: ${SPIFFE_ID}" \
    -H "Content-Type: ${CONTENT_TYPE}" \
    -d "${REQUEST_BODY}" \
    -T "${CONTENT_TYPE}" \
    "${GATEWAY_URL}/"

echo ""
echo "================================================================================"
echo "  Load test complete."
echo ""
echo "  Key metrics to evaluate:"
echo "  - Requests/sec:        Higher is better (throughput)"
echo "  - Latency percentiles: Lower is better (P50/P95/P99)"
echo "  - Error rate:          Should be 0% (or near 0%)"
echo "  - Status code dist:    Expect mostly 200s"
echo "================================================================================"

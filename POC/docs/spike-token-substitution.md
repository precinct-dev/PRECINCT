# SPIKE Token Substitution Implementation

## Overview

This document describes the SPIKE token substitution feature implemented in the MCP Security Gateway. SPIKE (Secure Programmatic Interface for Key Exchange) enables agents to reference secrets without ever seeing the actual values.

## Token Format

```
$SPIKE{ref:<hex>,exp:<seconds>,scope:<scope>}
```

**Components:**
- `ref`: Hexadecimal reference to the secret (required)
- `exp`: Expiry time in seconds relative to IssuedAt (optional)
- `scope`: Scope in format `location.operation.destination` (optional)

**Regex:**
```go
\$SPIKE\{ref:([a-f0-9]+)(?:,exp:(\d+))?(?:,scope:([\w.]+))?\}
```

## Architecture

### Request Flow

1. Agent sends request with SPIKE token(s) in body: `{"api_key": "$SPIKE{ref:abc123}"}`
2. Gateway's TokenSubstitution middleware:
   - Extracts SPIFFE ID from context
   - Finds all SPIKE tokens in request body
   - For each token:
     - Parse token structure
     - Validate token ownership (SPIFFE ID matches token owner)
     - Validate token expiry
     - Validate token scope
     - Redeem token for actual secret via SPIKE Nexus
   - Substitute all tokens with actual secrets
   - Forward modified request to upstream
3. Upstream receives: `{"api_key": "actual-secret-value"}`
4. Agent never sees the secret value

### Security Properties

1. **Agent isolation**: Agents receive opaque tokens, never see actual credentials
2. **Ownership enforcement**: Each token is bound to a specific SPIFFE ID
3. **Scope limitation**: Tokens are restricted by location, operation, and destination
4. **Time-bounded**: Tokens can expire
5. **Audit trail**: All substitutions logged WITHOUT secret values

## Implementation

### Core Components

**spike_token.go**
- `SPIKEToken`: Token structure with validation metadata
- `ParseSPIKEToken`: Parse token string into structured data
- `ValidateTokenOwnership`: Verify SPIFFE ID matches token owner
- `ValidateTokenExpiry`: Check token hasn't expired
- `ValidateTokenScope`: Verify scope matches request context
- `FindSPIKETokens`: Find all tokens in request body
- `SubstituteTokens`: Replace tokens with secrets

**hooks.go**
- `TokenSubstitution`: Middleware implementing the substitution flow
- `POCSecretRedeemer`: Mock implementation for POC (returns deterministic secrets)
- `SecretRedeemer`: Interface for production SPIKE Nexus integration

### POC vs Production

**POC Implementation:**
- `POCSecretRedeemer` returns mock secrets: `secret-value-for-<ref>`
- IssuedAt set to current time if not present
- Scope validation uses default scope
- Audit logging to stdout

**Production Requirements:**
- Replace `POCSecretRedeemer` with real mTLS client to SPIKE Nexus
- Call `https://spike-nexus:8443/api/v1/redeem` with token ref
- Verify mTLS certificate chain
- Parse SPIKE response for actual secret and metadata
- Persistent audit logging (database or file)
- Metrics for latency and error rates
- Circuit breaker for SPIKE Nexus failures

## Testing

### Unit Tests (spike_token_test.go)

**Token Parsing:**
- Valid tokens with all fields
- Valid tokens with minimal fields
- Invalid tokens (missing ref, wrong format, non-hex ref)

**Validation:**
- Token ownership (matching/mismatching SPIFFE IDs)
- Token expiry (not expired, no expiry, expired)
- Token scope (exact match, location mismatch, operation mismatch)

**Substitution:**
- Single token substitution
- Multiple token substitution
- No tokens (pass-through)

**Audit:**
- Audit events never contain secret values

### Integration Tests (token_substitution_test.go)

**Full Flow:**
- Successful single and multiple token substitution
- Pass-through for non-token content
- Malformed tokens pass through unchanged
- Missing SPIFFE ID rejection
- Token expiry handling

**Token Parsing Edge Cases:**
- Various token formats
- Hex-only enforcement
- Required fields validation

**Security:**
- Secrets never leaked in logs
- Secrets substituted in outbound request
- Original tokens not present in response

## Usage Example

```bash
# Agent makes request with SPIKE token
curl -X POST http://gateway:8080/api/tool \
  -H "X-SPIFFE-ID: spiffe://poc.local/agent/my-agent" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "docker",
    "credentials": "$SPIKE{ref:deadbeef,exp:3600,scope:tools.docker.read}"
  }'

# Gateway logs (stdout):
# Token substitution succeeded: ref=deadbeef, spiffe=spiffe://poc.local/agent/my-agent

# Upstream receives:
# {
#   "tool": "docker",
#   "credentials": "actual-docker-api-key"
# }

# Agent response contains NO secret
```

## Files

- `internal/gateway/middleware/spike_token.go` - Core token handling logic
- `internal/gateway/middleware/spike_token_test.go` - Unit tests
- `internal/gateway/middleware/hooks.go` - Middleware implementation
- `tests/integration/token_substitution_test.go` - Integration tests

## Performance Considerations

- Token regex matching is fast (compiled once)
- Per-request: O(n) where n = number of tokens in body
- Each token requires:
  - Parse: ~1μs
  - Validate: ~1μs
  - Redeem: network RTT to SPIKE Nexus (production)
  - Substitute: O(m) where m = body size

For typical requests with 1-2 tokens, overhead is negligible.

## Next Steps

1. Implement production `SecretRedeemer` with mTLS to SPIKE Nexus
2. Add persistent audit logging
3. Add metrics and monitoring
4. Add circuit breaker for SPIKE Nexus calls
5. Performance testing with realistic workloads

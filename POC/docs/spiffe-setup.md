# SPIFFE ID Setup

This document describes the SPIFFE ID schema and registration process for the reference implementation.

## Overview

The reference implementation uses SPIFFE (Secure Production Identity Framework for Everyone) to provide cryptographic workload identities to all components. Each workload receives a unique SPIFFE ID that encodes its role and purpose.

## SPIFFE ID Schema

Based on Reference Architecture Section 4.5, our schema follows this pattern:

```
spiffe://<trust-domain>/<agent-class>/<agent-purpose>/<environment>
```

### Components

- **trust-domain**: `poc.local` (development trust domain)
- **agent-class**: Workload category
  - `gateways` - MCP security gateway enforcement points
  - `agents/mcp-client` - MCP client agents using external LLMs
  - `agents/autonomous` - Autonomous agents with embedded models
  - `tools` - MCP tool servers
  - `infrastructure` - Supporting services (secrets, logging, etc.)
- **agent-purpose**: Functional identifier (e.g., `dspy-researcher`, `pydantic-researcher`)
- **environment**: Deployment environment (`dev`, `staging`, `prod`)

## Registered SPIFFE IDs

The system includes these workload identities:

| SPIFFE ID | Component | Purpose |
|-----------|-----------|---------|
| `spiffe://poc.local/gateways/mcp-security-gateway/dev` | MCP Security Gateway | Enforces all security controls (auth, authz, content inspection) |
| `spiffe://poc.local/agents/mcp-client/dspy-researcher/dev` | DSPy Agent | Research agent using DSPy framework |
| `spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev` | PydanticAI Agent | Research agent using PydanticAI framework |
| `spiffe://poc.local/tools/docker-mcp-server/dev` | Docker MCP Server | Containerized tool execution service |
| `spiffe://poc.local/infrastructure/spike-nexus/dev` | SPIKE Nexus | SPIFFE-native secrets management |

## Files

- **`config/spiffe-ids.yaml`**: Complete SPIFFE ID schema documentation with selectors and patterns
- **`scripts/register-spire-entries.sh`**: Idempotent registration script for SPIRE server
- **`config/opa/tool_grants.yaml`**: OPA policy data mapping SPIFFE IDs to authorized tools
- **`tests/test_spire_registration.sh`**: Integration test verifying registration

## Registration Process

### Prerequisites

1. Docker Compose environment running with SPIRE server and agent
2. SPIRE server accessible via `/run/spire/sockets/registration.sock`

### Register All Workloads

Execute the registration script inside the SPIRE server container:

```bash
# From the POC directory
docker compose exec spire-server bash < scripts/register-spire-entries.sh
```

The script is **idempotent** - running it multiple times will not create duplicate entries.

### Verify Registration

Check all registered entries:

```bash
docker compose exec spire-server spire-server entry show
```

Check a specific SPIFFE ID:

```bash
docker compose exec spire-server spire-server entry show \
    -spiffeID "spiffe://poc.local/gateways/mcp-security-gateway/dev"
```

### Run Integration Tests

Execute the test suite to verify all registrations:

```bash
./tests/test_spire_registration.sh
```

Expected output:
- All 5+ workload SPIFFE IDs are registered
- Gateway entry has correct Docker label selectors
- Script is idempotent (re-running shows "already exists")

## Docker Label Selectors

Workloads are attested using Docker container labels. Each service in `docker-compose.yaml` should include labels matching the selectors in `config/spiffe-ids.yaml`.

Example for the gateway service:

```yaml
services:
  mcp-gateway:
    labels:
      spiffe-id: mcp-security-gateway
      component: gateway
```

The SPIRE agent's Docker workload attestor matches these labels to issue the correct SPIFFE ID.

## OPA Authorization

The `config/opa/tool_grants.yaml` file defines which SPIFFE IDs can access which MCP tools.

Example grant:

```yaml
tool_grants:
  - spiffe_pattern: "spiffe://poc.local/agents/mcp-client/*-researcher/dev"
    allowed_tools:
      - file_read
      - file_list
      - search
      - http_request
      - database_query
    max_data_classification: internal
```

The MCP Security Gateway queries OPA with:
- The agent's SPIFFE ID (from mTLS certificate)
- The requested tool name
- The data classification level

OPA evaluates the pattern match and returns an authorization decision.

## Pattern Matching

SPIFFE ID patterns support wildcards for flexible authorization:

| Pattern | Matches |
|---------|---------|
| `spiffe://poc.local/gateways/*/dev` | All gateway components |
| `spiffe://poc.local/agents/mcp-client/*/dev` | All MCP client agents |
| `spiffe://poc.local/agents/mcp-client/*-researcher/dev` | Both research agents |
| `spiffe://poc.local/infrastructure/*/dev` | All infrastructure services |

## Troubleshooting

### Entry Creation Fails

**Symptom**: `spire-server entry create` returns an error

**Solutions**:
1. Check SPIRE server logs: `docker compose logs spire-server`
2. Verify socket path: `ls -la /run/spire/sockets/registration.sock` inside container
3. Ensure trust domain matches: `spire-server trustdomain show`

### Workload Cannot Obtain SVID

**Symptom**: Agent logs show "no identity found" or similar

**Solutions**:
1. Verify SPIRE agent is running: `docker compose ps spire-agent`
2. Check workload attestation: `docker compose logs spire-agent | grep attestation`
3. Verify container labels match selectors in registered entry
4. Check that parent SPIFFE ID exists (SPIRE agent's own identity)

### Authorization Denied

**Symptom**: Gateway blocks tool request even though SPIFFE ID seems correct

**Solutions**:
1. Verify exact SPIFFE ID: extract from mTLS certificate and compare to entry
2. Check OPA policy data loaded: `docker compose logs opa | grep tool_grants`
3. Test pattern matching in OPA playground with actual SPIFFE ID
4. Check data classification level is not exceeded

## Security Considerations

### SPIFFE ID Uniqueness

Each workload must have a unique SPIFFE ID. Do not reuse SPIFFE IDs across different workload types.

### Selector Specificity

Use specific Docker label selectors to prevent SPIFFE ID confusion. Avoid overly broad selectors like `docker:label:env:dev` that would match many containers.

### Parent ID Chain

All workload SPIFFE IDs must chain up to a trusted parent (the SPIRE agent). The agent's own identity must chain to the SPIRE server's identity.

### Rotation

SPIRE automatically rotates X.509 SVIDs (default: 1 hour lifetime). Workloads must be configured to fetch updated SVIDs from the Workload API.

## Next Steps

1. **Configure Docker Compose**: Add labels to service definitions matching selectors
2. **Start SPIRE services**: Bring up SPIRE server and agent
3. **Run registration**: Execute `register-spire-entries.sh`
4. **Test**: Run integration tests with `test_spire_registration.sh`
5. **Deploy workloads**: Start agent and gateway containers
6. **Verify**: Check that workloads obtain SVIDs via Workload API

## References

- Reference Architecture Section 4: SPIFFE for Agent Identity
- Reference Architecture Section 6.4: OPA Policy Data Structure
- SPIFFE Specification: https://github.com/spiffe/spiffe
- SPIRE Documentation: https://spiffe.io/docs/latest/spire-about/

# Session Data Management

Operational guide for managing session data stored in KeyDB, including data inventory, retention policy, and GDPR/CCPA right-to-deletion procedures.

## Data Inventory

### What IS Stored

Session data in KeyDB tracks agent behavior for security purposes (cross-request exfiltration detection, rate limiting). The following data elements are stored:

| Key Pattern | Type | Contents | TTL |
|---|---|---|---|
| `session:{spiffe_id}:{session_id}` | STRING (JSON) | Session metadata: session ID, SPIFFE ID, start time, data classifications, risk score, flags | SESSION_TTL (default: 1 hour) |
| `session:{spiffe_id}:{session_id}:actions` | LIST (JSON items) | Tool action records: timestamp, tool name, resource path, classification level, external target flag, destination domain | SESSION_TTL (default: 1 hour) |
| `gdpr:sessions:{spiffe_id}` | SET | Set of session IDs associated with a SPIFFE ID (enables right-to-deletion lookup) | SESSION_TTL (default: 1 hour) |
| `ratelimit:{spiffe_id}:tokens` | STRING | Current token bucket count (float64) | 120 seconds |
| `ratelimit:{spiffe_id}:last_fill` | STRING | Unix nanosecond timestamp of last token refill | 120 seconds |

### What is NOT Stored

The following data is explicitly **not** persisted in KeyDB:

- **Request/response bodies**: Full MCP request and response payloads are never stored. Only the tool name and resource path are recorded.
- **PII from payloads**: No user data, query results, file contents, or API responses are stored.
- **Authentication credentials**: Passwords, API keys, tokens, or certificates are never stored in session data.
- **SPIFFE SVIDs or private keys**: Cryptographic material is managed by the SPIRE agent, not by the session store.

### Data Classification

Session data is classified as **operational security metadata**. It contains:
- Agent identity (SPIFFE ID -- a workload identifier, not a personal identifier)
- Tool invocation patterns (what tools were called, not what they returned)
- Risk scores (computed from tool behavior patterns)
- Rate limiting counters (request frequency, not content)

## Retention Policy

### TTL-Based Automatic Expiration

All session data is subject to automatic TTL-based expiration:

| Data Category | Default TTL | Configuration | Rationale |
|---|---|---|---|
| Session metadata | 1 hour (3600s) | `SESSION_TTL` env var | Sufficient for cross-request exfiltration detection within a session |
| Tool action lists | 1 hour (3600s) | `SESSION_TTL` env var | Aligned with session lifetime |
| GDPR tracking set | 1 hour (3600s) | `SESSION_TTL` env var | Tracking set TTL refreshed on each new session creation |
| Rate limit state | 120 seconds | Hardcoded (2x refill window) | Rate limit buckets auto-expire when idle |

**Configuring Session TTL:**

```bash
# In docker-compose.yml or environment
SESSION_TTL=3600  # seconds (default: 1 hour)
```

### Fallback Behavior

When `KEYDB_URL` is empty (not configured), the gateway falls back to in-memory storage. In-memory data is lost on process restart and is not subject to the retention policy documented here.

## Right-to-Deletion (GDPR Art. 17 / CCPA 1798.105)

### Overview

The right-to-deletion mechanism removes ALL data associated with a given SPIFFE ID from KeyDB. This implements the requirements of:

- **GDPR Article 17**: Right to erasure ("right to be forgotten")
- **CCPA Section 1798.105**: Consumer's right to deletion

### Executing a Deletion

```bash
# Basic usage
make gdpr-delete SPIFFE_ID=spiffe://poc.local/agents/example

# With custom KeyDB URL
KEYDB_URL=redis://keydb:6379 make gdpr-delete SPIFFE_ID=spiffe://poc.local/agents/example
```

**Prerequisites:**
- KeyDB must be running and reachable at the configured `KEYDB_URL`
- Default `KEYDB_URL` is `redis://localhost:6379`

### What Gets Deleted

For the specified SPIFFE ID, the deletion removes:

1. **All session metadata** (`session:{spiffe_id}:{session_id}` for each tracked session)
2. **All tool action lists** (`session:{spiffe_id}:{session_id}:actions` for each tracked session)
3. **Rate limit token count** (`ratelimit:{spiffe_id}:tokens`)
4. **Rate limit last refill timestamp** (`ratelimit:{spiffe_id}:last_fill`)
5. **GDPR tracking set** (`gdpr:sessions:{spiffe_id}`)

### Deletion Output

The command outputs a JSON result for compliance evidence:

```json
{
  "spiffe_id": "spiffe://poc.local/agents/example",
  "sessions_found": 2,
  "keys_deleted": 7,
  "session_ids": ["session-abc", "session-def"],
  "rate_limit_purged": true
}
```

### Edge Cases

- **Non-existent SPIFFE ID**: The deletion is a no-op. No error is returned. `sessions_found` and `keys_deleted` will be 0.
- **Already-expired data**: If session data has already expired via TTL, the deletion will report fewer keys deleted. This is expected and correct -- the data was already removed by TTL expiration.
- **Idempotent**: Running the deletion twice for the same SPIFFE ID is safe. The second run will be a no-op.

## Data Processing Records (GDPR Article 30)

### Processing Activity: Session Context Tracking

| Field | Value |
|---|---|
| **Purpose** | Security monitoring: cross-request exfiltration detection, rate limiting |
| **Legal basis** | Legitimate interest (security of AI agent operations) |
| **Categories of data subjects** | AI agent workloads (identified by SPIFFE ID, not personal identifiers) |
| **Categories of data** | Operational metadata: tool names, resource paths, timestamps, risk scores |
| **Recipients** | Security operations team (via audit logs) |
| **Transfers to third countries** | None (data stored in local KeyDB instance) |
| **Retention period** | Default 1 hour (TTL-based), configurable via SESSION_TTL |
| **Technical measures** | Network isolation (Docker network), no persistence beyond TTL, right-to-deletion mechanism |
| **Organizational measures** | Access restricted to infrastructure operators, deletion audit trail via log output |

### Processing Activity: Rate Limiting

| Field | Value |
|---|---|
| **Purpose** | Preventing abuse and ensuring fair resource allocation |
| **Legal basis** | Legitimate interest (service availability and security) |
| **Categories of data** | Request frequency counters per SPIFFE ID |
| **Retention period** | 120 seconds (auto-expiring) |
| **Technical measures** | Automatic TTL-based expiration, included in right-to-deletion scope |

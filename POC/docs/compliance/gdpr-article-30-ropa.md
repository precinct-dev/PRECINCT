# GDPR Article 30 -- Records of Processing Activities (ROPA)

**Document Version:** 1.0
**Last Updated:** 2026-02-06
**Classification:** Compliance -- Internal
**Applicable Regulation:** EU General Data Protection Regulation (GDPR), Article 30

---

## 1. Controller and Processor Identification

### Data Controller

The **deploying organization** is the data controller under GDPR Article 4(7). The
controller determines the purposes and means of processing personal data within the
agentic AI system.

| Field                        | Value                                         |
|------------------------------|-----------------------------------------------|
| Organization Name            | [DEPLOYING ORGANIZATION NAME]                 |
| Contact Person               | [DATA PROTECTION OFFICER / CONTACT NAME]      |
| Contact Email                | [DPO EMAIL ADDRESS]                           |
| Contact Address              | [REGISTERED ADDRESS]                          |
| EU Representative (Art. 27)  | [IF APPLICABLE -- NON-EU CONTROLLERS ONLY]    |

### Data Processor

The **MCP Security Gateway** acts as a data processor under GDPR Article 4(8). It
processes personal data on behalf of the controller to enforce security policies,
perform audit logging, and maintain session state.

| Field                        | Value                                         |
|------------------------------|-----------------------------------------------|
| Processor Name               | MCP Security Gateway                          |
| Component Version            | v1.0                                          |
| Deployment Model             | Docker Compose (self-hosted)                  |
| Processing Location          | Controller's infrastructure (on-premises or cloud) |

---

## 2. Categories of Data Subjects

Data subjects whose personal data may be processed by the gateway:

| Category                | Identifier Type   | Description                                                                 |
|-------------------------|-------------------|-----------------------------------------------------------------------------|
| AI Agents               | SPIFFE ID         | Agents identified by SPIFFE IDs (e.g., `spiffe://poc.local/agents/mcp-client/dspy-researcher/dev`). SPIFFE IDs are pseudonymous identifiers -- not directly personal data -- but may be linked to individuals in deployment environments where agents are assigned to specific users. |
| Agent Operators         | Indirect          | Individuals who operate or are responsible for agents. Identifiable through SPIFFE ID-to-operator mappings maintained outside the gateway. |

**Note on Pseudonymity:** SPIFFE IDs are cryptographic identities issued by the SPIRE
infrastructure. They do not contain directly identifying information (names, emails).
However, per GDPR Recital 26, pseudonymous data remains personal data if the controller
holds or can reasonably obtain the mapping to natural persons.

---

## 3. Categories of Processing

The gateway performs the following categories of data processing:

### 3.1 Session Creation and Tracking

| Attribute          | Detail                                                      |
|--------------------|-------------------------------------------------------------|
| Data Processed     | SPIFFE ID, session ID (UUID), creation timestamp            |
| Storage Backend    | KeyDB (Redis-compatible in-memory store)                    |
| Key Format         | `session:{spiffe_id}:{session_id}`                          |
| Purpose            | Correlate requests within a single agent session            |
| Legal Basis        | Legitimate interest (Art. 6(1)(f)) -- security monitoring   |

### 3.2 Tool Action Recording

| Attribute          | Detail                                                      |
|--------------------|-------------------------------------------------------------|
| Data Processed     | Tool name, resource path, data classification, destination hostname, action timestamp |
| Storage Backend    | KeyDB (list per session)                                    |
| Key Format         | `session:{spiffe_id}:{session_id}:actions`                  |
| Purpose            | Detect exfiltration patterns across sequential requests     |
| Legal Basis        | Legitimate interest (Art. 6(1)(f)) -- threat detection      |

### 3.3 Risk Score Computation

| Attribute          | Detail                                                      |
|--------------------|-------------------------------------------------------------|
| Data Processed     | Cumulative tool impact scores, session risk score            |
| Storage Backend    | KeyDB (embedded in session JSON)                            |
| Purpose            | Trigger step-up gating for high-risk tool invocations       |
| Legal Basis        | Legitimate interest (Art. 6(1)(f)) -- adaptive security     |

### 3.4 Exfiltration Detection

| Attribute          | Detail                                                      |
|--------------------|-------------------------------------------------------------|
| Data Processed     | Sensitive data access flags, external destination targets    |
| Storage Backend    | KeyDB (derived from session actions)                        |
| Purpose            | Block data exfiltration attempts (read sensitive + send external) |
| Legal Basis        | Legitimate interest (Art. 6(1)(f)) -- data loss prevention  |

### 3.5 Audit Logging

| Attribute          | Detail                                                      |
|--------------------|-------------------------------------------------------------|
| Data Processed     | SPIFFE ID, session ID, decision ID, trace ID, action, result, status code, timestamps, security metadata (tool hash, bundle digest, registry digest), prev_hash chain |
| Storage Backend    | Append-only JSONL file (structured JSON, one entry per line)|
| Purpose            | Compliance evidence, forensic investigation, tamper detection |
| Legal Basis        | Legal obligation (Art. 6(1)(c)) -- regulatory compliance; legitimate interest (Art. 6(1)(f)) -- security monitoring |

### 3.6 Rate Limiting

| Attribute          | Detail                                                      |
|--------------------|-------------------------------------------------------------|
| Data Processed     | SPIFFE ID, request count, window timestamp                  |
| Storage Backend    | KeyDB (rate limit counters)                                 |
| Purpose            | Prevent resource exhaustion by per-agent rate limiting      |
| Legal Basis        | Legitimate interest (Art. 6(1)(f)) -- system availability   |

---

## 4. Purpose of Processing

All processing activities serve the following purposes:

| Purpose                              | Description                                                           | Legal Basis        |
|--------------------------------------|-----------------------------------------------------------------------|--------------------|
| Security Monitoring and Threat Detection | Real-time monitoring of agent behavior to detect malicious patterns, exfiltration attempts, and policy violations | Art. 6(1)(f) |
| Audit Trail for Compliance Evidence  | Maintaining tamper-evident audit logs for regulatory compliance (SOC 2, ISO 27001, CCPA, GDPR) and forensic investigation | Art. 6(1)(c), Art. 6(1)(f) |
| Rate Limiting per Agent Identity     | Enforcing per-agent request rate limits to ensure system availability and prevent denial-of-service | Art. 6(1)(f) |

---

## 5. Data Retention

| Data Category               | Retention Period          | Mechanism                                      | Justification                                    |
|-----------------------------|---------------------------|-------------------------------------------------|--------------------------------------------------|
| Session data (KeyDB)        | Configurable TTL, default 3600s (1 hour) | KeyDB key expiration (`EXPIRE` command)  | Sessions are short-lived; data has no value after TTL |
| Tool action lists (KeyDB)   | Same as session TTL (3600s default) | KeyDB key expiration, co-located with session  | Actions are meaningful only within session context |
| Rate limit counters (KeyDB) | TTL 120s (2 minutes)      | KeyDB key expiration                            | Rate windows are short-lived by design            |
| GDPR session index (KeyDB)  | Same as session TTL       | KeyDB SET with TTL                              | Index for right-to-deletion; expires with sessions |
| Audit logs (JSONL)          | Indefinite (append-only)  | File system retention; external rotation policy | Regulatory requirement for long-term evidence     |

**Right-to-Deletion:** The `make gdpr-delete SPIFFE_ID=...` command implements GDPR
Article 17 right-to-erasure. It deletes all session data, action lists, rate limit
entries, and GDPR session indices for a given SPIFFE ID from KeyDB. Audit logs are
retained for legal compliance (Art. 17(3)(b) -- legal obligation exception).

---

## 6. Technical and Organizational Measures (Article 32 Cross-Reference)

The following measures protect personal data during processing, per GDPR Article 32:

### 6.1 Encryption in Transit

| Measure                         | Implementation                                              |
|---------------------------------|-------------------------------------------------------------|
| mTLS (Gateway to Agents)        | All agent-to-gateway connections use mutual TLS with SPIRE-issued X.509 SVIDs. go-spiffe v2 handles automatic certificate rotation (1-hour default SVID lifetime). |
| mTLS (Gateway to KeyDB)         | Gateway-to-KeyDB connection uses SPIRE SVID-to-PEM init container pattern for mTLS. KeyDB configured with TLS certificates derived from SPIRE SVIDs. |
| mTLS (Gateway to MCP Servers)   | Downstream MCP server connections secured via mTLS where supported. |
| OTel Collector Exception        | The OpenTelemetry Collector receives telemetry data (traces, metrics) without mTLS. This is a documented exception: telemetry data contains operational metrics only, no secrets or PII. Note: gateway does not declare `depends_on` for otel-collector in docker-compose.yml (known gap, bug RFA-39h). |

### 6.2 Encryption at Rest

| Measure                         | Implementation                                              |
|---------------------------------|-------------------------------------------------------------|
| KeyDB Persistence               | If configured, KeyDB persists data to disk. Encryption at rest depends on the underlying storage volume encryption (e.g., LUKS, dm-crypt, cloud provider KMS). |
| Audit Log Files                 | JSONL audit log files stored on the host filesystem. Encryption at rest delegated to host-level disk encryption. |

### 6.3 Access Control

| Measure                         | Implementation                                              |
|---------------------------------|-------------------------------------------------------------|
| SPIFFE-Based Identity           | All inter-service authentication uses SPIFFE IDs verified via X.509 SVIDs. No shared secrets or API keys. |
| OPA Policy Authorization        | Tool access controlled by OPA policies mapping SPIFFE IDs to allowed tools, paths, and destinations. |
| Least Privilege                 | Each agent granted only the specific tools and resources required for its function (tool grants in `config/opa/tool_grants.yaml`). |

### 6.4 Right-to-Deletion Mechanism

| Measure                         | Implementation                                              |
|---------------------------------|-------------------------------------------------------------|
| GDPR Delete Command             | `make gdpr-delete SPIFFE_ID=...` deletes all session data, actions, rate limits, and GDPR indices for a SPIFFE ID. Implemented in `cmd/gdpr-delete/`. |
| CCPA Compliance                 | Same deletion mechanism satisfies CCPA Section 1798.105 right-to-deletion. |

### 6.5 Data Minimization

| Measure                         | Implementation                                              |
|---------------------------------|-------------------------------------------------------------|
| Short-Lived Sessions            | Session data expires automatically (default 1-hour TTL).    |
| Pseudonymous Identifiers        | SPIFFE IDs do not contain directly identifying information. |
| No Payload Storage              | Request/response payloads are not stored; only metadata (tool name, resource, classification) is recorded. |

### 6.6 Integrity Protection

| Measure                         | Implementation                                              |
|---------------------------------|-------------------------------------------------------------|
| Tamper-Evident Audit Chain      | Audit log entries chained with SHA-256 `prev_hash` values. Tampering with any entry breaks the hash chain. |
| Tool Hash Verification          | Tool descriptions verified against SHA-256 hashes from the tool registry to detect tampering. |
| Container Image Signing         | Container images signed with Sigstore cosign for supply chain integrity. |
| SBOM Generation                 | Software Bill of Materials generated for all images (SPDX format). |

---

## 7. Transfers to Third Countries

### Default Configuration

By default, **no personal data is transferred to third countries**. All processing
occurs within the controller's infrastructure:

| Component          | Location                                     | Transfer? |
|--------------------|----------------------------------------------|-----------|
| MCP Security Gateway | Controller's infrastructure                | No        |
| KeyDB              | Controller's infrastructure (Docker Compose) | No        |
| SPIRE Server       | Controller's infrastructure                  | No        |
| Audit Logs         | Controller's infrastructure (local filesystem) | No      |
| OPA Policy Engine  | Controller's infrastructure (embedded)       | No        |

### Documented Risk: Groq API (Deep Scan)

The gateway's deep scan middleware can optionally send request payloads to the **Groq
API** for advanced content analysis. The Groq API is hosted in the **United States**.

| Attribute                   | Detail                                                 |
|-----------------------------|--------------------------------------------------------|
| Destination                 | Groq, Inc. (US-based cloud inference API)              |
| Data Transferred            | MCP tool request payloads (tool name, arguments)       |
| Transfer Mechanism          | HTTPS API call to `api.groq.com`                       |
| Safeguards Required         | Standard Contractual Clauses (SCCs) per GDPR Art. 46(2)(c); supplementary measures per Schrems II |
| Risk Level                  | Medium -- payloads may contain references to data subjects |
| Mitigation                  | Deep scan is optional and disabled when no Groq API key is configured (`GROQ_API_KEY` environment variable). When disabled, the gateway uses local pattern matching only. |

**Controller Responsibility:** If deep scan with Groq API is enabled, the controller
must ensure appropriate transfer safeguards (SCCs, DPIA) are in place before activating
this feature.

---

## Appendix: Cross-References

| Reference                          | Location                                              |
|------------------------------------|-------------------------------------------------------|
| Compliance Report Generator        | `tools/compliance/generate.py` (GDPR Art. 30 mapping) |
| Control Taxonomy                   | `tools/compliance/control_taxonomy.yaml`              |
| Right-to-Deletion Implementation   | `cmd/gdpr-delete/` and `make gdpr-delete`             |
| KeyDB Session Store                | `internal/gateway/middleware/session_store.go`         |
| Audit Logging Middleware           | `internal/gateway/middleware/audit.go`                 |
| SPIRE Configuration                | `docker-compose.yml`, `scripts/register-spire-entries.sh` |
| OPA Policies                       | `config/opa/mcp_policy.rego`                          |
| Tool Registry                      | `config/tool-registry.yaml`                           |

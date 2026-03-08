# Framework Taxonomy Signal Mappings

## Purpose

Document how generic gateway security signal keys are enriched with:

- MITRE ATLAS technique identifiers
- OWASP Agentic Top 10 category identifiers

The gateway emits these values in:

- `security.framework_refs.signal_keys`
- `security.framework_refs.mitre_atlas`
- `security.framework_refs.owasp_agentic_top10`

## Mapping Matrix

| Signal Key | MITRE ATLAS | OWASP Agentic Top 10 |
|---|---|---|
| `prompt.injection_detected` | `AML.T0051` | `ASI01` |
| `prompt.injection_blocked` | `AML.T0051` | `ASI01` |
| `prompt.jailbreak_detected` | `AML.T0054` | `ASI01` |
| `tool.hash_unverified` | `AML.T0010` | `ASI02` |
| `policy.authorization_denied` | `AML.T0102` | `ASI03` |
| `policy.step_up_blocked` | `AML.T0102` | `ASI03` |
| `availability.rate_limited` | `AML.T0029` | `ASI04` |
| `content.blocked` | `AML.T0024`, `AML.T0098` | `ASI05` |
| `data.pii_detected` | `AML.T0024` | `ASI05` |
| `channel.unmediated_injection` | `AML.T0051` | `ASI01` (LLM01: Prompt Injection via unmediated channels) |
| `channel.unbounded_consumption` | `AML.T0029` | `ASI04` (LLM10: Unbounded Consumption) |
| `datasource.integrity_violation` | `AML.T0010`, `AML.T0020` | `ASI01` (LLM01: Prompt Injection via external data poisoning/rug-pull) |
| `escalation.score_threshold` | `AML.T0102` | `ASI03` (LLM06: Excessive Agency via progressive concessions) |
| `principal.authority_confusion` | `AML.T0040` | `ASI02` (LLM02: Sensitive Information Disclosure via authority confusion) |
| `action.irreversible_blocked` | `AML.T0102` | `ASI03` (LLM06: Excessive Agency via irreversible actions) |

## New Capability to OWASP Agentic Top 10 Mapping

The following maps new PRECINCT capabilities (validated against the Agents of Chaos paper, arXiv:2602.20021v1) to the OWASP Agentic Top 10 threat categories:

| PRECINCT Capability | OWASP Agentic Top 10 | Threat Description | Agents of Chaos Case Studies |
|---|---|---|---|
| Channel Mediation | LLM01 (Prompt Injection) | Injection via unmediated external channels (webhooks, queues, scheduled events) | #3 (SSN in email body), #4 (instruction loops) |
| Channel Mediation | LLM10 (Unbounded Consumption) | Resource exhaustion through unmediated channel flooding | #5 (resource exhaustion) |
| Data Source Integrity | LLM01 (Prompt Injection) | External data poisoning via mutable sources (rug-pull attacks) | #10 (mutable external data source) |
| Escalation Detection | LLM06 (Excessive Agency) | Progressive concession accumulation through incremental requests | #7 (concession accumulation) |
| Principal Hierarchy | LLM02 (Sensitive Info Disclosure) | Authority confusion enabling identity spoofing across trust boundaries | #8 (identity spoofing via authority confusion) |
| Irreversibility Gating | LLM06 (Excessive Agency) | Irreversible actions executed without adequate oversight or step-up | #1 (progressive destruction) |

## Machine-Readable Catalogs

- `docs/security/artifacts/mitre-atlas-signal-mapping.v1.json`
- `docs/security/artifacts/owasp-agentic-top10-signal-mapping.v1.json`

## Validation

Run deterministic mapping coverage validation:

```bash
bash tests/e2e/validate_framework_taxonomy_mappings.sh
```

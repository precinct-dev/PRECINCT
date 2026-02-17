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

## Machine-Readable Catalogs

- `docs/security/artifacts/mitre-atlas-signal-mapping.v1.json`
- `docs/security/artifacts/owasp-agentic-top10-signal-mapping.v1.json`

## Validation

Run deterministic mapping coverage validation:

```bash
bash tests/e2e/validate_framework_taxonomy_mappings.sh
```

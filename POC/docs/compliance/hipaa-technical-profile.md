# HIPAA Technical Profile Pack

This document defines the optional HIPAA technical profile for the reference
architecture. It is implementation-focused and limited to technical controls
that can be evidenced from code/runtime artifacts.

## Scope Boundary

- In scope: technical safeguards, runtime enforcement behavior, machine-readable evidence.
- Out of scope: legal interpretation, BAA operations, and non-technical administrative procedures.

## HIPAA Technical Control Mapping

| HIPAA Profile Control Path | HIPAA Safeguard Mapping | Reference Control ID | Evidence Source |
|---|---|---|---|
| Workload identity enforcement | 164.312(d) Person/entity authentication | `GW-AUTH-001` | Audit trace with SPIFFE principal linkage |
| Policy authorization + least privilege | 164.312(a)(1) Access control | `GW-AUTHZ-001` | OPA-mediated decision evidence |
| Prompt/request regulated-data detection | 164.312(a)(1) Access control, minimum-necessary enforcement path | `GW-DLP-001` | DLP request-scan audit evidence |
| Response regulated-data detection | 164.312(e)(1) Transmission security | `GW-DLP-002` | Response firewall and DLP evidence |
| Structured audit traceability | 164.312(b) Audit controls | `GW-AUDIT-001` | Decision/trace/session-linked audit events |
| Encryption in transit | 164.312(e)(1) Transmission security | `GW-TRANS-001` | TLS/mTLS config evidence |
| Session-linked risk context | 164.312(a)(1) Access control | `GW-SESS-001` | Session context runtime evidence |

Source taxonomy:

- `tools/compliance/control_taxonomy.yaml` (`profile_tags: ["hipaa-technical"]`)

## Prompt-Safety Reason-Code Contract (HIPAA Profile)

When `compliance_profile=hipaa` and regulated prompt content is detected:

| Caller intent | Decision | Reason code | Notes |
|---|---|---|---|
| No prompt-action override | `deny` | `PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED` | Raw regulated prompt is blocked. |
| `prompt_action=tokenize` | `quarantine` | `PROMPT_SAFETY_TOKENIZATION_APPLIED` | Request is quarantined until minimum-necessary tokenization workflow is applied. |
| `prompt_action=redact` | `quarantine` | `PROMPT_SAFETY_REDACTION_APPLIED` | Request is quarantined until minimum-necessary redaction workflow is applied. |

Implementation source:

- `internal/gateway/phase3_runtime_helpers.go` (`evaluatePromptSafety`)

## K8s-First Implementation Notes

- Kubernetes is the authoritative production posture for this profile.
- Profile evidence should be generated from K8s-backed runtime logs/config artifacts.
- Keep enforcement-profile startup gates enabled for regulated environments.

## Non-K8s Adaptation Guidance

- Preserve enforced behavior parity for SPIFFE identity, policy authorization, and audit traceability.
- Use compensating controls documented in `docs/architecture/non-k8s-cloud-adaptation-guide.md`.
- Do not claim equivalence where K8s-native invariants are not replaced with auditable controls.

## Evidence Outputs

The compliance exporter emits:

- Global evidence bundles:
  - `compliance-evidence.v2.json`
  - `compliance-evidence.v2.csv`
- HIPAA profile evidence bundles (when HIPAA-tagged controls exist):
  - `compliance-evidence.hipaa.json`
  - `compliance-evidence.hipaa.csv`

The HIPAA bundles are machine-readable subsets filtered from controls tagged
`hipaa-technical` in the taxonomy.

# UASGS Canonical Contract Set v2.4

This document freezes the canonical UASGS control-plane contract set for version `2.4.0`.
It is the normative reference for endpoint contracts, wire schemas, versioning policy,
and backward-compatibility mappings.

## Normative Artifacts

- Manifest: `POC/contracts/v2.4/manifest.v2.4.json`
- Request schema: `POC/contracts/v2.4/schemas/plane_request_v2.schema.json`
- Response schema: `POC/contracts/v2.4/schemas/plane_decision_v2.schema.json`
- Connector manifest schema: `POC/contracts/v2.4/schemas/connector_manifest_v1.schema.json`
- Connector authority lifecycle doc: `POC/contracts/v2.4/connector-conformance-authority.v2.4.md`
- RuleOps lifecycle doc: `POC/contracts/v2.4/ruleops-lifecycle.v2.4.md`
- Reason-code catalog: `POC/contracts/v2.4/reason-code-catalog.v2.4.json`
- Reason-code policy: `POC/contracts/v2.4/reason-code-catalog.v2.4.md`
- Changelog: `POC/contracts/v2.4/CHANGELOG.md`

## Versioning Policy

`2.4.0` follows semantic versioning for contract artifacts:

- `MAJOR`: breaking endpoint/path, payload, or semantic behavior changes.
- `MINOR`: backward-compatible endpoint, field, or reason-code additions.
- `PATCH`: non-breaking clarifications, examples, and metadata fixes.

## Canonical Endpoints

| Plane | Canonical path | Compatibility aliases | Request schema | Response schema |
|---|---|---|---|---|
| Ingress | `/v1/ingress/submit` | `/v1/ingress/admit` | `plane_request_v2` | `plane_decision_v2` |
| Context | `/v1/context/admit` | none | `plane_request_v2` | `plane_decision_v2` |
| Model | `/v1/model/call` | `/v1/chat/completions` | `plane_request_v2` | `plane_decision_v2` |
| Tool | `/v1/tool/execute` | none | `plane_request_v2` | `plane_decision_v2` |
| Loop | `/v1/loop/check` | none | `plane_request_v2` | `plane_decision_v2` |

### Connector Governance Endpoints

- `/v1/connectors/register`
- `/v1/connectors/validate`
- `/v1/connectors/approve`
- `/v1/connectors/activate`
- `/v1/connectors/revoke`
- `/v1/connectors/status`
- `/v1/connectors/report`

### RuleOps Governance Endpoints

- `/admin/dlp/rulesets`
- `/admin/dlp/rulesets/active`
- `/admin/dlp/rulesets/create`
- `/admin/dlp/rulesets/validate`
- `/admin/dlp/rulesets/approve`
- `/admin/dlp/rulesets/sign`
- `/admin/dlp/rulesets/promote`
- `/admin/dlp/rulesets/rollback`

### Approval Capability Governance Endpoints

- `/admin/approvals/request`
- `/admin/approvals/grant`
- `/admin/approvals/deny`
- `/admin/approvals/consume`

## Compatibility Matrix And Migration Mapping

| Legacy behavior/path | Canonical v2.4 path | Mapping | Migration guidance |
|---|---|---|---|
| `/v1/ingress/admit` | `/v1/ingress/submit` | payload-compatible envelope/policy shape | Move clients to `/submit`; keep `/admit` as compatibility alias during migration window |
| `/v1/chat/completions` (OpenAI compat) | `/v1/model/call` | maps provider mediation metadata to canonical reason codes | New integrations should call `/v1/model/call` for explicit policy envelope semantics |
| Generic middleware `code` (13-chain errors) | `reason_code` (control-plane decisions) | both retained by domain: chain errors for proxy/tool path, `reason_code` for plane governance | SDKs should preserve both fields and route by endpoint family |

### Ingress Runtime Guard Notes

The canonical ingress endpoint (`/v1/ingress/submit`) and compatibility alias
(`/v1/ingress/admit`) execute identical runtime checks:

- Source principal consistency checks (`INGRESS_SOURCE_UNAUTHENTICATED`)
- Replay detection keyed by `event_id` (or `nonce`) (`INGRESS_REPLAY_DETECTED`)
- Freshness window checks using `event_timestamp` (`INGRESS_FRESHNESS_STALE`)

### Horizontal Hardening Notes

v2.4 governance endpoints (`/v1/*`, `/admin/dlp/rulesets*`, `/admin/approvals*`, `/admin/loop/runs*`)
run through gateway middleware identity/policy hooks. Request failures use the
unified gateway error envelope (`code`, `middleware`, `middleware_step`,
`decision_id`, `trace_id`), while plane policy decisions continue to use the
canonical `plane_decision_v2` reason-code response.

## Contract Drift Notes (POC As-Built To Canonical)

1. Ingress endpoint naming drift:
   `admit` path exists in POC; canonical path is `submit`.
2. Model endpoint has dual surfaces:
   OpenAI compatibility path and canonical plane endpoint.
3. Error taxonomy split:
   middleware error `code` vs plane `reason_code` is intentional and documented.

## Example Artifacts

- `POC/contracts/v2.4/examples/ingress_admit_request.example.json`
- `POC/contracts/v2.4/examples/ingress_allow_response.example.json`
- `POC/contracts/v2.4/examples/model_deny_response.example.json`

## Changelog Entry

Contract changelog entries are maintained in `POC/contracts/v2.4/CHANGELOG.md`.

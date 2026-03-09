---
id: OC-p5s6
title: "Update POC Technical Documentation"
status: closed
priority: 1
type: task
labels: [agents-of-chaos, documentation, rejected]
parent: OC-mfwm
created_at: 2026-03-08T02:46:35Z
created_by: ramirosalas
updated_at: 2026-03-08T17:35:04Z
content_hash: "sha256:fc08f02cf95b31c71d3b1ddfcc4e430e4a95baac229edcfca943d6c71ef78782"
closed_at: 2026-03-08T17:35:04Z
close_reason: "Implemented and merged to main. nd not updated at delivery time -- closed retroactively."
---

## Description
## User Story

As a developer working on PRECINCT, I need the POC technical documentation (ARCHITECTURE.md, api-reference.md, configuration-reference.md) updated to cover all new adapters, endpoints, headers, error codes, and configuration options so that the documentation is accurate and complete.

## Context

POC docs at POC/docs/:
- ARCHITECTURE.md (v1.0) -- comprehensive technical architecture
- api-reference.md (v2.4.0) -- HTTP API reference with endpoints, headers, error codes
- configuration-reference.md -- config options and env vars

Current api-reference.md documents: POST / (main JSON-RPC), POST /data/dereference, GET /health, plus DLP RuleOps admin endpoints. Headers: X-SPIFFE-ID, X-Session-ID. Error codes: 25 codes across middleware steps.

## Implementation

POC/docs/ARCHITECTURE.md updates:
- Document Discord adapter (POC/ports/discord/) in adapter pattern section
- Document Email adapter (POC/ports/email/) in adapter pattern section
- Document DataSourceDefinition in tool registry section
- Document escalation detection in session context section (step 8)
- Document principal hierarchy resolution (after step 3)
- Document irreversibility classification (in step-up gating, step 9)
- Add ADR: "Why communication channel mediation addresses agent-to-agent bypass"

POC/docs/api-reference.md updates:
- New endpoints: /discord/send, /discord/webhooks, /discord/commands, /email/send, /email/webhooks, /email/list, /email/read
- New request headers: (none -- these are response/proxy headers)
- New response/proxy headers: X-Precinct-Principal-Level, X-Precinct-Principal-Role, X-Precinct-Principal-Capabilities, X-Precinct-Auth-Method, X-Precinct-Reversibility, X-Precinct-Backup-Recommended, X-Precinct-Escalation-Score
- New error codes: data_source_hash_mismatch (step 5, HTTP 403), unregistered_data_source (step 5, HTTP 403), principal_level_insufficient (step 6, HTTP 403), irreversible_action_denied (step 9, HTTP 403)
- Update error code catalog table with new codes
- Update middleware chain table if behaviors are extended

POC/docs/configuration-reference.md updates:
- New config sections: data_sources (in tool-registry.yaml), escalation thresholds (in risk_thresholds.yaml), principal_mapping (SPIFFE path prefix to role), reversibility_overrides (per-tool reversibility scores)
- New env vars: UNKNOWN_DATA_SOURCE_POLICY (default: "flag")
- New config fields: EscalationWarningThreshold, EscalationCriticalThreshold, EscalationEmergencyThreshold, UnknownDataSourcePolicy

## Key Files

- POC/docs/ARCHITECTURE.md (modify)
- POC/docs/api-reference.md (modify)
- POC/docs/configuration-reference.md (modify)

## Testing

- Documentation review: all new items present
- Cross-reference: terms match code exactly (no renamed columns or headers)

## Acceptance Criteria

1. ARCHITECTURE.md documents Discord and Email adapters, data source registry, escalation detection, principal hierarchy, irreversibility classification
2. ARCHITECTURE.md includes ADR for channel mediation
3. api-reference.md documents 7 new endpoints
4. api-reference.md documents 7 new headers (6 proxy + 1 response)
5. api-reference.md documents 4 new error codes in error code catalog
6. configuration-reference.md documents new config sections and env vars
7. All technical terms match code exactly

## Dependencies

Should wait until implementation epics have committed code to ensure accuracy.

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T17:35:04Z status: in_progress -> closed

## Links
- Parent: [[OC-mfwm]]

## Comments

### 2026-03-08 -- PM-Acceptor Rejection

EXPECTED: (1) ARCHITECTURE.md documents principal hierarchy resolution and irreversibility classification; (2) ARCHITECTURE.md includes ADR for channel mediation (agent-to-agent bypass rationale); (3) api-reference.md documents all 7 specified response headers: X-Precinct-Principal-Level, X-Precinct-Principal-Role, X-Precinct-Principal-Capabilities, X-Precinct-Auth-Method, X-Precinct-Reversibility, X-Precinct-Backup-Recommended, X-Precinct-Escalation-Score; (4) api-reference.md documents all 4 required error codes: data_source_hash_mismatch (step 5), unregistered_data_source (step 5), principal_level_insufficient (step 6), irreversible_action_denied (step 9); (5) configuration-reference.md documents UNKNOWN_DATA_SOURCE_POLICY env var, principal_mapping config section, and reversibility_overrides config section.

DELIVERED: ARCHITECTURE.md adds sections 3.7 (Port Adapters: Discord + Email -- PASS), 3.8 (Data Source Integrity -- PASS), 3.9 (Escalation Detection -- PASS). Principal hierarchy and irreversibility classification are entirely absent. No ADR for channel mediation was added. api-reference.md adds all 7 endpoint entries (AC3 PASS) and 3 response headers (X-Precinct-Data-Classification, X-Precinct-Escalation-Score, X-Precinct-Escalation-Flag) -- none of the 6 principal/auth/reversibility/backup headers from the AC, and Escalation-Flag is not in the AC list. Error code table adds data_source_hash_mismatch and unregistered_data_source (correct) plus escalation_emergency and discord_signature_invalid (not required by AC) but omits principal_level_insufficient and irreversible_action_denied entirely. configuration-reference.md adds escalation thresholds (section 9), data source registry (section 10), and port adapter env vars (section 11) -- UNKNOWN_DATA_SOURCE_POLICY is missing, principal_mapping and reversibility_overrides sections are absent.

GAP: AC1 FAIL (missing principal hierarchy and irreversibility classification in ARCHITECTURE.md); AC2 FAIL (no ADR for channel mediation); AC4 FAIL (delivered 3 wrong/partial headers instead of the 7 specified: X-Precinct-Principal-Level, X-Precinct-Principal-Role, X-Precinct-Principal-Capabilities, X-Precinct-Auth-Method, X-Precinct-Reversibility, X-Precinct-Backup-Recommended are all absent); AC5 FAIL (missing principal_level_insufficient and irreversible_action_denied error codes); AC6 FAIL (UNKNOWN_DATA_SOURCE_POLICY env var missing, principal_mapping and reversibility_overrides sections missing); AC7 FAIL (wrong headers and error codes delivered).

FIX: (a) Add to ARCHITECTURE.md: a principal hierarchy section describing SPIFFE-path-to-role mapping and level resolution logic, an irreversibility classification subsection in the step-up gating area (step 9), and an ADR (e.g. ADR-011) for channel mediation with agent-to-agent bypass rationale. (b) Replace/extend the Response Headers table in api-reference.md to include all 7 AC-specified headers with descriptions. (c) Add to api-reference.md error catalog: principal_level_insufficient (step 6, HTTP 403, middleware principal_hierarchy) and irreversible_action_denied (step 9, HTTP 403, middleware step_up_gate). (d) Add to configuration-reference.md section 11: UNKNOWN_DATA_SOURCE_POLICY env var (default: "flag"). Add new sections for principal_mapping (SPIFFE path prefix to role mapping) and reversibility_overrides (per-tool reversibility scores).

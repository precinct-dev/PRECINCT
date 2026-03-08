---
id: OC-lvda
title: "Update Security and Compliance Documentation"
status: in_progress
priority: 1
type: task
labels: [agents-of-chaos, documentation, delivered]
parent: OC-mfwm
created_at: 2026-03-08T02:46:54Z
created_by: ramirosalas
updated_at: 2026-03-08T04:13:18Z
content_hash: "sha256:027a535ec232cb1292f61fa1d291a3253746ac0e3960c6ecfcbe8c869f6f8c63"
---

## Description
## User Story

As a compliance auditor reviewing PRECINCT, I need the security and compliance documentation updated with the new controls and the 'Agents of Chaos' paper citation so that the compliance evidence reflects the expanded threat coverage.

## Context

Security docs:
- precinct-security-review.md -- security review and threat coverage matrix
- precinct-stride-pasta-assurance.md -- STRIDE/PASTA threat modeling
- POC/docs/security/framework-taxonomy-signal-mappings.md -- maps capabilities to OWASP Agentic Top 10
- POC/docs/security/baseline.md -- security controls baseline

## Implementation

precinct-security-review.md updates:
- Add 'Agents of Chaos' paper as external threat validation source
- Map each of the 16 case studies to STRIDE categories:
  - Spoofing: Case Study #8 (identity spoofing)
  - Tampering: Case Study #10 (mutable resource)
  - Repudiation: covered by audit logging
  - Information Disclosure: Case Study #3 (SSN in email)
  - Denial of Service: Case Studies #4 (loop), #5 (DoS)
  - Elevation of Privilege: Case Studies #1, #7 (progressive destruction)
- Update threat coverage matrix with new controls

precinct-stride-pasta-assurance.md updates:
- Add new controls: channel mediation, data source integrity, escalation detection, principal hierarchy, irreversibility gating
- Update control evidence baseline with new middleware behaviors

POC/docs/security/framework-taxonomy-signal-mappings.md updates:
- Map new capabilities to OWASP Agentic Top 10:
  - Channel mediation -> LLM01 (Prompt Injection via unmediated channels), LLM10 (Unbounded Consumption via message loops)
  - Data source integrity -> LLM01 (Prompt Injection via external data poisoning)
  - Escalation detection -> LLM06 (Excessive Agency via progressive concessions)
  - Principal hierarchy -> LLM02 (Sensitive Information Disclosure via authority confusion)
  - Irreversibility gating -> LLM06 (Excessive Agency via irreversible actions)

POC/docs/security/baseline.md updates:
- Add new security controls: channel mediation, data source integrity, escalation detection, principal hierarchy, irreversibility gating
- Add evidence pointers (which middleware step, which config)

## Key Files

- precinct-security-review.md (modify)
- precinct-stride-pasta-assurance.md (modify)
- POC/docs/security/framework-taxonomy-signal-mappings.md (modify)
- POC/docs/security/baseline.md (modify)

## Testing

- Documentation review: all new controls documented, paper citation accurate
- Cross-reference: STRIDE mappings consistent, OWASP mappings appropriate

## Acceptance Criteria

1. Security review document cites 'Agents of Chaos' (arXiv:2602.20021v1) as external threat validation
2. All 16 case studies mapped to STRIDE categories
3. Threat coverage matrix updated with new controls
4. STRIDE/PASTA document includes 5 new controls
5. Framework taxonomy mappings updated for OWASP Agentic Top 10
6. Security baseline includes new controls with evidence pointers
7. All documentation internally consistent

## Dependencies

Should wait until implementation epics are at least designed.

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes
COMPLETED: All 4 documentation files updated with Agents of Chaos coverage. Commit 1923e10 pushed to story/OC-lvda.

## History
- 2026-03-08T04:08:21Z status: in_progress -> in_progress

## Links
- Parent: [[OC-mfwm]]

## Comments

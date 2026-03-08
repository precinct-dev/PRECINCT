---
id: OC-v1yl
title: "Update Reference Architecture Document"
status: in_progress
priority: 1
type: task
labels: [agents-of-chaos, documentation, delivered]
parent: OC-mfwm
created_at: 2026-03-08T02:46:13Z
created_by: ramirosalas
updated_at: 2026-03-08T03:54:44Z
content_hash: "sha256:06bec602a5f6c8ae86afb461e230e44b950a3910ab00711c59cd907677829f5a"
---

## Description
## User Story

As a security architect reviewing PRECINCT, I need the reference architecture document to cover the new capabilities and cite the 'Agents of Chaos' paper so that the strategic-level documentation accurately reflects the system's threat coverage.

## Context

The reference architecture document lives at precinct-reference-architecture.md in the project root. It covers PRECINCT's strategic architecture, threat model, and the 5 governed planes (Context, Policy, Identity, Control Loop, Ingress).

New sections needed for capabilities implemented in this initiative.

## Implementation

Update precinct-reference-architecture.md with:

1. New section: "Communication Channel Mediation"
   - Port adapter pattern for Discord and email
   - How mediation addresses direct channel bypass (Case Studies #4, #10, #11)
   - DLP, rate limiting, and session context applied to messaging

2. New section: "Data Source Integrity"
   - DataSourceDefinition with content hash verification
   - Mutable policy enforcement (block_on_change, flag_on_change, allow)
   - How this addresses Case Study #10 (mutable external resource trust)

3. New section: "Escalation Detection"
   - Concession accumulator tracking cumulative destructiveness
   - Configurable thresholds (Warning/Critical/Emergency)
   - How this addresses Case Studies #1 and #7

4. New section: "Principal Hierarchy"
   - SPIFFE-to-role resolution (6 levels)
   - Metadata enrichment headers
   - How this addresses Case Study #8

5. New section: "Irreversibility Classification"
   - Four-tier reversibility taxonomy
   - Automatic step-up for irreversible actions
   - Backup recommendation header

6. Update threat model section:
   - Reference 'Agents of Chaos' paper (Shapira et al., 2026, arXiv:2602.20021v1)
   - Add threat-to-defense mapping table

7. Update governed planes:
   - Context plane: add escalation tracking
   - Control loop plane: add irreversibility gating
   - Ingress plane: add communication channel mediation

## Key Files

- precinct-reference-architecture.md (modify)

## Testing

- Document review: all new sections present, paper citation accurate
- Cross-reference: new sections consistent with implementation details

## Acceptance Criteria

1. Five new sections added (channel mediation, data source integrity, escalation detection, principal hierarchy, irreversibility)
2. Threat model updated with paper citation (arXiv:2602.20021v1)
3. Governed planes updated (Context, Control Loop, Ingress)
4. All technical terms match ARCHITECTURE.md exactly
5. Document coherent and internally consistent

## Dependencies

Should wait until implementation epics are at least designed.

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T03:52:05Z status: open -> in_progress

## Links
- Parent: [[OC-mfwm]]

## Comments

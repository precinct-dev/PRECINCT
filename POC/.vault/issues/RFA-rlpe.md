---
id: RFA-rlpe
title: "Release Sanity: Security and Robustness Hardening"
status: closed
priority: 0
type: epic
labels: [release-sanity, security-hardening, accepted]
created_at: 2026-03-10T04:55:56Z
created_by: ramirosalas
updated_at: 2026-03-10T13:49:33Z
content_hash: "sha256:5d8df5c5df01a8355141ead27ff6324414ca853efb04320b29e6072b78ecea85"
closed_at: 2026-03-10T13:49:33Z
close_reason: "All child release-sanity stories accepted after final Makefile release validation."
---

## Description
## Context
- Goal: Track release-blocking security and robustness gaps found during the March 10, 2026 sanity review.
- Scope: Compose production-intent path, admin/authz defaults, connector governance, shell mediation, policy integrity, SDK bypasses, supply-chain/deployment contradictions, and release-quality gates.
- Why now: These findings affect the credibility of the reference architecture ahead of release and external review.

## Acceptance Criteria
1. Every child bug has a concrete fix path, explicit verification steps, and closure evidence.
2. Release-facing deployment paths no longer ship obvious insecure/demo defaults.
3. Security-control claims in code, SDKs, docs, and manifests are internally consistent.

## Testing Requirements
- Child bugs must include targeted tests or verification commands.
- Release sign-off should include config rendering checks, static checks, and relevant integration coverage.

## nd_contract
status: new

### evidence
- Created from release sanity review on 2026-03-10.

### proof
- [ ] Pending bug triage and remediation

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-10T13:49:33Z status: open -> closed

## Links


## Comments

## Epic Closure
- All child release-sanity stories under `RFA-rlpe` are now closed.
- Final release validation evidence:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `/tmp/story-evidence-final-acceptance.log` -> delivered story evidence validation PASS across the accepted set.

## nd_contract
status: accepted

### evidence
- All child issues under `RFA-rlpe` are closed and accepted, with `RFA-ir6i` closed as superseded by `RFA-yekm`.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `/tmp/story-evidence-final-acceptance.log` -> PASS across the delivered-story evidence validation loop.

### proof
- [x] AC #1: Every child bug now has closure evidence in nd.
- [x] AC #2: Release-facing deployment and demo/test paths passed the final Makefile validation run.
- [x] AC #3: The tracked code, SDK, docs, and manifest gaps were fixed and accepted through the nd workflow.

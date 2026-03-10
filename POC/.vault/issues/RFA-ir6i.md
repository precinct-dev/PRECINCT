---
id: RFA-ir6i
title: "Gateway body capture breaks session continuity by regenerating session IDs"
status: closed
priority: 0
type: bug
parent: RFA-rlpe
created_at: 2026-03-10T08:44:40Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:49Z
content_hash: "sha256:d1da1976a95ed35f28de2911cf0732885d23c4d310477c2405cdec4105cc73d1"
closed_at: 2026-03-10T13:48:49Z
close_reason: "Superseded by accepted fix RFA-yekm covering the same session continuity defect."
---

## Description
## Description
## Context (Embedded)
- Problem: During live compose retest of the release demo, step-up escalation never accumulated across repeated requests that intentionally reused the same caller session. The gateway middleware in  generated a fresh internal session ID for each request instead of honoring inbound  and  headers.
- Evidence:
  - Manual compose replay using repeated  requests with the same owner SPIFFE ID and an explicit  showed the audit log recording different  values per request.
  - Because the gateway lost caller session continuity, the escalation counter never crossed the denial threshold and destructive follow-up actions were not blocked by the intended session-aware step-up behavior.
  - After fixing the middleware to preserve inbound session headers and rebuilding the gateway image, the same replay produced a deterministic  with  from  on the destructive request.
- Impact: Session-aware controls become materially weaker in the live runtime because risk accumulation, escalation, and related audit correlation are fragmented across synthetic per-request sessions. This is both a security regression and a release-credibility issue because the demo path claims session-aware protections that were not actually operating end to end.
- Scope: This story is about preserving externally supplied session identity at the gateway boundary and proving that the real compose stack enforces escalation across multiple requests in one caller session.

## Acceptance Criteria
1. The gateway preserves inbound caller session identity by honoring  first, then , and only generates a new session ID when neither header is present.
2. A regression test covers the middleware contract so future refactors cannot silently replace caller-provided session IDs.
3. A real integration test against the running gateway proves that repeated requests in one shared session accumulate step-up state and deny the destructive follow-up with the expected step-up response.
4. Delivery evidence includes the failing live symptom and the passing post-fix replay or equivalent test output.

## Testing Requirements
- Unit: add or update middleware tests for inbound session header preservation.
- Integration: add or update a real  test that exercises repeated requests against the live gateway with a shared session ID and proves the denial threshold is reached.
- Runtime: reproduce the live compose symptom before the fix if possible, then rerun the replay or Usage: make <target>

  [36mattestation-resign                 [0m Re-sign attestation artifacts (generates keypair if missing)
  [36mci                                 [0m Full CI pipeline (lint + test + conformance + build)
  [36mclean                              [0m Full cleanup (containers, volumes, build artifacts, logs, SPIRE state)
  [36mcompose-down                       [0m Tear down Docker Compose stack and volumes
  [36mdemo-cli                           [0m Run all CLI demos (agw CLI, operate, compliance, repave, upgrade)
  [36mdemo-compose                       [0m Run E2E demo (Docker Compose; leaves stack running for inspection)
  [36mdemo-k8s                           [0m Run E2E demo (K8s; leaves cluster running for inspection)
  [36mdemo                               [0m Run E2E demo (Docker Compose + K8s)
  [36mdown                               [0m Stop Docker Compose stack
  [36mhelp                               [0m Show available targets
  [36mk8s-check-config                   [0m Check K8s overlay gateway config for drift (CI use)
  [36mk8s-down                           [0m Tear down local K8s deployment
  [36mk8s-opensearch-down                [0m Remove only OpenSearch extension resources from local K8s deployment
  [36mk8s-opensearch-up                  [0m Deploy local K8s stack plus optional OpenSearch observability extension
  [36mk8s-sync-config                    [0m Sync K8s overlay gateway config from canonical config/ source
  [36mk8s-up                             [0m Deploy to local K8s (Docker Desktop)
  [36mk8s-validate                       [0m Validate K8s overlays and Phase 3 gateway wiring (offline-first)
  [36mlint                               [0m Run linters
  [36mlogs                               [0m Tail gateway logs
  [36mobservability-down                 [0m Stop both observability backends (preserves data)
  [36mobservability-reset                [0m Destroy all observability backend data (Phoenix + OpenSearch)
  [36mobservability-up                   [0m Start both observability backends (Phoenix + OpenSearch)
  [36mopenclaw-demo                      [0m Run OpenClaw E2E against live Compose stack (brings stack up if needed)
  [36mopensearch-down                    [0m Stop OpenSearch + Dashboards stack (preserves OpenSearch data)
  [36mopensearch-reset                   [0m Stop OpenSearch + Dashboards and destroy all OpenSearch data
  [36mopensearch-seed                    [0m Seed OpenSearch index template and import PRECINCT dashboard objects
  [36mopensearch-up                      [0m Start OpenSearch + Dashboards + audit forwarder (optional compliance/forensics profile)
  [36mopensearch-validate                [0m Validate OpenSearch health, template, and dashboard API
  [36mphoenix-down                       [0m Stop Phoenix stack (preserves trace data)
  [36mphoenix-reset                      [0m Stop Phoenix stack and destroy trace data
  [36mphoenix-up                         [0m Start standalone Phoenix + OTel collector (persistent traces)
  [36mproduction-readiness-validate      [0m Strict production-readiness security evidence gate
  [36mreadiness-state-validate           [0m Validate readiness docs/state snapshot against live nd status
  [36mrepave                             [0m Repave containers (COMPONENT=<name> for single, default: all)
  [36mstory-evidence-validate            [0m Validate evidence paths in an nd story (STORY_ID=<id>)
  [36mtest                               [0m Run all tests (Go packages + integration/unit suites + OPA)
  [36mtracker-surface-validate           [0m Audit active release workflow surfaces for stale tracker references
  [36mup                                 [0m Start Docker Compose stack (waits for all services healthy)
  [36mupgrade-all                        [0m Upgrade all non-pinned components (VERIFY=1)
  [36mupgrade-check                      [0m Show current vs latest versions (containers, Go modules, Python deps)
  [36mupgrade                            [0m Upgrade a single component (COMPONENT=<name> VERIFY=1)
  [36mvalidate                           [0m Run all offline validation suites (SUITE=compose|k8s to filter)-driven validation after the fix.
- Commands to run:
  - ok  	github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware	0.672s
  - === RUN   TestStepUpGating_EscalationSessionPersists
    step_up_gating_integration_test.go:342: Gateway not ready: service http://localhost:9090/health not ready after 30s
--- FAIL: TestStepUpGating_EscalationSessionPersists (30.16s)
FAIL
FAIL	github.com/RamXX/agentic_reference_architecture/POC/tests/integration	30.686s
FAIL
  - relevant compose or demo command proving the fixed behavior in the real stack

## Delivery Requirements
- Append the exact replay or demo command and the decisive  evidence.
- Reference the code paths and test paths that enforce the contract.
- Update the final  to  and add label  when implementation proof is attached.

## nd_contract
status: new

### evidence
- Created from release-validation retest after a live compose replay showed step-up escalation failing to accumulate because gateway-generated session IDs replaced caller-provided session IDs.

### proof
- [ ] AC #1: Gateway preserves inbound caller session identity before generating a fallback session ID.
- [ ] AC #2: Middleware regression tests cover inbound session header preservation.
- [ ] AC #3: Live integration coverage proves shared-session escalation reaches the denial path.
- [ ] AC #4: Delivery notes include failing and passing runtime evidence for the session continuity defect.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-10T13:48:49Z status: open -> closed

## Links
- Parent: [[RFA-rlpe]]

## Comments


## Acceptance Criteria


## Design


## Notes


## History


## Links


## Comments

## Resolution
- Closed as superseded by `RFA-yekm`, which carries the implemented and accepted session continuity fix for the same defect.
- No separate implementation was required once `RFA-yekm` landed and passed the final Makefile release validation.

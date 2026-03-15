# DLP RuleOps Lifecycle v2.4

This document defines the governed lifecycle for DLP rulesets in v2.4.

## Objective

Provide a deterministic and auditable lifecycle for DLP rulesets, including:

- draft authoring and validation
- explicit approval and signing
- controlled canary promotion
- rollback to prior active baseline

## Lifecycle States

`draft -> validated -> approved -> signed -> canary -> active`

Additional terminal/history states:

- `superseded`
- `rolled_back`

## Endpoints

- `GET /admin/dlp/rulesets`
- `GET /admin/dlp/rulesets/active`
- `POST /admin/dlp/rulesets/create`
- `POST /admin/dlp/rulesets/validate`
- `POST /admin/dlp/rulesets/approve`
- `POST /admin/dlp/rulesets/sign`
- `POST /admin/dlp/rulesets/promote`
- `POST /admin/dlp/rulesets/rollback`

## Promotion Constraints

Promotion is denied unless all constraints are satisfied:

1. ruleset is approved (`approved_by`, `approved_at` present)
2. ruleset is signed
3. signature matches the manager-computed expected signature

Unsigned or invalidly signed rulesets cannot be promoted.

## Canary And Rollback

- `promote` with `mode=canary` moves a signed ruleset into canary state without replacing active baseline.
- `promote` with `mode=active` activates the ruleset and records previous active baseline for rollback.
- `rollback` reverts canary or active promotions to a safe prior state.

## Auditability

Every lifecycle decision emits append-only audit events with:

- operation name (`ruleops.*`)
- decision (`allow` / `deny`)
- reason
- correlation fields (`decision_id`, `trace_id`)

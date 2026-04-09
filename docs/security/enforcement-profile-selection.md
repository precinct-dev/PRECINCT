# Enforcement Profile Selection Guide

This guide explains when to use each runtime enforcement profile and the
tradeoffs operators should consider.

## Profiles

1. `dev`
   - Startup mode: permissive
   - Best for: local development and rapid debugging
   - Includes: HIPAA prompt-safety gate can still be exercised in local testing when `ENFORCE_HIPAA_PROMPT_SAFETY_GATE=true`
   - Tradeoff: allows controlled fallback behavior that is not acceptable for production

2. `prod_standard`
   - Startup mode: strict (fail closed)
   - Best for: staging and production baselines
   - Tradeoff: stricter startup requirements; misconfigurations fail startup immediately

3. `prod_regulated_hipaa`
   - Startup mode: strict (fail closed)
   - Best for: regulated workloads requiring HIPAA prompt-safety gates
   - Tradeoff: strongest guardrails with highest setup/config discipline

## Safe Selection Defaults

- If `SPIFFE_MODE=dev`, default to `ENFORCEMENT_PROFILE=dev`.
- If `SPIFFE_MODE=prod`, default to `ENFORCEMENT_PROFILE=prod_standard`.
- Upgrade to `prod_regulated_hipaa` when regulated prompt-safety controls are required.

Those defaults are now implemented directly by the runtime config loader, so the
safe-selection guidance matches what the gateway actually does when
`ENFORCEMENT_PROFILE` is omitted.

`prod_regulated_hipaa` remains the strict regulated bundle because it adds
startup conformance guarantees and automatic HIPAA-oriented model defaults.
The `dev` profile can still demonstrate HIPAA prompt-safety behavior for local
testing, but it does not claim regulated-runtime readiness.

## Conformance Diagnostics

At startup, the gateway emits a concise conformance report with pass/fail
results per critical control. The report includes:

- profile and startup gate mode
- pass/fail result for each required control
- warnings/failures for fallback-to-default events

In strict profiles, unsafe fallback-to-default behavior is treated as a startup
error and fails closed.

## Setup Wizard

`make setup` now prompts for enforcement profile selection and explains the
security/usability tradeoffs before writing `.env`.

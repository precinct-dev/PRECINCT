# App Pack Authoring Guide

## Goal

Help application teams onboard to the gateway without modifying upstream app source and without coupling app behavior into gateway core.

Canonical strategy/tradeoff/greenfield reference:

- `docs/sdk/no-upstream-mod-integration-playbook.md`

## Authoring Steps

1. Define pack metadata (`pack.v1.json`):
   - app identity/version
   - upstream source baseline
   - route/protocol map
   - required security controls
   - runtime validation commands
2. Implement SDK adaptation:
   - request shape normalization
   - model/provider/API-key reference plumbing
   - gateway headers/correlation propagation
3. Add conformance checks for both runtimes:
   - Compose flow
   - K8s flow
4. Validate with:
   - `bash tests/e2e/validate_app_integration_pack_model.sh`
   - `bash tests/e2e/validate_gateway_bypass_case26.sh`
   - `make demo-compose`
   - `make demo-k8s`

## SDK Conformance Notes

- Case-26 bypass behavior parity across Go/Python and Compose/K8s is defined in:
  - `docs/sdk/gateway-bypass-case26-conformance.md`

## Generic Migration Recipe

Use this sequence to migrate any agent app into pack+SDK adaptation without changing core:

1. Identify app defaults currently hardcoded outside a pack:
   - model/provider defaults
   - tool allow/deny assumptions
   - guardrail and timeout assumptions
   - runtime-specific hints (compose vs k8s)
2. Map each default to one of:
   - `pack.v1.json` adapter contract field (declarative)
   - SDK hook implementation (imperative)
3. Keep gateway core untouched:
   - no app-specific route logic in core middleware
   - no app-specific decision code branching in core
4. Enforce with validators:
   - schema/required-field validator (`validate_app_integration_pack_model.sh`)
   - runtime conformance validator (for app-specific critical paths)
5. Prove portability:
   - one passing Compose artifact
   - one passing K8s artifact

Reference mapping for OpenClaw defaults:

- `docs/sdk/openclaw-defaults-to-pack-sdk-map.md`

## Responsibilities

### App Team

- Maintain pack metadata and SDK adapter behavior for their app.
- Maintain app-specific integration tests.

### Platform/Core Team

- Maintain generic control planes and core invariants.
- Maintain pack schema/validator and conformance gates.

## Anti-Patterns

- Adding app-specific hardcoded route logic directly into core middleware.
- Allowing SDK to bypass gateway policy decisions.
- Shipping pack changes without Compose and K8s evidence.

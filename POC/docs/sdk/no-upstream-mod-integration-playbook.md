# No-Upstream-Modification Integration Playbook

## Purpose

Provide a claim-ready implementation guide for onboarding insecure agent applications into this reference architecture without changing upstream source code.

This playbook is app-agnostic. OpenClaw is the hostile reference app used to prove the pattern, not a special-case exception in core.

## Zero-Upstream-Modification Model

The integration model uses three layers with strict boundaries:

1. Core gateway controls (agnostic, mandatory):
   - identity, authn/authz, policy, DLP, prompt-safety, tool governance, rate limits, circuit breaking, and audit.
2. App integration pack (declarative app metadata):
   - route/protocol mapping, expected controls, runtime hints, validation commands.
3. SDK adaptation layer (imperative app shaping):
   - request normalization, default model/provider shaping, API key reference insertion, correlation/header propagation.

Security outcomes are enforced in core. Packs and SDKs can shape requests but cannot bypass policy decisions.

## Boundary Invariants

- No app-specific route logic in core middleware.
- No app-specific allowlist/denylist policy branching in core.
- No direct model/tool bypass path around gateway mediation.
- Upstream source remains independent (for OpenClaw: `~/workspace/openclaw`).
- Compose and Kubernetes validations are both required for promotion-eligible integration packs.

## Tradeoff Matrix

| Strategy | Best fit | Pros | Risks | Recommendation |
|---|---|---|---|---|
| pack-only | Protocol/header adaptation is small and mostly declarative | Low implementation cost, easy portability | Client ergonomics may remain weak; app defaults can drift into ad-hoc wrappers | Use for simple integrations with minimal client behavior |
| sdk-only | App already has stable route/protocol contract and only client ergonomics need shaping | Fast for one app, explicit client behavior | Higher chance of hidden per-app logic and weaker governance of app assumptions | Use only when pack metadata adds little value |
| hybrid pack+sdk | Most real-world insecure apps with both declarative and imperative adaptation needs | Best separation of concerns, strongest governance, reusable conformance | Slightly more upfront effort and artifact discipline | Default and recommended path |

## Greenfield Build Path

Use this for new applications built directly for this architecture:

1. Define threat model and trust boundaries:
   - identify model/tool/context/control surfaces and expected deny reasons.
2. Author initial app integration pack:
   - `pack.v1.json` with route map, security expectations, runtime validation commands.
3. Build SDK adapter:
   - normalize app payloads, wire correlation/headers, and map app defaults into pack fields.
4. Wire integration tests:
   - include allow/deny coverage for prompt injection, tool misuse, and gateway-bypass attempts.
5. Enforce conformance:
   - run deterministic schema/runtime validators before any promotion decision.
6. Produce promotion evidence:
   - capture command logs and artifacts for Compose and Kubernetes campaigns.

## Validation Gates

### Compose Validation Gates

- `bash tests/e2e/validate_app_integration_pack_model.sh`
- `bash tests/e2e/validate_gateway_bypass_case26.sh`
- `make demo-compose`

### Kubernetes Validation Gates

- `bash tests/e2e/validate_app_integration_pack_model.sh`
- `bash tests/e2e/validate_gateway_bypass_case26.sh`
- `make demo-k8s`

## What We Can Claim

- The core remains app-agnostic while app-specific adaptation lives in pack/SDK layers.
- Target apps can be onboarded with no upstream source modifications when they stay behind gateway mediation.
- Prompt injection and tool hijack risk is substantially reduced relative to direct app operation, because all model/tool/control surfaces are policy-mediated and audited.

## Residual Risks and Limits

- This architecture reduces risk; it does not eliminate all attack paths.
- Weak or stale pack metadata can degrade expected protection outcomes.
- Promotion claims are only as strong as current evidence freshness for both Compose and Kubernetes.

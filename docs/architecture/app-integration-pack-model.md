# App Integration Pack Model

## Purpose

This model keeps the gateway core application-agnostic while allowing teams to onboard specific agent applications through thin, explicit adaptation layers.

For a full strategy guide (no-upstream-mod model, tradeoffs, and greenfield path), see:

- `docs/sdk/no-upstream-mod-integration-playbook.md`

## Boundary Rules

### Core (must stay agnostic)

- Identity, authn/authz, policy, DLP, prompt-safety, rate-limit, circuit-breaker, audit, and secret mediation controls.
- Generic transport and plane contracts (ingress/model/tool/context/loop).
- No app-branded policy exceptions or hardcoded app protocol assumptions.

### SDK Adaptation Layer

- Developer ergonomics: model defaults, API key reference resolution, headers, retries, and client-side normalization.
- Converts app-native requests into gateway-compatible requests.
- Must not bypass gateway controls or embed allowlist/policy decisions that belong in core.

### App Integration Pack

- App-specific route map, protocol adaptation metadata, and required security expectations.
- Optional adapter implementation package that maps app payloads to generic gateway contracts.
- Runtime and conformance test vectors for Compose and K8s.

## Reference Layout

```
packs/
  <app-name>/
    pack.v1.json
    README.md
    tests/
      compose/
      k8s/
```

## Reference Case-Study Pack

The current hostile-app case study pack metadata is published at:

- `packs/<reference-app>/pack.v1.json`

This pack defines app-specific routes and required security control expectations without changing upstream source.

## Migration Guidance (from core-specific handlers)

1. Keep existing behavior stable.
2. Move app-specific route/protocol mapping into pack metadata + adapter packages.
3. Preserve core control invariants and keep all policy/security decisions in core middleware.
4. Gate migration with Compose and K8s runtime evidence.

## Non-Negotiable Invariants

- Upstream app source remains independent.
- Gateway mediation remains mandatory for model/tool/control paths.
- No direct bypass introduced in either Compose or K8s deployment modes.

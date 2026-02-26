# OpenClaw Source Intake Baseline (2026-02-16)

## Purpose
Establish implementation-truth intake for secure OpenClaw porting using live source at `/Users/ramirosalas/workspace/openclaw`, and map required wrapper boundaries into `POC`.

## Upstream Baseline (Latest Verified)
- Repository: `/Users/ramirosalas/workspace/openclaw`
- Branch: `main`
- Commit: `5d40d47501c19465761f503ebb12667b83eea84f`
- Commit timestamp (UTC): `2026-02-16T18:09:49Z`

## Scope
- Source-grounded intake of OpenClaw control surfaces (HTTP, WS, auth, tool policy, sandbox/exec approvals).
- Mapping into `POC` enforcement boundaries for fail-closed mediation.
- Baseline risk/control dataset for comparative posture reporting.
- Evidence-drift reconciliation input for `RFA-l6h6.6.16`.

## Source Inventory

### HTTP Control Surfaces
- OpenResponses endpoint: `/Users/ramirosalas/workspace/openclaw/docs/gateway/openresponses-http-api.md`
  - `POST /v1/responses` is documented as disabled-by-default and gateway-auth protected.
- Tool invocation endpoint: `/Users/ramirosalas/workspace/openclaw/docs/gateway/tools-invoke-http-api.md`
  - `POST /tools/invoke` is documented as always enabled, gateway-auth and policy-gated.
- Runtime routing/auth wiring: `/Users/ramirosalas/workspace/openclaw/src/gateway/server-http.ts`
  - HTTP handlers call gateway auth decisions and enforce dedicated handling for responses/tools endpoints.
- Dangerous HTTP-tool deny defaults: `/Users/ramirosalas/workspace/openclaw/src/security/dangerous-tools.ts`
  - default deny list includes `sessions_spawn`, `sessions_send`, `gateway`, `whatsapp_login`.

### Auth and Identity Surfaces
- Auth modes and enforcement paths: `/Users/ramirosalas/workspace/openclaw/src/gateway/auth.ts`
  - Modes: `token`, `password`, `trusted-proxy`.
  - Optional `allowTailscale` behavior and trusted-proxy header validation paths.

### Sandboxing / Exec-Approval Surfaces
- Exec approvals: `/Users/ramirosalas/workspace/openclaw/src/infra/exec-approvals.ts`
  - default security posture and allowlist model for command approvals.
- Sandbox tool policy resolution: `/Users/ramirosalas/workspace/openclaw/src/agents/sandbox/tool-policy.ts`
  - layered policy sources and deny/allow expansion behavior.
- Security operator guidance: `/Users/ramirosalas/workspace/openclaw/docs/gateway/security/index.md`
  - explicitly states sandboxing is opt-in; documents high-risk operating modes.

## Wrapper Mapping to POC

| OpenClaw Surface | Upstream File(s) | Required POC Wrapper Boundary | Primary Evidence Target |
|---|---|---|---|
| `POST /v1/responses` | `docs/gateway/openresponses-http-api.md`, `src/gateway/openresponses-http.ts`, `src/gateway/server-http.ts` | POC HTTP adapter with mandatory identity/policy/audit mediation | integration allow+deny tests, reason-code checks |
| `POST /tools/invoke` | `docs/gateway/tools-invoke-http-api.md`, `src/gateway/tools-invoke-http.ts` | POC tool mediation + dangerous-tool deny parity (fail-closed) | adversarial deny tests for unauthorized + dangerous-tool requests |
| WS control-plane methods/events | `src/gateway/protocol/*`, `src/gateway/server/ws-connection/*` | POC WS mediation adapter with authz gates + canonical denials | WS auth/authz matrix tests |
| Gateway auth modes | `src/gateway/auth.ts` | POC identity admission mapping (SPIFFE/authz policy), no bypass path | 401/403/allow matrix |
| Sandbox/exec approval pathways | `src/infra/exec-approvals.ts`, `src/agents/sandbox/tool-policy.ts` | POC hardened execution controls and runbook constraints | policy conformance and drill evidence |

## Baseline Risk Notes (for Comparative Report)
- Upstream includes strong controls but also operator-selectable insecure modes; security posture can degrade by configuration drift.
- `POST /tools/invoke` exposure is constrained by policy, but still a high-value abuse path requiring strict wrapper enforcement and adversarial tests.
- Sandbox/exec approval protections are opt-in or profile-dependent in several paths and must be normalized to fail-closed behavior for this port.

## Evidence Drift Observation
- Accepted story `RFA-l6h6.5.1` references OpenClaw adapter/test files that are currently not present under `POC`.
- This is tracked as bug `RFA-l6h6.6.16` and is a mandatory blocker before final comparative acceptance.

## Newly Discovered Gaps (Latest-Source Intake Cycle)
- None. No new latest-source intake defects were identified beyond already-tracked and accepted reconciliation items.

## Immediate Execution Implications
- `RFA-l6h6.6.12` and `RFA-l6h6.6.13` can proceed in parallel after this intake is accepted.
- `RFA-l6h6.6.14` must remain blocked on:
  - HTTP lane completion
  - WS lane completion
  - evidence drift reconciliation (`RFA-l6h6.6.16`).

## Command Snapshot
- `rg -n "POST /v1/responses|POST /tools/invoke|Gateway auth|sandbox|exec approval|trusted-proxy|allowTailscale" ...`
- `bd show RFA-l6h6.5.1 --json | jq -r '.[0].notes' | rg -n "POC/internal/integrations/openclaw|openclaw_walking_skeleton" -S`
- `rg --files /Users/ramirosalas/workspace/agentic_reference_architecture/POC | rg "openclaw|integrations/openclaw|openclaw_walking" -S`

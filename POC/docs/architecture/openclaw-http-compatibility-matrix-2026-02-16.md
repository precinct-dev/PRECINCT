# OpenClaw HTTP Compatibility Matrix (2026-02-16)

## Upstream Baseline
- Source repo: `/Users/ramirosalas/workspace/openclaw`
- Branch: `main`
- Commit: `5d40d47501c19465761f503ebb12667b83eea84f`
- Commit timestamp (UTC): `2026-02-16T18:09:49Z`

## Scope
- Upstream reference endpoints:
  - `/v1/responses`
  - `/tools/invoke`
- Secure wrapper implementation:
  - `POC/internal/gateway/openclaw_http_adapter.go`
  - `POC/internal/integrations/openclaw/http_adapter.go`

## Separation Model
- Upstream OpenClaw code remains isolated in `~/workspace/openclaw`.
- Security enforcement remains centralized in `POC` wrapper and middleware chain.
- Porting changes are applied in wrapper contracts, not by embedding upstream runtime logic into `POC`.

## Latest-Source Delta Notes
- No new upstream HTTP endpoint was introduced in this baseline beyond documented `/v1/responses` and `/tools/invoke` control surfaces.
- Compatibility posture remains stable for this cycle; wrapper hardening deltas remain intentional (policy mediation + deterministic deny semantics).

## Routing and Enforcement
| Surface | Upstream OpenClaw behavior | POC wrapped behavior | Compatibility | Security posture delta |
|---|---|---|---|---|
| `POST /v1/responses` | Accepts OpenResponses request and executes agent/model flow | Accepts normalized OpenResponses payload and routes through model-plane policy + mediated provider egress | Partial parity | Enforces PRECINCT Gateway reason-coded model policy decisions before any egress |
| `POST /tools/invoke` | Resolves tool list and executes tool directly in gateway runtime | Accepts invoke payload and evaluates tool-plane admission through wrapper policy contracts | Partial parity | No direct tool execution path from OpenClaw-facing endpoint; policy decision only |
| Authn/Authz | Gateway auth modes (token/password/trusted proxy) | SPIFFE identity middleware + plane-specific policy reasons | Intentional divergence | Stronger identity binding in wrapper path |
| Denials | Endpoint-specific error payloads | Canonical PRECINCT Gateway reason codes (`X-Precinct-Reason-Code`) + decision/trace correlation IDs | Compatible with documented hardening | Deterministic deny telemetry for audit and incident triage |

## `/v1/responses` Request/Response Mapping
| OpenClaw field | Wrapped mapping | Notes |
|---|---|---|
| `model` | preserved | Required; used by model-plane policy |
| `input` (string or message array) | normalized into OpenAI-compatible `messages` | Supports message text parts and function call output text |
| `instructions` | prepended as `system` message | Preserved |
| `max_output_tokens` | mapped to `max_tokens` | Preserved |
| `stream=true` | rejected (`400`) | Intentional hardening in this phase (non-stream wrapper only) |
| response output | mapped to OpenResponses resource envelope | Returns assistant text or function-call item |

## `/tools/invoke` Request/Response Mapping
| OpenClaw field | Wrapped mapping | Notes |
|---|---|---|
| `tool` | `policy.attributes.tool_name` | Required |
| `action` | `policy.action` | Defaults to `tool.execute` |
| `args` | carried in metadata (`openclaw_args`) | No direct execution in wrapper |
| `sessionKey` | envelope session ID fallback | Preserved for audit correlation |
| `approval_capability_token` / `step_up_token` / `approval_token` | consumed by tool-plane step-up validation | Enables bounded privileged actions when policy requires step-up |

## Intentional Hardening Differences
1. `POST /tools/invoke` does not directly execute tools in this lane; it returns policy admission decisions through the secure wrapper.
2. Dangerous HTTP tools are blocked deterministically (`TOOL_CLI_COMMAND_DENIED`) even when requested explicitly.
3. `POST /v1/responses` currently supports non-stream mode only (`stream=false`) to keep the mediation/audit chain deterministic in this lane.

## Wiring Evidence (No Direct Bypass)
- OpenClaw endpoints are handled inside the existing gateway middleware chain:
  - `SPIFFEAuth` -> `AuditLog` -> `ToolRegistryVerify` -> `OPA` passthrough for plane routes -> `StepUpGating` -> `...` -> `proxyHandler` route dispatch.
- Route dispatch:
  - `POC/internal/gateway/gateway.go` invokes `handleOpenClawHTTPEntry(...)`.
- Model path:
  - `handleOpenClawResponses(...)` -> `evaluateModelPlaneDecision(...)` -> `executeModelEgress(...)`.
- Tool path:
  - `handleOpenClawToolsInvoke(...)` -> `evaluateOpenClawToolRequest(...)`.

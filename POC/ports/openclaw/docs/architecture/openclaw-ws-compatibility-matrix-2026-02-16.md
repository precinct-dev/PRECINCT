# OpenClaw WS Compatibility Matrix (2026-02-16)

## Upstream Baseline
- Source repo: `/Users/ramirosalas/workspace/openclaw`
- Branch: `main`
- Commit: `5d40d47501c19465761f503ebb12667b83eea84f`
- Commit timestamp (UTC): `2026-02-16T18:09:49Z`

## Scope
- Wrapper endpoint: `GET /openclaw/ws` (websocket upgrade).
- Goal: mediate required OpenClaw gateway control-plane flows through POC security controls.
- Upstream references:
  - `/Users/ramirosalas/workspace/openclaw/src/gateway/server/ws-connection/message-handler.ts`
  - `/Users/ramirosalas/workspace/openclaw/src/gateway/protocol/schema.ts`
  - `/Users/ramirosalas/workspace/openclaw/src/gateway/auth.ts`

## Separation Model
- OpenClaw WS protocol evolution is tracked from upstream source, while enforcement remains in `POC` wrapper controls.
- `POC` does not run upstream gateway internals directly; it mediates and constrains required WS control operations through fail-closed contracts.

## Latest-Source Delta Notes
- Latest upstream WS stack includes richer handshake/auth/client metadata paths than the wrapper allowlist intentionally exposes.
- Current wrapper scope remains intentionally reduced to required secure control methods (`connect`, `health`, `devices.list`, `devices.ping`) with explicit deny-by-default for all others.

## Method-Level Allow/Deny Mapping

| Method | Wrapper Behavior | Allow Conditions | Deny Conditions | Reason Code(s) |
|---|---|---|---|---|
| `connect` | Session bootstrap and capability negotiation | Valid SPIFFE identity in request context, role in `{operator,node}`, optional device auth token when device id is declared | Missing/invalid SPIFFE context, invalid role, device id without token | `WS_AUTH_INVALID` |
| `health` | Deterministic health response frame with correlation IDs | Must be sent after a successful `connect` | First frame is not `connect`, malformed request frame | `WS_CONNECT_REQUIRED`, `WS_PAYLOAD_MALFORMED` |
| `devices.list` | Returns bound device list for current session | `operator` role or `devices:read` scope | Role/scope does not permit device listing | `WS_METHOD_FORBIDDEN` |
| `devices.ping` | Returns deterministic `pong` for specified device id | `operator` role or `devices:write` scope and `params.device_id` present | Role/scope disallowed or missing `params.device_id` | `WS_METHOD_FORBIDDEN`, `WS_PAYLOAD_MALFORMED` |
| other methods | Fail-closed deny | N/A | Any unsupported method | `WS_METHOD_FORBIDDEN` |

## Security/Hardening Deltas vs Upstream

| Area | Upstream OpenClaw | POC Wrapper Hardening |
|---|---|---|
| Authentication source | Shared-secret/password/trusted-proxy and device auth combinations | Mandatory POC middleware identity gate (SPIFFE context) before WS mediation, then role/device token checks |
| Unsupported methods | Broad protocol surface with many control and session operations | Explicit allowlist (`connect`, `health`, `devices.list`, `devices.ping`) and fail-closed deny for everything else |
| Correlation | Connection and frame metadata present upstream | Every mediated response carries `decision_id` + `trace_id`; every WS action is audit-logged with action-level correlation |
| Origin handling | Browser-origin checks in selected paths | Wrapper origin check enforces same-host origin when `Origin` is present |

## Notes
- This lane intentionally focuses on required control-plane methods for secure parity.
- Remaining upstream WS surface can be added only through explicit wrapper allowlist expansion with tests and policy evidence.

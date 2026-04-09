# OpenClaw Integration Pack

This pack records OpenClaw-specific adaptation metadata while preserving gateway core agnosticism.

Primary manifest:

- `pack.v1.json`

Adapter contract sections in `pack.v1.json`:

- `adapter_contract.model_routing`
- `adapter_contract.tool_registration`
- `adapter_contract.gateway_guardrails`
- `adapter_contract.runtime_profile_hints`

Validation:

- `bash tests/e2e/validate_app_integration_pack_model.sh`

---

## Endpoint Inventory

Two HTTP endpoints and one WebSocket endpoint are mediated by the PRECINCT Gateway wrapper. All traffic flows through the full 13-layer middleware chain before reaching any upstream service.

### HTTP Endpoints

| Endpoint | Upstream behavior | Wrapper behavior | Key hardening delta |
|---|---|---|---|
| `POST /v1/responses` | Accepts OpenResponses request and executes agent/model flow | Routes through model-plane policy and mediated provider egress | Stream mode rejected (`400`); non-stream only in this lane. Request field `stream=true` is an intentional hardening difference. |
| `POST /tools/invoke` | Resolves tool list and executes tool directly | Evaluates tool-plane admission; returns policy decision, not tool result | Dangerous HTTP tools blocked deterministically (`TOOL_CLI_COMMAND_DENIED`). No direct execution path from the OpenClaw-facing endpoint. |

#### `/v1/responses` field mapping

| OpenClaw field | Wrapper mapping |
|---|---|
| `model` | preserved; required by model-plane policy |
| `input` (string or message array) | normalized into OpenAI-compatible `messages` |
| `instructions` | prepended as `system` message |
| `max_output_tokens` | mapped to `max_tokens` |
| `stream=true` | rejected with `400` (intentional) |

#### `/tools/invoke` field mapping

| OpenClaw field | Wrapper mapping |
|---|---|
| `tool` | `policy.attributes.tool_name` |
| `action` | `policy.action` |
| `args` | carried in metadata (`openclaw_args`) -- no direct execution |
| `sessionKey` | envelope session ID fallback for audit correlation |
| `approval_capability_token` / `step_up_token` / `approval_token` | consumed by tool-plane step-up validation |

### WebSocket Endpoint

`GET /openclaw/ws` -- mediates required OpenClaw gateway control-plane flows.

Wrapper scope is intentionally reduced to four required control methods. All other upstream WS surface is fail-closed denied by default. New methods can be added only through explicit wrapper allowlist expansion with tests and policy evidence.

| Method | Allowed conditions | Deny conditions | Reason code |
|---|---|---|---|
| `connect` | Valid SPIFFE identity, role in `{operator,node}`, device auth token when device id is declared | Missing/invalid SPIFFE context, invalid role, device id without token | `WS_AUTH_INVALID` |
| `health` | Sent after successful `connect` | First frame is not `connect`, malformed request frame | `WS_CONNECT_REQUIRED`, `WS_PAYLOAD_MALFORMED` |
| `devices.list` | `operator` role or `devices:read` scope | Role/scope does not permit device listing | `WS_METHOD_FORBIDDEN` |
| `devices.ping` | `operator` role or `devices:write` scope and `params.device_id` present | Role/scope disallowed or missing `params.device_id` | `WS_METHOD_FORBIDDEN`, `WS_PAYLOAD_MALFORMED` |
| any other method | -- | Always | `WS_METHOD_FORBIDDEN` |

Every mediated WS response carries `decision_id` and `trace_id` for audit correlation.

---

## Defaults-to-Pack Field Map

This table records OpenClaw-specific defaults that were previously implicit and where they now live in the pack, keeping gateway core agnostic.

| Previous default / assumption | Pack field | SDK hook surface | Why this keeps core agnostic |
|---|---|---|---|
| Default LLM/provider selection assumed by app wiring | `adapter_contract.model_routing.*` | `call_model_chat` request shaping in SDK demos | Core only enforces policy; app-specific model choice is declarative in pack |
| Tool set expected by OpenClaw workflows | `adapter_contract.tool_registration.required_tools` | SDK tool call adapter layer (`client.call(...)`) | Core registry remains generic; app expectations live in pack metadata |
| Unregistered tool denial and hash verification expectations | `adapter_contract.tool_registration.hash_verification` | SDK-side onboarding checks and conformance tests | Core does not learn app names/flows; only generic registry controls |
| Prompt-injection guardrail posture (DLP + deep scan contract) | `adapter_contract.gateway_guardrails.*` | SDK path-specific assertions | Guardrail mechanism stays core-generic; app interpretation is pack-defined |
| Timeout semantics for gateway-mediated model route in non-strict mode | `adapter_contract.gateway_guardrails.decision_contract.timeout_behavior_*` | SDK case-26 handling | Core unchanged; SDK/pack encode app-level acceptance criteria |
| Runtime differences between Compose and K8s | `adapter_contract.runtime_profile_hints.compose\|k8s` | SDK runtime test selection and strictness toggles | Core behavior is stable; runtime nuance is profile data in pack |

---

## Security Invariants (Fail Build If Violated)

These invariants apply to any OpenClaw port built on this pack:

1. No direct model provider call path from OpenClaw runtime without gateway mediation.
2. No direct tool execution path bypassing gateway tool-plane checks.
3. No admin/control endpoint callable without authn and authz.
4. No raw secret material in OpenClaw request payloads where token substitution is required.
5. No unsigned/unverified artifact admitted in strict deployment paths.

## Approval and Break-Glass Operating Model

High-risk operations require approval capability tokens. Tokens are scoped, signed, time-bounded, and single-use (consumed on use). Missing or weak signing key is startup-fatal in strict profiles.

Break-glass remains bounded and auditable. Break-glass events must include an explicit reason code, bounded TTL, issuer identity, and an immutable audit event sequence. Break-glass cannot disable baseline identity or audit requirements.

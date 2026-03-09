---
id: OC-o3xl
title: "Discord Adapter -- Outbound Message Mediation"
status: closed
priority: 0
type: task
labels: [agents-of-chaos, channel-mediation, delivered, accepted]
parent: OC-0esa
created_at: 2026-03-08T02:34:58Z
created_by: ramirosalas
updated_at: 2026-03-08T03:59:14Z
content_hash: "sha256:e15b883981e5110f855dafad426c9ada2ca803b972feb68809ef03f56f6725c1"
was_blocked_by: [OC-cbzc]
follows: [OC-cbzc]
closed_at: 2026-03-08T03:59:14Z
close_reason: "Accepted: Discord outbound send with DLP content scanning, SPIKE token redemption, and egress execution"
led_to: [OC-di1n]
---

## Description
## User Story

As a security operator, I need outbound Discord messages from agents to be evaluated through the full middleware chain so that DLP catches credential leaks, rate limiting prevents infinite message loops (Case Study #4), and OPA policy enforces authorization on who agents can message.

## Context

This story implements the core outbound send handler for the Discord adapter created in story OC-cbzc. The handler builds a PlaneRequestV2 for tool plane evaluation, calls EvaluateToolRequest() for policy/DLP/session checks, then calls ExecuteMessagingEgress() for actual Discord API delivery. Discord bot tokens are retrieved via SPIKE token references ($SPIKE{ref:...}) so the agent never sees the raw credential.

The PortGatewayServices facade provides:
- EvaluateToolRequest(req PlaneRequestV2) ToolPlaneEvalResult -- runs DLP, OPA, session context, step-up evaluation
- ExecuteMessagingEgress(ctx context.Context, attrs map[string]string, payload []byte, authHeader string) (*MessagingEgressResult, error) -- delivers message to external service
- RedeemSPIKESecret(ctx context.Context, tokenStr string) (string, error) -- late-binding credential retrieval

PlaneRequestV2 (POC/internal/gateway/phase3_contracts.go): Envelope RunEnvelope + Policy PolicyInputV2

ToolPlaneEvalResult (POC/internal/gateway/port.go): Decision, Reason ReasonCode, HTTPStatus int, RequireStepUp bool, Metadata map[string]any

DLP scanning detects: credentials (OpenAI keys pattern sk-..., AWS keys AKIA..., GitHub tokens ghp_/gho_/ghs_, Slack tokens xoxb-/xoxp-, PEM blocks, passwords), PII (SSN \d{3}-\d{2}-\d{4}, email, phone, credit card, IBAN, DOB). DLPPolicy defaults: Credentials="block", Injection="flag", PII="flag".

Rate limiting: per-identity token bucket via KeyDB. Keys: ratelimit:{spiffe_id}:tokens, ratelimit:{spiffe_id}:last_fill. Config: RateLimitRPM, RateLimitBurst.

## Implementation

Create POC/ports/discord/http_handler.go with handleSend() function:

1. Parse request body as protocol.SendMessageRequest (channel_id, content, embeds, reply_to)
2. Build PlaneRequestV2 with:
   - Tool name: "messaging_send"
   - Attributes: channel_id, guild_id (from request or context)
   - Payload: message content (subject to DLP scanning)
3. Call gateway.EvaluateToolRequest(planeReq) -- this runs OPA policy, DLP scan, session context
4. If Decision is denied: return structured error with decision_id and reason code using WriteGatewayError()
5. If Decision is allowed: check for SPIKE token references in bot token config
6. Call gateway.RedeemSPIKESecret() to get actual Discord bot token
7. Call gateway.ExecuteMessagingEgress() with Discord API attributes and redeemed token
8. Return structured response with decision_id

Error response format follows existing error envelope (api-reference.md):
```json
{
  "code": "<error_code>",
  "message": "<human-readable>",
  "middleware": "<middleware_name>",
  "middleware_step": <step>,
  "decision_id": "<uuid>",
  "trace_id": "<otel_trace_id>"
}
```

## Key Files

- POC/ports/discord/http_handler.go (create)
- POC/ports/discord/adapter.go (modify -- wire handleSend to /discord/send route)

## Testing

- Unit tests: policy allow path (Decision allowed, message delivered), policy deny path (DLP blocks credential in content), SPIKE token redemption invoked, rate limit enforcement (ToolPlaneEvalResult with ratelimit_exceeded)
- Integration test: end-to-end send with DLP blocking -- send a Discord message containing "sk-proj-abc123" (OpenAI key pattern) and verify HTTP 403 with code "dlp_credentials_detected"

## Acceptance Criteria

1. handleSend() builds PlaneRequestV2 with tool name "messaging_send" and Discord-specific attributes (channel_id, guild_id)
2. EvaluateToolRequest() called for policy evaluation before any external delivery
3. DLP scanning applies to message content field -- credential patterns blocked, PII flagged
4. Rate limiting applies per SPIFFE identity -- returns 429 with "ratelimit_exceeded" when exceeded
5. SPIKE token references ($SPIKE{ref:...}) used for Discord bot token -- agent never sees raw token
6. Structured decision response returned with decision_id and reason code
7. Unit tests cover allow/deny/rate-limit paths
8. Integration test demonstrates DLP blocking a credential pattern in Discord message content

## Scope Boundary

Inbound webhook handling is story OC-cbzc+1 (story 1.3). This story handles outbound send ONLY.

## Dependencies

Depends on OC-cbzc (Discord adapter core router must exist first).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T03:59:14Z dep_removed: no_longer_blocks OC-di1n

## Links
- Parent: [[OC-0esa]]
- Was blocked by: [[OC-cbzc]]
- Follows: [[OC-cbzc]]
- Led to: [[OC-di1n]]

## Comments

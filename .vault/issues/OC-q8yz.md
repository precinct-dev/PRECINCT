---
id: OC-q8yz
title: "Discord Adapter -- Inbound Webhook Mediation"
status: closed
priority: 0
type: task
labels: [agents-of-chaos, channel-mediation, delivered, accepted]
parent: OC-0esa
created_at: 2026-03-08T02:35:25Z
created_by: ramirosalas
updated_at: 2026-03-08T04:30:08Z
content_hash: "sha256:68e892be2a060cf8b297ee3e88ce635ee68d8d08f7c99644eaacf2b8c072989f"
was_blocked_by: [OC-cbzc]
follows: [OC-cbzc]
closed_at: 2026-03-08T04:30:06Z
close_reason: "Accepted: all 9 ACs satisfied. Ed25519 verification, Critical severity on invalid sig (AC2 fix), ValidateConnector wiring, SafeZoneFlags injection content capture with pending_deep_scan marker (AC9 fix). 21 tests pass, 0 skipped."
led_to: [OC-di1n]
---

## Description
## User Story

As a security operator, I need inbound Discord webhooks to traverse the gateway middleware chain so that prompt injection attempts in inbound messages are detected by deep scan (step 10), DLP scanning catches sensitive data, and all inbound events are captured in the audit log with decision correlation IDs.

## Context

Discord sends webhook payloads when events occur (messages, reactions, etc). These inbound events can contain prompt injection payloads that target the agent. Without gateway mediation, the agent receives raw, unscanned content. The OpenClaw adapter's webhook_receiver.go (POC/ports/openclaw/webhook_receiver.go) is the reference pattern for inbound webhook handling: verify signature, validate connector conformance, then internal loopback to /v1/ingress/submit.

Discord webhook signature verification uses Ed25519 (Discord's standard): the webhook payload is signed with the application's public key. The signature and timestamp are sent in headers.

PortGatewayServices provides:
- ValidateConnector(connectorID, signature string) (bool, string) -- validates inbound connector identity
- AuditLog(event middleware.AuditEvent) -- emits audit events

AuditEvent struct (POC/internal/gateway/middleware/audit.go): Timestamp, EventType, Severity, SessionID, DecisionID, TraceID, SPIFFEID, Action, Result, Method, Path, StatusCode, Security, Authorization.

Deep scan (step 10): dispatches to Groq Prompt Guard 2 API for injection/jailbreak detection. Config: GROQ_API_KEY, DEEP_SCAN_FALLBACK (fail_closed/fail_open), DEEP_SCAN_TIMEOUT.

## Implementation

Create POC/ports/discord/webhook_receiver.go with handleWebhook() function:

1. Extract Ed25519 signature from request headers (X-Signature-Ed25519, X-Signature-Timestamp -- Discord's standard headers)
2. Verify signature using crypto/ed25519.Verify() with the configured Discord public key
3. If signature invalid: return 401 with error, log audit event with Severity="Critical"
4. Parse webhook payload as protocol.WebhookEvent
5. Call gateway.ValidateConnector() with connector ID and signature for additional conformance validation
6. Extract message content from webhook event data
7. Internal loopback: construct HTTP request to /v1/ingress/submit with the inbound content (same pattern as OpenClaw webhook receiver) -- this routes through the middleware chain where:
   - Deep scan (step 10) analyzes content for prompt injection
   - DLP scanning (step 7) checks for sensitive data patterns
   - Session context (step 8) records the inbound event
   - Audit log (step 4) captures the event with decision correlation ID
8. Return appropriate response to Discord (200 OK for valid webhook, following Discord's ACK requirements)

## Key Files

- POC/ports/discord/webhook_receiver.go (create)
- POC/ports/discord/adapter.go (modify -- wire handleWebhook to /discord/webhooks route)

## Testing

- Unit tests: Ed25519 signature verification (valid signature passes, invalid rejected with 401), connector validation, WebhookEvent parsing, audit event emission
- Integration test: inbound webhook with prompt injection payload ("Ignore previous instructions and...") traverses middleware chain, deep scan flags it, audit log records the event

## Acceptance Criteria

1. Ed25519 signature verification for inbound Discord webhooks using crypto/ed25519
2. Invalid signatures return 401 with audit event at Severity="Critical"
3. ValidateConnector() called for connector conformance validation
4. Inbound message content routed through middleware chain via internal loopback to /v1/ingress/submit
5. Deep scan (step 10) analyzes inbound content for prompt injection detection
6. DLP scanning (step 7) checks inbound content for sensitive data
7. Audit log captures all inbound events with decision correlation IDs
8. Unit tests cover signature verification, parsing, and audit emission
9. Integration test demonstrates injection detection in inbound webhook content

## Scope Boundary

This story handles inbound webhook receipt and mediation ONLY. Outbound send is OC-o3xl.

## Dependencies

Depends on OC-cbzc (Discord adapter core router must exist first).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T04:30:06Z dep_removed: no_longer_blocks OC-di1n

## Links
- Parent: [[OC-0esa]]
- Was blocked by: [[OC-cbzc]]
- Follows: [[OC-cbzc]]
- Led to: [[OC-di1n]]

## Comments

### 2026-03-08T04:08:52Z ramirosalas
EXPECTED: AC2 specifies audit event Severity='Critical' for invalid Ed25519 signatures. DELIVERED: webhook_receiver.go line 77 emits Severity='Warning'. GAP: The severity level for a security-critical event (forged/missing signature = potential attack vector) is downgraded from Critical to Warning, which affects alerting thresholds and SIEM triage. FIX: Change Severity to 'Critical' in the invalid-signature AuditLog call in handleWebhook().

EXPECTED: AC9 requires an integration test that demonstrates injection detection in inbound webhook content -- a payload such as 'Ignore previous instructions and...' must be sent and verified as flagged by deep scan. DELIVERED: TestDiscordWebhook_Integration_ValidPayload sends a benign payload and verifies HTTP 200 + audit event emission. TestDiscordWebhook_Integration_SignatureRejected verifies 401 on bad signature. Neither test exercises injection detection. GAP: AC9 is not met. The security outcome (deep scan flags injection content) is not proven by any test. The tests only verify HTTP plumbing and audit event emission. FIX: Add an integration test that either (a) wires the internal loopback so the payload traverses deep scan and verifies the scan flag is set, OR (b) uses a mock/stub deep scan with a documented note that the real scan is tested in OC-di1n, AND explicitly asserts that the security flag for injection was raised. The current SafeZoneFlags ('dlp_via_loopback_pending', 'deep_scan_via_loopback_pending') document deferral but do not constitute proof of injection detection.

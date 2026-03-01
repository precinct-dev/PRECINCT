---
id: RFA-xynt
title: "WS Mediation via HTTP-Only Egress -- Messaging Send/Receive Through Full Middleware Chain"
status: closed
priority: 1
type: epic
created_at: 2026-02-27T04:27:49Z
created_by: ramirosalas
updated_at: 2026-02-27T06:46:37Z
content_hash: "sha256:83d637958910aec39ba329ddcacb710dd553eb0e31374488052ffdad3db5bea8"
labels: [milestone]
---

## Description
## Epic: WebSocket Mediation via HTTP-Only Egress

### Business Context
WS frames after upgrade bypass DLP, OPA, deep scan, rate limiting, and token substitution. OpenClaw needs to send messages to WhatsApp/Telegram/Slack and receive inbound webhooks. All traffic MUST be mediated by the gateway's full 13-step middleware chain.

### Architecture Decision
HTTP-Only Egress (Option A): Force all outbound messaging through the gateway's tool plane (full middleware chain). Inbound messages enter via the ingress plane with connector conformance. No outbound WS dial.

### Outbound Path (messaging.send)
Client --WS frame--> [Port Adapter WS handler]
  --> Adapter extracts message intent from WS frame
  --> Adapter builds PlaneRequestV2 for tool plane
  --> gw.EvaluateToolRequest(req) -- in-process (OPA, step-up, exfiltration check)
  --> gw.ExecuteMessagingEgress(ctx, attrs, payload, authHeader)
      (destination allowlist, SPIKE token sub, HTTP POST to external API)
  --> [WhatsApp/Telegram/Slack HTTP API]
  --> Adapter wraps response as WS frame --> Client

### Inbound Path (webhook receive)
[External Service] --HTTP POST--> [Gateway /v1/ingress/submit]
  --> Full middleware chain (steps 0-13), DLP scans inbound content
  --> Connector conformance check
  --> Port adapter receives ingress event
  --> Delivers to connected WS client

### Acceptance Criteria
1. messaging.send WS method sends messages through full middleware chain to external HTTP APIs
2. DLP fires on messaging content containing sensitive data (SSN, credit card, etc.)
3. Exfiltration detection triggers on sensitive-read-then-send pattern via messaging
4. OPA policy evaluates correctly for messaging tools (messaging_send, messaging_status)
5. SPIKE token references substitute correctly in HTTP Authorization headers
6. Inbound webhooks enter via ingress plane with connector conformance
7. All integration tests pass against live Compose stack with realistic service simulators
8. E2E scenarios (scenario_k, scenario_l) pass and are wired into make openclaw-demo

## Acceptance Criteria


## Design


## Notes


## History
- 2026-02-27T06:46:37Z status: open -> closed

## Links


## Comments

### 2026-02-27T06:46:37Z ramirosalas
EPIC COMPLETE: All 9 stories accepted. 2 P3 discovered issues (RFA-exak, RFA-iqij) remain open for Sr PM triage.

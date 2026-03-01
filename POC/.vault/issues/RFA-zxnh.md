---
id: RFA-zxnh
title: "Harden ExecuteMessagingEgress for all platforms with TLS enforcement and comprehensive error handling"
status: closed
priority: 1
type: task
parent: RFA-xynt
created_at: 2026-02-27T04:29:43Z
created_by: ramirosalas
updated_at: 2026-02-27T05:51:46Z
content_hash: "sha256:91c3ed7107a8b0f089fb5ad0067f1e5c1029f6b06b55c82377cc8dcbf7aa9a8a"
blocks: [RFA-mbmr, RFA-ajf6, RFA-yt63]
related: [RFA-np7t]
blocked_by: [RFA-1fui]
follows: [RFA-np7t, RFA-ncf1]
labels: [accepted]
closed_at: 2026-02-27T05:51:46Z
close_reason: "Accepted: All 7 ACs verified. resolveMessagingTarget constructs correct platform paths (WhatsApp/Telegram/Slack), env var override works for all platforms, HTTPS enforced for non-local hosts, extractMessageID parses all 3 platform response formats. Compile-time interface check passes in port_services.go. go build ./... clean. 31 tests pass (18 top-level + 14 subtests). No wiring gap - ExecuteMessagingEgress delegates to private method in port_services.go. Integration tests deferred to sibling story RFA-yt63 per explicit Sr. PM documentation in story text."
led_to: [RFA-mbmr, RFA-yt63]
---

## Description
## User Story
As a port adapter developer, I need the ExecuteMessagingEgress method hardened to support all three platforms (WhatsApp, Telegram, Slack) with TLS enforcement, comprehensive error handling, and production-ready endpoint resolution so that the messaging egress pipeline is robust.

## Context
The walking skeleton (RFA-1fui) established the minimal ExecuteMessagingEgress method with WhatsApp support, env var endpoint override, and basic destination allowlist validation. This story hardens it for production:

1. Adds Telegram and Slack endpoint resolution with platform-specific path construction
2. Enforces HTTPS outside local development (same rule as model egress)
3. Adds comprehensive error handling and edge cases
4. Adds thorough unit test coverage for all three platforms

## What to Build

### 1. Extend `internal/gateway/messaging_egress.go`

The walking skeleton already provides:
- `executeMessagingEgress` with basic HTTP POST and WhatsApp endpoint
- `resolveMessagingTarget` with env var override and allowlist check
- `extractMessageID` with WhatsApp parsing
- `MessagingEgressResult` type

This story extends:

**Platform endpoint map** -- add all three platforms to `messagingPlatformEndpoints`:
```go
var messagingPlatformEndpoints = map[string]string{
    "whatsapp": "https://graph.facebook.com/v17.0",
    "telegram": "https://api.telegram.org",
    "slack":    "https://slack.com",
}
```

**Platform-specific path construction** in `resolveMessagingTarget`:
```go
switch platform {
case "whatsapp":
    endpoint = baseURL + "/v1/messages"
case "telegram":
    token := getStringAttr(attrs, "bot_token", "")
    if token == "" { token = "bot-token" }
    endpoint = baseURL + "/bot" + token + "/sendMessage"
case "slack":
    endpoint = baseURL + "/api/chat.postMessage"
}
```

**HTTPS enforcement** outside local development:
```go
if target.Scheme != "https" && !isLocalHost(host) && !isSingleLabelHostname(host) {
    return nil, fmt.Errorf("messaging endpoint must use https outside local development")
}
```

**Extend extractMessageID** for Telegram (message_id as float64 -> string) and Slack (ts field).

**TLS config**: Enforce TLS 1.2 minimum on the HTTP client.

### 2. Comprehensive Unit Tests: `internal/gateway/messaging_egress_test.go`

Test cases:
- Successful egress to each platform (WhatsApp, Telegram, Slack) with httptest server
- Missing platform error
- Unsupported platform error
- Destination allowlist denial
- Env var override for each platform
- HTTPS enforcement (rejects http:// for non-local hosts)
- Message ID extraction for all three platforms (WhatsApp, Telegram, Slack, unknown)
- Empty auth header handling
- Malformed endpoint URL handling

## Acceptance Criteria
1. `resolveMessagingTarget` constructs correct paths for all three platforms
2. `resolveMessagingTarget` supports `MESSAGING_PLATFORM_ENDPOINT_<PLATFORM>` env var override for Telegram and Slack (WhatsApp was in walking skeleton)
3. `resolveMessagingTarget` enforces HTTPS outside local development (same rule as model egress)
4. `extractMessageID` correctly parses responses from all three platforms
5. Gateway compile-time interface check passes: `var _ PortGatewayServices = (*Gateway)(nil)`
6. `go build ./...` succeeds
7. Unit tests in `internal/gateway/messaging_egress_test.go` cover: all 3 platforms success, missing platform, allowlist denial, env var override, HTTPS enforcement, message ID extraction for all platforms

## Technical Notes
- Follow the same pattern as `executeModelEgress` in `phase3_model_egress.go` (line 314-371)
- Reuse existing helpers: `getStringAttr`, `isLocalHost`, `isSingleLabelHostname` (all in phase3_model_egress.go)
- Reuse `g.destinationAllowlist` (same allowlist used by model egress at line 515-521)
- The Gateway struct is defined in `internal/gateway/gateway.go` -- should not need modification
- The middleware import is `github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware`

## Testing Requirements
- Unit tests: comprehensive coverage of resolveMessagingTarget and extractMessageID for all platforms
- Integration tests are covered by story RFA-yt63

## Scope Boundary
This story hardens the gateway egress capability. The walking skeleton (RFA-1fui) established the interface, basic implementation, and wiring. WS handler extensions, config/policy updates, and SPIKE secrets are handled by sibling stories.

## Dependencies
- Requires RFA-1fui (walking skeleton) -- base implementation established

## MANDATORY SKILLS TO REVIEW
- None identified. Follows existing model egress pattern closely.

## History
- 2026-02-27T05:51:46Z status: in_progress -> closed

## Links
- Parent: [[RFA-xynt]]
- Blocks: [[RFA-mbmr]], [[RFA-ajf6]], [[RFA-yt63]]
- Blocked by: [[RFA-1fui]]
- Related: [[RFA-np7t]]
- Follows: [[RFA-np7t]], [[RFA-ncf1]]
- Led to: [[RFA-mbmr]], [[RFA-yt63]]

## Comments

### 2026-02-27T05:46:22Z ramirosalas
DELIVERED: All 7 ACs verified. 31 tests passing (18 top-level + 14 subtests). Commit eeddfaa on epic/RFA-xynt-ws-mediation-messaging.

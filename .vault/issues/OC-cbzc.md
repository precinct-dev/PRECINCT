---
id: OC-cbzc
title: "Discord Port Adapter -- Core Router and Protocol Contract"
status: closed
priority: 0
type: task
labels: [agents-of-chaos, channel-mediation, delivered, accepted]
parent: OC-0esa
created_at: 2026-03-08T02:34:23Z
created_by: ramirosalas
updated_at: 2026-03-08T03:26:46Z
content_hash: "sha256:fcf94a3ec1564dbb49e98e7bc7e34a54792b60ebc2884200f881116fbc95b26d"
follows: [OC-0lx3]
closed_at: 2026-03-08T03:26:46Z
close_reason: "Accepted: Discord adapter complete with EvaluateToolRequest wiring and passing integration tests"
led_to: [OC-o3xl, OC-q8yz]
---

## Description
## User Story

As a security operator, I need Discord communication to be mediated through the PRECINCT gateway so that all 13 middleware layers (DLP, rate limiting, session context, OPA policy, deep scan, audit) apply to agent-to-agent Discord messaging, preventing the bypass documented in Case Studies #4 and #10 of 'Agents of Chaos' (arXiv:2602.20021v1).

## Context

The PRECINCT gateway uses a port adapter pattern for protocol-specific mediation. The production reference is the OpenClaw adapter (POC/ports/openclaw/ -- ~1,671 LOC across 6 files: adapter.go, http_handler.go, messaging_egress.go, webhook_receiver.go, ws_handler.go, protocol/ types). This story creates the Discord adapter scaffolding following the exact same pattern.

The PortAdapter interface (POC/internal/gateway/port.go):
```go
type PortAdapter interface {
    Name() string
    TryServeHTTP(w http.ResponseWriter, r *http.Request) bool
}
```

Adapters run INSIDE the middleware chain. Registration happens at startup in cmd/gateway/main.go. Gateway services are exposed via PortGatewayServices facade.

## Implementation

Create the following files:
- POC/ports/discord/adapter.go -- implements PortAdapter interface
- POC/ports/discord/protocol/types.go -- Discord-specific request/response types

Discord adapter.go must:
1. Implement Name() returning "discord"
2. Implement TryServeHTTP claiming paths: /discord/send, /discord/webhooks, /discord/commands
3. Accept PortGatewayServices in constructor (same pattern as OpenClaw adapter)
4. Route to internal handlers based on path

Protocol types (protocol/types.go):
```go
type SendMessageRequest struct {
    ChannelID string   `json:"channel_id"`
    Content   string   `json:"content"`
    Embeds    []Embed  `json:"embeds,omitempty"`
    ReplyTo   string   `json:"reply_to,omitempty"`
}

type WebhookEvent struct {
    Type      string          `json:"type"`
    Data      json.RawMessage `json:"data"`
    Signature string          `json:"signature"`  // Ed25519 signature from Discord
    Timestamp string          `json:"timestamp"`
}

type BotCommandRequest struct {
    Command string                 `json:"command"`
    Options map[string]interface{} `json:"options,omitempty"`
    GuildID string                 `json:"guild_id"`
}
```

Map Discord operations to gateway planes:
- /discord/send -> tool plane evaluation via EvaluateToolRequest(PlaneRequestV2) with tool name "messaging_send"
- /discord/webhooks -> ingress plane via ValidateConnector() + internal loopback
- /discord/commands -> tool plane evaluation with tool name "discord_command"

Register adapter in cmd/gateway/main.go alongside OpenClaw adapter registration.

## Key Files

- POC/ports/discord/adapter.go (create)
- POC/ports/discord/protocol/types.go (create)
- POC/cmd/gateway/main.go (modify -- add adapter registration)

## Testing

- Unit tests: path claiming (TryServeHTTP returns true for /discord/* paths, false for others), request parsing for each protocol type, error handling for malformed requests
- Integration test: adapter registered in gateway and dispatching through middleware chain (send request to /discord/send, verify it traverses SPIFFE auth and audit logging)

## Acceptance Criteria

1. POC/ports/discord/adapter.go implements PortAdapter with Name() returning "discord"
2. TryServeHTTP claims /discord/send, /discord/webhooks, /discord/commands and returns false for unrelated paths
3. POC/ports/discord/protocol/types.go defines SendMessageRequest, WebhookEvent, BotCommandRequest with correct JSON tags
4. Adapter registered in cmd/gateway/main.go at startup
5. Discord operations mapped to gateway plane requests: messaging_send for /discord/send, discord_command for /discord/commands
6. Unit tests verify path claiming, request parsing, and error handling
7. Integration test verifies adapter registration and middleware chain traversal

## Scope Boundary

This story creates the adapter skeleton and protocol types ONLY. Outbound send logic (story 1.2), inbound webhook handling (story 1.3), and E2E demo scenarios (story 1.7) are separate stories.

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes
COMPLETED: Fixed integration test SIGSEGV by providing integrationMockGateway (non-nil PortGatewayServices impl). Updated request bodies for /discord/send and /discord/commands to include required fields so they pass validation and reach the 501 stub. All 17 unit tests + 3 integration tests pass. Commit 6b8a02d pushed to story/OC-cbzc.

## History
- 2026-03-08T03:26:46Z dep_removed: no_longer_blocks OC-q8yz

## Links
- Parent: [[OC-0esa]]
- Follows: [[OC-0lx3]]
- Led to: [[OC-o3xl]], [[OC-q8yz]]

## Comments

### 2026-03-08T03:02:36Z ramirosalas
EXPECTED: AC5 requires Discord operations to be mapped to gateway plane requests: messaging_send for /discord/send, discord_command for /discord/commands. This means handleSend() must call a.gw.EvaluateToolRequest() with a PlaneRequestV2 whose tool name is 'messaging_send', and handleCommand() must call EvaluateToolRequest() with tool name 'discord_command'. The gateway service facade (PortGatewayServices) exposes EvaluateToolRequest() precisely for this purpose. AC6 also requires unit tests that verify error handling for malformed requests -- no such tests are present.

DELIVERED: handleSend(), handleWebhook(), and handleCommand() are pure stubs returning http.StatusNotImplemented with no gateway service calls. The unit tests cover path claiming and 501 stub responses but do not test request parsing or malformed request handling.

GAP: (1) AC5 -- no gateway plane mapping in any handler. The stub implementation does not call EvaluateToolRequest() or construct a PlaneRequestV2 with the required tool names. The 'Scope Boundary' note in the story description is contradicted by AC5 -- ACs are the authoritative contract. (2) AC6 -- no malformed request error handling tests (e.g., invalid JSON body on /discord/send or /discord/commands).

FIX: (1) In handleSend(), decode the request body as protocol.SendMessageRequest, construct a PlaneRequestV2 with tool name 'messaging_send', call a.gw.EvaluateToolRequest() and respond based on the result. (2) In handleCommand(), decode as protocol.BotCommandRequest, construct PlaneRequestV2 with tool name 'discord_command', call EvaluateToolRequest(). (3) Add unit tests for malformed JSON on /discord/send and /discord/commands verifying 400 Bad Request is returned. Note: the story's Scope Boundary note conflicts with AC5 -- if the intent truly was to defer gateway plane mapping to a later story, the Sr. PM must update the ACs before the developer redelivers.

### 2026-03-08T03:13:33Z ramirosalas
EXPECTED: AC7 requires an integration test that verifies adapter registration and middleware chain traversal. The test must execute without errors, confirming the adapter operates correctly when wired through real middleware.

DELIVERED: The integration test at POC/tests/integration/discord_adapter_integration_test.go creates the adapter with discord.NewAdapter(nil) (line 26), relying on a comment that says 'stub handlers don't call gateway services'. However, after the AC5 fix, handleSend and handleCommand now call a.gw.WriteGatewayError() for validation errors and a.gw.EvaluateToolRequest() for valid requests -- both of which dereference the nil gw pointer.

GAP: TestDiscordAdapter_SPIFFEAuth_Passthrough panics with a nil pointer dereference (SIGSEGV) at adapter.go:82 (a.gw.WriteGatewayError). TestDiscordAdapter_AllEndpoints_Behind_SPIFFE would panic for the same reason on the with_spiffe sub-tests. The integration test comment was written for the original stub and was not updated after the AC5 fix was applied. Result: 'go test ./tests/integration/... -run TestDiscordAdapter -tags integration' exits with code 1 and a panic, not a PASS.

FIX: Update discord_adapter_integration_test.go to pass a real or mock gateway services implementation instead of nil. The test must construct a mockGatewayServices (already defined in adapter_test.go within the discord package) or define a local one in the integration test package. Alternatively, restructure buildDiscordChain to pass the same mock used in unit tests. The test body at line 26 must be changed so that NewAdapter receives a non-nil PortGatewayServices that satisfies all method calls made by handleSend and handleCommand. After the fix, all three TestDiscordAdapter_* tests must pass with -tags integration and produce PASS output with 0 panics.

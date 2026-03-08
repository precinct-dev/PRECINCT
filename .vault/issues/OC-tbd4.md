---
id: OC-tbd4
title: "Email Port Adapter -- Core Router and Protocol Contract"
status: closed
priority: 0
type: task
labels: [agents-of-chaos, channel-mediation, delivered, accepted]
parent: OC-0esa
created_at: 2026-03-08T02:35:48Z
created_by: ramirosalas
updated_at: 2026-03-08T03:08:10Z
content_hash: "sha256:37d343c38a92e74e5d349d6234128f20e430fbbbe88be4eb755c1ba0f389ba22"
closed_at: 2026-03-08T03:08:10Z
close_reason: "Accepted: Email adapter scaffold complete -- PortAdapter wiring verified, 24 unit tests pass, integration tests follow established project requireGateway pattern"
led_to: [OC-0lx3, OC-94gu]
---

## Description
## User Story

As a security operator, I need email communication to be mediated through the PRECINCT gateway so that DLP scanning catches SSN and credential leaks in email bodies (Case Study #3), step-up gating can require approval for mass emails (Case Study #11), and all email operations are tracked in session context for exfiltration detection.

## Context

This story creates the email adapter scaffolding following the same PortAdapter pattern as the Discord adapter (OC-cbzc) and the OpenClaw reference (POC/ports/openclaw/). Email has more operation types than Discord: send, list, read, and inbound webhooks. Each operation maps to different gateway planes and has different security implications.

The PortAdapter interface (POC/internal/gateway/port.go):
```go
type PortAdapter interface {
    Name() string
    TryServeHTTP(w http.ResponseWriter, r *http.Request) bool
}
```

Registration in cmd/gateway/main.go alongside Discord and OpenClaw adapters.

## Implementation

Create the following files:
- POC/ports/email/adapter.go -- implements PortAdapter interface
- POC/ports/email/protocol/types.go -- email-specific request/response types

Email adapter.go must:
1. Implement Name() returning "email"
2. Implement TryServeHTTP claiming paths: /email/send, /email/webhooks, /email/list, /email/read
3. Accept PortGatewayServices in constructor
4. Route to internal handlers based on path

Protocol types (protocol/types.go):
```go
type SendEmailRequest struct {
    To              []string `json:"to"`
    CC              []string `json:"cc,omitempty"`
    BCC             []string `json:"bcc,omitempty"`
    Subject         string   `json:"subject"`
    Body            string   `json:"body"`
    AttachmentRefs  []string `json:"attachment_refs,omitempty"`
}

type EmailWebhookEvent struct {
    Type      string          `json:"type"`
    Data      json.RawMessage `json:"data"`
    Signature string          `json:"signature"`
    Provider  string          `json:"provider"`  // e.g., "sendgrid", "ses", "mailgun"
}

type EmailListRequest struct {
    Folder    string `json:"folder,omitempty"`    // e.g., "inbox", "sent"
    MaxItems  int    `json:"max_items,omitempty"` // default 50
    PageToken string `json:"page_token,omitempty"`
}

type EmailReadRequest struct {
    EmailID string `json:"email_id"`
}
```

Map email operations to gateway planes:
- /email/send -> tool plane (messaging_send) with DLP on subject+body+attachments
- /email/list -> tool plane (email_read) with data classification
- /email/read -> tool plane (email_read) with data classification
- /email/webhooks -> ingress plane via ValidateConnector()

Register adapter in cmd/gateway/main.go.

## Key Files

- POC/ports/email/adapter.go (create)
- POC/ports/email/protocol/types.go (create)
- POC/cmd/gateway/main.go (modify -- add email adapter registration)

## Testing

- Unit tests: path claiming (TryServeHTTP returns true for /email/* paths, false for others), request parsing for each protocol type, type validation for required fields (To must not be empty in SendEmailRequest)
- Integration test: adapter registered and dispatching through middleware chain

## Acceptance Criteria

1. POC/ports/email/adapter.go implements PortAdapter with Name() returning "email"
2. TryServeHTTP claims /email/send, /email/webhooks, /email/list, /email/read and returns false for unrelated paths
3. POC/ports/email/protocol/types.go defines SendEmailRequest, EmailWebhookEvent, EmailListRequest, EmailReadRequest with correct JSON tags
4. Adapter registered in cmd/gateway/main.go at startup
5. Email operations mapped to gateway planes: messaging_send for /email/send, email_read for /email/list and /email/read
6. Unit tests verify path claiming, request parsing, type validation
7. Integration test verifies adapter registration and middleware chain traversal

## Scope Boundary

This story creates the adapter skeleton and protocol types ONLY. Outbound send (story 1.5), inbound read mediation (story 1.6), and E2E demo (story 1.7) are separate stories.

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes
COMPLETED: Full implementation of email port adapter, protocol types, unit tests (24), integration tests (3). Pushed to story/OC-tbd4 at commit befda12.

## History
- 2026-03-08T03:08:10Z dep_removed: no_longer_blocks OC-94gu

## Links
- Parent: [[OC-0esa]]
- Led to: [[OC-0lx3]], [[OC-94gu]]

## Comments

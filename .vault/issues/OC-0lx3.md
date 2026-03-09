---
id: OC-0lx3
title: "Email Adapter -- Outbound Send with DLP and Recipient Policy"
status: closed
priority: 0
type: task
labels: [agents-of-chaos, channel-mediation, delivered, accepted]
parent: OC-0esa
created_at: 2026-03-08T02:36:27Z
created_by: ramirosalas
updated_at: 2026-03-08T03:22:35Z
content_hash: "sha256:49babcbe1a24cd124319f133dabba36e77e3ffcdf12fd5d59e34c8affa975564"
was_blocked_by: [OC-tbd4]
follows: [OC-tbd4]
closed_at: 2026-03-08T03:22:35Z
close_reason: "Accepted: Email outbound send with DLP, mass-email detection, SPIKE redemption, and recipient policy"
led_to: [OC-cbzc, OC-di1n]
---

## Description
## User Story

As a security operator, I need outbound emails from agents to be evaluated through the full middleware chain so that DLP catches SSN in email bodies (Case Study #3), OPA enforces recipient allowlists, and step-up gating requires approval for mass emails exceeding a recipient threshold (Case Study #11 -- libelous broadcasts).

## Context

This story implements outbound send handling for the email adapter created in OC-tbd4. Email sending has unique security concerns beyond basic DLP: recipient policy enforcement (who can this agent email?), mass-email detection (>N recipients triggers step-up), and attachment size enforcement.

PortGatewayServices provides:
- EvaluateToolRequest(req PlaneRequestV2) ToolPlaneEvalResult
- ExecuteMessagingEgress(ctx context.Context, attrs map[string]string, payload []byte, authHeader string) (*MessagingEgressResult, error)
- RedeemSPIKESecret(ctx context.Context, tokenStr string) (string, error)
- WriteGatewayError(w, r, httpCode, errorCode, message, middlewareName, reason, details)

DLP scanning detects in email body+subject: credentials (OpenAI sk-..., AWS AKIA..., GitHub ghp_/gho_/ghs_, Slack xoxb-/xoxp-, PEM blocks, passwords), PII (SSN \d{3}-\d{2}-\d{4}, email addresses, phone numbers, credit card numbers, IBAN, DOB). DLPPolicy: Credentials="block", Injection="flag", PII="flag".

Step-up gating: RiskDimension with Impact 0-3, Reversibility 0-3, Exposure 0-3, Novelty 0-3. Gates: Fast Path (0-3), Step-Up (4-6), Approval (7-9), Deny (10-12). Mass email (>N recipients) increases Exposure dimension.

Request size limit: MaxRequestSizeBytes (default 10MB, step 1) applies to attachment payload.

## Implementation

Create POC/ports/email/http_handler.go with handleSend() function:

1. Parse request body as protocol.SendEmailRequest (to, cc, bcc, subject, body, attachment_refs)
2. Compute total recipient count: len(To) + len(CC) + len(BCC)
3. Build PlaneRequestV2 with:
   - Tool name: "messaging_send"
   - Attributes: recipient_count, has_attachments, subject_preview (first 50 chars)
   - Payload: subject + body concatenated (subject to DLP scanning on full content)
4. If recipient_count > configurable threshold (default: 10):
   - Set additional attributes indicating mass-email (triggers Exposure=3 in step-up gating)
   - ToolDefinition override: RequiresStepUp=true for mass sends
5. Call gateway.EvaluateToolRequest(planeReq)
6. If denied: return structured error with decision_id
7. If allowed: redeem SPIKE token for SMTP credentials via RedeemSPIKESecret()
8. Call ExecuteMessagingEgress() with email delivery attributes
9. Emit audit event with full recipient list and decision

Recipient policy enforcement via OPA:
- OPAInput includes recipient domains extracted from To/CC/BCC
- OPA policy can restrict which domains this SPIFFE ID can email
- Implemented via existing EvaluateToolRequest which includes OPA evaluation

## Key Files

- POC/ports/email/http_handler.go (create)
- POC/ports/email/adapter.go (modify -- wire handleSend to /email/send route)

## Testing

- Unit tests: DLP blocking SSN pattern (\d{3}-\d{2}-\d{4}) in email body, recipient count threshold detection, mass-email step-up trigger, SPIKE token redemption for SMTP credentials
- Integration test: end-to-end send with DLP catching PII -- send email with body containing "123-45-6789" (SSN pattern) and verify DLP flags it (PII default policy is "flag", not "block", so request proceeds but SecurityFlagsCollector records "pii_detected")

## Acceptance Criteria

1. handleSend() parses SendEmailRequest and builds PlaneRequestV2 with tool name "messaging_send"
2. DLP scanning applies to subject + body concatenated -- credential patterns blocked, PII flagged
3. Recipient count > threshold (default 10) triggers step-up gating with elevated Exposure dimension
4. OPA policy evaluation includes recipient domain information for authorization
5. SPIKE token references ($SPIKE{ref:...}) used for SMTP credentials
6. Attachment size enforcement via existing MaxRequestSizeBytes (10MB default)
7. Audit log records full recipient list (To, CC, BCC counts) and decision
8. Unit tests cover DLP blocking, mass-email detection, and SPIKE redemption
9. Integration test demonstrates DLP flagging PII in email body

## Scope Boundary

Email list/read operations are story OC-tbd4+next (story 1.6). This story handles outbound send ONLY.

## Dependencies

Depends on OC-tbd4 (email adapter core router must exist first).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes
COMPLETED: Implemented handleSend with DLP, OPA, SPIKE, mass-email detection. All 27 unit tests pass. Integration tests added. Pushed to story/OC-0lx3.

## History
- 2026-03-08T03:22:35Z dep_removed: no_longer_blocks OC-di1n

## Links
- Parent: [[OC-0esa]]
- Was blocked by: [[OC-tbd4]]
- Follows: [[OC-tbd4]]
- Led to: [[OC-cbzc]], [[OC-di1n]]

## Comments

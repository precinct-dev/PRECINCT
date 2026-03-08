---
id: oc-6bq
title: "Validate and fix OpenClaw integration against updated upstream"
status: closed
priority: 1
type: epic
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T19:56:18Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:22Z
content_hash: "sha256:ffa71677e4ad36852c95cb433bae9bdcfce37ab6bf2a6ff3cf4f5f5e666b207c"
closed_at: 2026-02-21T20:46:34Z
close_reason: "All 5 stories complete: WS adapter device-identity enforcement (oc-a39), pack config pin update (oc-0bl), port validation campaign (oc-b9w), Docker Compose validation (oc-sdh), Kubernetes validation (oc-ht7). OpenClaw integration validated end-to-end in both deployment modes."
follows: [oc-l5u]
---

## Description
Epic: Verify the existing MCP Security Gateway OpenClaw integration adapters still work correctly against OpenClaw commit 302fa03f4 (current HEAD), up from pinned 5d40d47501. OpenClaw received ~50 commits including breaking changes to WS connect policy (node role now requires device identity), auth surface refactoring (authorizeGatewayConnect split into HTTP/WS variants), and deprecation of allowInsecureAuth. HTTP API contract (/v1/responses, /tools/invoke) is unchanged. All existing Go tests pass (10 unit + 4 integration), but the WS adapter contract may be stale relative to upstream enforcement. Changes MUST be scoped to adapter layer only: internal/integrations/openclaw/, openclaw_*_adapter.go, tests, deployment configs. No changes to core gateway, middleware, or policy engine.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T02:10:22Z status: open -> closed

## Links
- Follows: [[oc-l5u]]

## Comments

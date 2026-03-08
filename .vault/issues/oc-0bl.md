---
id: oc-0bl
title: "Update pack config commit pin and add upstream contract changelog"
status: closed
priority: 1
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T19:57:27Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:22Z
content_hash: "sha256:f6e57c450f7d732d7b15b734edb07d7b69727355e31d427938f7e321dc738ad1"
closed_at: 2026-02-21T20:04:54Z
close_reason: "Pack config updated: upstream commit pinned to 302fa03f41, pack_version bumped to 2026-02-21, upstream_changelog added with WS protocol changes documentation, ws_device_required deny code added. All ACs verified, full Go test suite green, pack model validation passed."
parent: oc-6bq
blocked_by: [oc-a39]
blocks: [oc-b9w]
follows: [oc-a39]
led_to: [oc-b9w]
---

## Description
## User Story

As a gateway operator, I need the OpenClaw pack config to accurately reflect the current upstream commit and document what contract changes were absorbed, so that future integration maintainers know what version the adapter targets and what behavioral differences exist.

## Context and Business Value

The pack config at `packs/openclaw/pack.v1.json` currently pins commit `5d40d47501c19465761f503ebb12667b83eea84f` (2026-02-16). The upstream is now at `302fa03f4164094d6938ea3243889963230576d4` with ~50 commits. Key contract-relevant changes that affect the adapter:
- Node role now requires device identity during WS connect (ddcb2d79b)
- `allowInsecureAuth` config flag deprecated; only `dangerouslyDisableDeviceAuth` remains (protocol.md change)
- Auth surface split: `authorizeGatewayConnect` is now two separate functions for HTTP vs WS (36a0df423)
- Role policy and connect policy extracted to separate modules (51149fcaf)

These changes do NOT affect the HTTP API contract (/v1/responses, /tools/invoke) -- only the WS protocol.

## Implementation

### File: `/Users/ramirosalas/workspace/agentic_reference_architecture/POC/packs/openclaw/pack.v1.json`

Update the `upstream` block:
```json
"upstream": {
    "repo": "/Users/ramirosalas/workspace/openclaw",
    "branch": "main",
    "commit": "302fa03f4164094d6938ea3243889963230576d4"
}
```

Update `pack_version` to today:
```json
"pack_version": "2026-02-21"
```

Add a new `upstream_changelog` section documenting absorbed changes:
```json
"upstream_changelog": [
    {
        "from_commit": "5d40d47501",
        "to_commit": "302fa03f41",
        "date": "2026-02-21",
        "http_api_changes": "none",
        "ws_protocol_changes": [
            "node role now requires device identity during connect (ddcb2d79b)",
            "allowInsecureAuth config deprecated; only dangerouslyDisableDeviceAuth honored (protocol.md)",
            "auth surface refactored: separate HTTP vs WS authorize functions (36a0df423)",
            "role-policy and connect-policy extracted to separate modules (51149fcaf)"
        ],
        "adapter_impact": "WS adapter updated to enforce device-identity for node role"
    }
]
```

### File: `/Users/ramirosalas/workspace/agentic_reference_architecture/POC/packs/openclaw/pack.v1.json`

Also update `adapter_contract.gateway_guardrails.decision_contract.deny_codes` to add:
```json
"ws_device_required"
```

## Acceptance Criteria

1. [AC1] `pack.v1.json` upstream.commit matches current OpenClaw HEAD (`302fa03f4164094d6938ea3243889963230576d4`).
2. [AC2] `pack_version` is updated to `2026-02-21`.
3. [AC3] `upstream_changelog` array exists with one entry documenting the absorbed changes from 5d40d47501 to 302fa03f41.
4. [AC4] `deny_codes` array includes `ws_device_required`.
5. [AC5] `jq . packs/openclaw/pack.v1.json` produces valid JSON (no syntax errors).

## Testing Requirements
### Unit tests (mocks OK)

- None needed -- this is a configuration file update.

### Integration tests (MANDATORY, no mocks)

- Add a test case to the app-pack validation or create a new one:
  ```bash
  jq -e ".upstream.commit" packs/openclaw/pack.v1.json | grep -q "302fa03f4"
  jq -e ".upstream_changelog | length > 0" packs/openclaw/pack.v1.json
  ```
- If `make app-pack-model-validate` exists, run it and confirm it passes.

### Test commands

```bash
jq . packs/openclaw/pack.v1.json  # valid JSON
make app-pack-model-validate      # if exists
```

## Scope Boundary

Scope: Pack config only. File modified:
- `packs/openclaw/pack.v1.json`
No changes to: adapter code, core gateway, middleware, policy engine, tests.

## Dependencies

Depends on Story oc-a39 (WS adapter device-identity fix) being complete, because the changelog documents the adapter change.

MANDATORY SKILLS TO REVIEW:
- None identified. JSON configuration editing, no specialized skill requirements.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T02:10:22Z dep_added: blocks oc-b9w

## Links
- Parent: [[oc-6bq]]
- Blocks: [[oc-b9w]]
- Blocked by: [[oc-a39]]
- Follows: [[oc-a39]]
- Led to: [[oc-b9w]]

## Comments

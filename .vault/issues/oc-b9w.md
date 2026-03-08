---
id: oc-b9w
title: "Run full OpenClaw port validation campaign and fix any drift in e2e scripts"
status: closed
priority: 1
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T19:57:51Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:22Z
content_hash: "sha256:34c34e019bfc208a4479eb6b2691808fa29d574c8eb61480655b84ba435113e1"
closed_at: 2026-02-21T20:12:00Z
close_reason: "COMPLETED: Full OpenClaw port validation campaign passed.\n\nVALIDATION RESULTS:\n1. Port Campaign (validate_openclaw_port_campaign.sh): EXIT 0 -- all 4 suites pass\n   - required_integration_suite: PASS (2s)\n   - openclaw_gateway_unit_suite: PASS (4s)\n   - openclaw_parser_unit_suite: PASS (0s)\n   - openclaw_integration_authz_audit_suite: PASS (2s)\n\n2. Campaign JSON (openclaw-port-campaign-2026-02-21.json): summary.fail == 0\n\n3. Operations Runbook Pack (validate_openclaw_operations_runbook_pack.sh): EXIT 0\n   - All runbook assertions pass\n   - Drill artifact refreshed to 2026-02-21 via live Docker Compose drill\n\n4. Full Suite Regression (go test -race -count=1 ./...): ALL PASS\n   - 15 packages tested, 0 failures\n\n5. Pack Model Validation (make app-pack-model-validate): ALL PASS\n\nTEST COUNTS:\n- Gateway unit tests: 7 top-level (11 leaf with subtests including node-device-identity)\n- Parser unit tests: 4\n- Integration tests: 5 top-level (12 leaf with subtests)\n- New oc-a39 subtests captured: node_without_device_identity_denied, node_with_device_identity_allowed, operator_without/with_device_identity_allowed, device_required_audit\n\nCHANGES MADE:\n- tests/e2e/validate_openclaw_port_campaign.sh: updated default date stamp from 2026-02-16 to 2026-02-21\n\nAC VERIFICATION:\n\n| AC  | Requirement | Status |\n|-----|-------------|--------|\n| AC1 | validate_openclaw_port_campaign.sh exits 0 | PASS |\n| AC2 | Campaign JSON summary.fail == 0 | PASS |\n| AC3 | validate_openclaw_operations_runbook_pack.sh exits 0 | PASS |\n| AC4 | New oc-a39 test names captured in campaign log | PASS |\n| AC5 | No regressions in existing tests | PASS |\n\nCommit: 2601e03 on main"
blocked_by: [oc-0bl, oc-a39]
parent: oc-6bq
blocks: [oc-sdh]
follows: [oc-0bl]
led_to: [oc-sdh]
---

## Description
## User Story

As a gateway operator, I need the full OpenClaw port validation campaign (`validate_openclaw_port_campaign.sh`) to pass end-to-end, confirming that all unit tests, integration tests, and e2e validations reflect the updated adapter behavior and upstream contract.

## Context and Business Value

The port validation campaign at `tests/e2e/validate_openclaw_port_campaign.sh` orchestrates four test suites:
1. `required_integration_suite` -- `go test ./tests/integration/... -run "OpenClaw|Security|Adversarial"`
2. `openclaw_gateway_unit_suite` -- `go test ./internal/gateway/... -run "OpenClaw"`
3. `openclaw_parser_unit_suite` -- `go test ./internal/integrations/openclaw/...`
4. `openclaw_integration_authz_audit_suite` -- `go test ./tests/integration/... -run "GatewayAuthz_OpenClawWSDenyMatrix|AuditOpenClawWSCorrelation"`

After Story oc-a39 adds the node-role device-identity enforcement and new test cases, the campaign must be re-run to confirm zero failures. The campaign also produces machine-readable JSON at `tests/e2e/artifacts/openclaw-port-campaign-<stamp>.json`.

Additionally, the operations runbook pack validation (`validate_openclaw_operations_runbook_pack.sh`) depends on drill artifacts and runbook files. This story ensures those also validate correctly or documents any required updates.

## Implementation

### Step 1: Run the port validation campaign

```bash
cd /Users/ramirosalas/workspace/agentic_reference_architecture/POC
OPENCLAW_CAMPAIGN_DATE=2026-02-21 bash tests/e2e/validate_openclaw_port_campaign.sh
```

### Step 2: If any checks fail, investigate and fix

- The campaign runs Go test suites -- any new test failures from Story oc-a39 changes must be diagnosed.
- If the campaign script itself needs updating (e.g., new test names to include), update it.

### Step 3: Run the operations runbook pack validation

```bash
bash tests/e2e/validate_openclaw_operations_runbook_pack.sh
```
This validates:
- Incident triage runbook references correct endpoints and test names
- Rollback runbook references correct commands
- Ownership matrix has all required controls
- Drill JSON artifact is fresh and all steps pass

### Step 4: Update the campaign date stamp

If the campaign JSON was generated with a different date, update the `OPENCLAW_CAMPAIGN_DATE` default in the script to `2026-02-21`.

## Acceptance Criteria

1. [AC1] `validate_openclaw_port_campaign.sh` exits with status 0 (all checks pass).
2. [AC2] Campaign JSON at `tests/e2e/artifacts/openclaw-port-campaign-2026-02-21.json` shows `summary.fail == 0`.
3. [AC3] `validate_openclaw_operations_runbook_pack.sh` exits with status 0, or any blockers are documented as known issues for separate resolution.
4. [AC4] New test names from Story oc-a39 (e.g., node-device-identity subtests) are correctly captured in the campaign log.
5. [AC5] No regressions in the existing 10 unit tests + 4 integration tests that were passing before this epic.

## Testing Requirements
### Unit tests (mocks OK)

- No new unit tests -- this story validates existing ones.

### Integration tests (MANDATORY, no mocks)

- The campaign itself runs integration tests. Success of the campaign IS the integration test evidence.

### Test commands

```bash
OPENCLAW_CAMPAIGN_DATE=2026-02-21 bash tests/e2e/validate_openclaw_port_campaign.sh
bash tests/e2e/validate_openclaw_operations_runbook_pack.sh
```

## Scope Boundary

Scope: E2E validation scripts and artifacts. Files potentially modified:
- `tests/e2e/validate_openclaw_port_campaign.sh` -- update date stamp default if needed
- `tests/e2e/artifacts/` -- new campaign output files (generated)
No changes to: adapter code, core gateway, middleware, policy engine.

## Dependencies

Depends on Story oc-a39 (WS adapter fix) and Story oc-0bl (pack config update) being complete.

MANDATORY SKILLS TO REVIEW:
- None identified. Shell scripting, test execution. No specialized skill requirements.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T02:10:22Z dep_added: blocks oc-sdh

## Links
- Parent: [[oc-6bq]]
- Blocks: [[oc-sdh]]
- Blocked by: [[oc-0bl]], [[oc-a39]]
- Follows: [[oc-0bl]]
- Led to: [[oc-sdh]]

## Comments

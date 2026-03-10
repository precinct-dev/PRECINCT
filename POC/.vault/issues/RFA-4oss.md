---
id: RFA-4oss
title: "CLI tool-plane still permits arbitrary shell execution via bash -c"
status: closed
priority: 0
type: bug
labels: [release-sanity, security, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T04:55:56Z
created_by: ramirosalas
updated_at: 2026-03-10T13:47:59Z
content_hash: "sha256:a4ce5623113c4f108e34c320e79084ab89488d620d39d3b0b9071a629ac60556"
follows: [RFA-aszr]
closed_at: 2026-03-10T13:47:59Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: The default high-risk CLI capability allows `bash`, while enforcement only denies a short token list inside args.
- Evidence:
  - `tool.highrisk.cli` allows `bash`: internal/gateway/phase3_plane_stubs.go:260.
  - CLI enforcement only checks a denylist like `;`, `&&`, `||`, `|`, `$(`, backticks, `>`, `<`: internal/gateway/phase3_plane_stubs.go:443.
- Impact: A payload such as `command=bash`, `args=["-c","touch /tmp/pwned"]` contains no blocked token yet grants full script execution, which undermines the shell-injection-prevention claim.

## Acceptance Criteria
1. Shell interpreter escape modes such as `bash -c` / `sh -c` are blocked by policy.
2. The allowed CLI model aligns with the documented shell-injection prevention claim.
3. Tests explicitly cover blocked interpreter/script invocations and allowed safe commands.

## Testing Requirements
- Add negative tests for `bash -c`, `sh -c`, and equivalent script-evaluation paths.
- Preserve coverage for allowed read-only or explicitly permitted safe commands.

## nd_contract
status: new

### evidence
- 2026-03-10 sanity review of phase3 CLI policy code.

### proof
- [ ] AC #1: Interpreter script modes are denied.
- [ ] AC #2: Docs and implementation align on shell mediation guarantees.
- [ ] AC #3: Tests cover blocked and allowed CLI cases.

## Acceptance Criteria


## Design


## Notes
## nd_contract
status: delivered

### evidence
- Final authoritative contract restored at EOF after nd append ordering placed earlier history blocks after the delivery note.
- Updated default high-risk CLI rule to stop allowlisting nested shell interpreter payload commands.
- Added evaluator guard that denies `ash|bash|dash|ksh|sh|zsh` as nested CLI payload commands before action routing.
- Added unit and HTTP-path tests covering blocked `bash -c` / `sh -c` invocations and preserved allowed-command coverage.
- Updated `docs/api-reference.md` to document that CLI-mediated `bash` denies nested shell interpreter invocations.
- `go test ./internal/gateway -run 'TestCLI|TestHasDeniedCLIArgToken|TestIsDeniedCLIInterpreterCommand|TestParseStringSlice|TestCapabilityRegistryV2YAMLParsing|TestMCPProtocolRegressionSafe' -count=1` -> PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/internal/gateway 0.917s`)
- `rg -n 'NotImplementedError|panic\\("todo"\\)|unimplemented!|raise NotImplementedError|return \\{\\}|pass$' internal/gateway/phase3_plane_stubs.go internal/gateway/phase3_tool_cli_test.go docs/api-reference.md` -> PASS (no matches)
- Commit `95f4775d5ee3f7c77fe2968d5fa7dc6c06764abe` on `story/RFA-4oss`

### proof
- [x] AC #1: Nested shell interpreter payload commands are denied for CLI mediation, including `bash -c` and `sh -c`.
- [x] AC #2: The default CLI allowlist and API reference both state the mediated contract without implying nested shell escape paths remain allowed.
- [x] AC #3: Unit and HTTP-path tests cover blocked interpreter invocations and preserved allowed safe commands.


## Implementation Evidence (DELIVERED)

### CI/Test Results
- Commands run:
  - `go test ./internal/gateway -run 'TestCLI|TestHasDeniedCLIArgToken|TestIsDeniedCLIInterpreterCommand|TestParseStringSlice|TestCapabilityRegistryV2YAMLParsing|TestMCPProtocolRegressionSafe' -count=1`
  - `rg -n 'NotImplementedError|panic\\("todo"\\)|unimplemented!|raise NotImplementedError|return \\{\\}|pass$' internal/gateway/phase3_plane_stubs.go internal/gateway/phase3_tool_cli_test.go docs/api-reference.md`
- Summary: targeted gateway CLI policy tests PASS; stub scan PASS with no matches.
- Key output:
  - `ok github.com/RamXX/agentic_reference_architecture/POC/internal/gateway 0.917s`
  - `rg` exited `1` with no matches, confirming no stub markers in touched files.

### Commit
- Branch: `story/RFA-4oss`
- SHA: `95f4775d5ee3f7c77fe2968d5fa7dc6c06764abe`

### AC Verification
| AC # | Requirement | Code Location | Test Location | Status |
|------|-------------|---------------|---------------|--------|
| 1 | Shell interpreter escape modes such as `bash -c` / `sh -c` are blocked by policy. | `internal/gateway/phase3_plane_stubs.go` | `internal/gateway/phase3_tool_cli_test.go` (`TestCLIProtocolDeniedNestedShellInterpreterCommand`, `TestCLIIntegrationDeniedNestedShellInterpreterHTTP`) | PASS |
| 2 | Allowed CLI model aligns with the documented shell-injection prevention claim. | `internal/gateway/phase3_plane_stubs.go`, `docs/api-reference.md` | `internal/gateway/phase3_tool_cli_test.go` (`TestCLIProtocolAllowedCommand`, `TestCLIProtocolDisallowedCommand`) | PASS |
| 3 | Tests explicitly cover blocked interpreter/script invocations and allowed safe commands. | `internal/gateway/phase3_tool_cli_test.go` | `internal/gateway/phase3_tool_cli_test.go` | PASS |

## nd_contract
status: delivered

### evidence
- Updated default high-risk CLI rule to stop allowlisting nested shell interpreter payload commands.
- Added evaluator guard that denies `ash|bash|dash|ksh|sh|zsh` as nested CLI payload commands before action routing.
- Added unit and HTTP-path tests covering blocked `bash -c` / `sh -c` invocations and preserved allowed-command coverage.
- Updated `docs/api-reference.md` to document that CLI-mediated `bash` denies nested shell interpreter invocations.
- `go test ./internal/gateway -run 'TestCLI|TestHasDeniedCLIArgToken|TestIsDeniedCLIInterpreterCommand|TestParseStringSlice|TestCapabilityRegistryV2YAMLParsing|TestMCPProtocolRegressionSafe' -count=1` -> PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/internal/gateway 0.917s`)
- `rg -n 'NotImplementedError|panic\\("todo"\\)|unimplemented!|raise NotImplementedError|return \\{\\}|pass$' internal/gateway/phase3_plane_stubs.go internal/gateway/phase3_tool_cli_test.go docs/api-reference.md` -> PASS (no matches)
- Commit `95f4775d5ee3f7c77fe2968d5fa7dc6c06764abe` on `story/RFA-4oss`

### proof
- [x] AC #1: Nested shell interpreter payload commands are denied for CLI mediation, including `bash -c` and `sh -c`.
- [x] AC #2: The default CLI allowlist and API reference both state the mediated contract without implying nested shell escape paths remain allowed.
- [x] AC #3: Unit and HTTP-path tests cover blocked interpreter invocations and preserved allowed safe commands.


## nd_contract
status: in_progress

### evidence
- Claimed: 2026-03-10
- Scope limited to CLI mediation enforcement surfaces per story RFA-4oss.

### proof
- [ ] AC #1: Interpreter script modes are denied.
- [ ] AC #2: Docs and implementation align on shell mediation guarantees.
- [ ] AC #3: Tests cover blocked and allowed CLI cases.


## History
- 2026-03-10T13:47:59Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-aszr]]

## Comments

## nd_contract
status: delivered

### evidence
- Final authoritative contract restored at EOF after nd append ordering placed earlier history blocks after the delivery note.
- Updated default high-risk CLI rule to stop allowlisting nested shell interpreter payload commands.
- Added evaluator guard that denies `ash|bash|dash|ksh|sh|zsh` as nested CLI payload commands before action routing.
- Added unit and HTTP-path tests covering blocked `bash -c` / `sh -c` invocations and preserved allowed-command coverage.
- Updated `docs/api-reference.md` to document that CLI-mediated `bash` denies nested shell interpreter invocations.
- `go test ./internal/gateway -run 'TestCLI|TestHasDeniedCLIArgToken|TestIsDeniedCLIInterpreterCommand|TestParseStringSlice|TestCapabilityRegistryV2YAMLParsing|TestMCPProtocolRegressionSafe' -count=1` -> PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/internal/gateway 0.917s`)
- `rg -n 'NotImplementedError|panic\\("todo"\\)|unimplemented!|raise NotImplementedError|return \\{\\}|pass$' internal/gateway/phase3_plane_stubs.go internal/gateway/phase3_tool_cli_test.go docs/api-reference.md` -> PASS (no matches)
- Commit `95f4775d5ee3f7c77fe2968d5fa7dc6c06764abe` on `story/RFA-4oss`

### proof
- [x] AC #1: Nested shell interpreter payload commands are denied for CLI mediation, including `bash -c` and `sh -c`.
- [x] AC #2: The default CLI allowlist and API reference both state the mediated contract without implying nested shell escape paths remain allowed.
- [x] AC #3: Unit and HTTP-path tests cover blocked interpreter invocations and preserved allowed safe commands.

## PM Acceptance
- Reviewed the delivered proof for RFA-4oss against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-4oss` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-4oss` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.

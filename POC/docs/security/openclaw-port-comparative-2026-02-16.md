# OpenClaw Port Comparative Security Posture Report (2026-02-16)

Story: `RFA-l6h6.6.14`

Machine-readable artifact: `POC/docs/security/artifacts/openclaw-port-comparative-2026-02-16.json`

## Binary Recommendation (Current)

**GO** for proceeding beyond framework-gap closure gate.

Decision basis:
- OpenClaw-focused wrapper campaign passes (`4/4` checks).
- Post-gap broad E2E campaign rerun (`bash POC/tests/e2e/run_all.sh`) reports `105 pass / 0 fail / 3 skip`.
- Previously high-severity shortcomings were remediated and accepted/closed (`RFA-4kd5`, `RFA-8a43`, `RFA-p7yw`, `RFA-thkk`, `RFA-ik18`).

## Comparative Security Delta vs Upstream Baseline

### Improvements (validated)
1. Mandatory SPIFFE identity gate on OpenClaw HTTP/WS wrapper paths.
2. Deterministic reason-coded denials with correlation IDs (`decision_id`, `trace_id`).
3. Fail-closed dangerous HTTP tool denial in wrapper lane.
4. WS control-plane surface reduction to explicit allowlist with deny-by-default fallback.

### Unchanged/Residual Risks
1. Tool-registry integrity remains a critical control and must continue to be monitored in each release campaign.
2. Approval lifecycle correctness still depends on preserving isolated control-plane rate-limit behavior.
3. Readiness quality remains sensitive to SPIRE registration discipline and evidence freshness.

## 1:1 Functional Coverage Matrix (In-Scope Surfaces)

| Surface | Coverage | Primary proof |
|---|---|---|
| `POST /v1/responses` | PASS | `TestOpenClawHTTP_OpenResponsesSuccess`, `TestOpenClawHTTP_OpenResponses_Integration` |
| `POST /tools/invoke` | PASS | `TestOpenClawHTTP_ToolsInvokeAllowed`, `TestOpenClawHTTP_DangerousToolDenied`, `TestOpenClawHTTP_ToolsInvoke_Integration` |
| `GET /openclaw/ws` + control methods | PASS | `TestOpenClawWSGatewayProtocol_*`, `TestOpenClawWS_AuthenticatedSuccess_Integration`, `TestGatewayAuthz_OpenClawWSDenyMatrix_Integration` |
| Audit/correlation propagation | PASS | `TestAuditOpenClawWSCorrelation_Integration`, `run_all` audit and middleware-chain checks |

## Adversarial Campaign Outcome

### OpenClaw-targeted campaign (story-specific)
- Command: `bash POC/tests/e2e/validate_openclaw_port_campaign.sh`
- Result: `PASS` (`4/4`)
- Artifact: `POC/tests/e2e/artifacts/openclaw-port-campaign-2026-02-16.json`

### Full E2E campaign (post-gap reassessment)
- Command: `bash POC/tests/e2e/run_all.sh`
- Result: `PASS` (`105 pass / 0 fail / 3 skip`)
- Artifacts:
  - `POC/tests/e2e/artifacts/rfa-t1hb-run-all-20260216T185105Z.log`

## Newly Discovered Shortcomings (Now Resolved)

1. `RFA-4kd5` resolved and accepted.
2. `RFA-8a43` resolved and accepted.
3. `RFA-p7yw` resolved and accepted.
4. `RFA-thkk` resolved and accepted.
5. `RFA-ik18` resolved and accepted.

## Reproducible Command Transcript Summary

1. `go test ./tests/integration/... -run 'OpenClaw|Security|Adversarial' -count=1` -> PASS (`POC/tests/e2e/artifacts/openclaw-port-go-test-2026-02-16.log`)
2. `bash POC/tests/e2e/run_all.sh` -> PASS (`105 pass / 0 fail / 3 skip`, latest-source reassessment run at `POC/tests/e2e/artifacts/rfa-t1hb-run-all-20260216T185105Z.log`)
3. `bash POC/tests/e2e/validate_openclaw_port_campaign.sh` -> PASS (`4/4`)

## AC-by-AC Evidence Table

| AC | Requirement | Evidence | Status |
|---|---|---|---|
| 1 | 1:1 functional coverage matrix for in-scope OpenClaw surfaces | Matrix above + HTTP/WS unit/integration suites + adapter docs | PASS |
| 2 | Comparative posture report with improvements, unchanged risks, residual gaps | This report + JSON artifact delta sections | PASS |
| 3 | Adversarial campaign proves deterministic denial/containment for critical abuse paths | OpenClaw campaign pass + WS/HTTP deny tests + reason-coded denial evidence | PASS |
| 4 | Binary GO/NO-GO with explicit rationale and follow-up remediation | **GO** decision + linked post-gap reassessment evidence (`RFA-l6h6.6.17.1`) | PASS |

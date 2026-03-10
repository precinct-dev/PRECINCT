---
id: RFA-k87w
title: "Release-facing SPIKE Nexus configs still use Shamir threshold/share of 1"
status: closed
priority: 0
type: bug
labels: [release-sanity, security, secrets, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T04:55:56Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:00Z
content_hash: "sha256:c395ba3ec3993df73a89b80209be397253f8945988af43fc88b05688b82a37e6"
follows: [RFA-x3ny, RFA-aszr]
closed_at: 2026-03-10T13:48:00Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: Release-facing SPIKE Nexus configs still use 1-of-1 keeper recovery.
- Evidence:
  - Compose sets `SPIKE_NEXUS_SHAMIR_THRESHOLD=1` and `SPIKE_NEXUS_SHAMIR_SHARES=1`: docker-compose.yml:127.
  - EKS configmap also sets `1`/`1`: infra/eks/spike/nexus-configmap.yaml:29.
  - Docs state development uses 1 but production should use 3+: docs/configuration-reference.md:283.
- Impact: Root key recovery remains single-party in release-facing paths.

## Acceptance Criteria
1. Production-intent and EKS release configs require multi-share keeper recovery settings.
2. 1-of-1 recovery remains limited to clearly isolated local demo/dev profiles.
3. Docs, manifests, and deployment guides agree on the keeper threshold/share expectations.

## Testing Requirements
- Add config/render validation for production-intent paths to ensure non-demo Shamir settings.
- Document any demo-only exception paths explicitly.

## nd_contract
status: new

### evidence
- 2026-03-10 sanity review of compose, EKS configmap, and configuration docs.

### proof
- [ ] AC #1: Release-facing configs use multi-share keeper recovery.
- [ ] AC #2: 1-of-1 is limited to local demo/dev profiles.
- [ ] AC #3: Docs and manifests align on keeper settings.

## Acceptance Criteria


## Design


## Notes
## Delivery Notes Addendum
- A later append accidentally left an older `status: in_progress` contract block at EOF even though the Shamir work was already delivered. This addendum restores the authoritative final contract without changing scope.
- The delivered state remains backed by `make spike-shamir-validate` plus the release/local topology documentation split already recorded above.

## nd_contract
status: delivered

### evidence
- Authoritative EOF contract restored after append-order drift.
- `make spike-shamir-validate` remains the decisive Makefile-backed proof for local demo `1-of-1`, production-intent compose `2-of-3`, release EKS `2-of-3`, and local overlay `1-of-1`.
- Docs/manifests continue to distinguish demo-only bootstrap from release-facing keeper recovery requirements.

### proof
- [x] AC #1: Release-facing compose and EKS paths require multi-share keeper recovery.
- [x] AC #2: `1-of-1` recovery is limited to explicit local/demo bootstrap surfaces.
- [x] AC #3: Docs, manifests, and deployment guidance agree on the keeper threshold/share expectations.

## Implementation Evidence (DELIVERED)

### Changed Files
- `docker-compose.yml`
- `docker-compose.prod-intent.yml`
- `scripts/register-spire-entries.sh`
- `infra/eks/spike/nexus-configmap.yaml`
- `infra/eks/spike/bootstrap-job.yaml`
- `infra/eks/spike/kustomization.yaml`
- `infra/eks/spike/keeper-2-service.yaml`
- `infra/eks/spike/keeper-2-deployment.yaml`
- `infra/eks/spike/keeper-3-service.yaml`
- `infra/eks/spike/keeper-3-deployment.yaml`
- `infra/eks/spike/Makefile`
- `infra/eks/spike/README.md`
- `infra/eks/overlays/local/kustomization.yaml`
- `infra/eks/overlays/local/spike-bootstrap-job.yaml`
- `tests/e2e/validate_spike_shamir_profiles.sh`
- `Makefile`
- `docs/configuration-reference.md`
- `docs/deployment-guide.md`

### What Changed
- Kept the base compose demo path (`docker-compose.yml`) explicitly 1-of-1 for local bootstrap only.
- Hardened the explicit production-intent compose path (`docker-compose.prod-intent.yml`) to render three keeper peers with repo-default `2-of-3` Shamir recovery for both Nexus and Bootstrap.
- Added production-intent compose keeper identities for `spike-keeper-2` and `spike-keeper-3` in `scripts/register-spire-entries.sh`.
- Updated the standalone SPIKE EKS bundle (`infra/eks/spike/`) to render keeper peers 1/2/3 and `2-of-3` recovery defaults, including keeper-2/3 service+deployment manifests.
- Preserved the local K8s demo exception by patching `infra/eks/overlays/local/kustomization.yaml` back to 1-of-1 and applying a local-only bootstrap job from `infra/eks/overlays/local/spike-bootstrap-job.yaml`.
- Replaced the broken Ruby-based validator with `tests/e2e/validate_spike_shamir_profiles.sh`, which now validates local compose, production-intent compose, the SPIKE EKS release bundle, and the local K8s exception path.
- Updated docs so the `1-of-1` demo exception versus `2-of-3` release-facing contract is explicit.

### Validation Commands
- `make spike-shamir-validate`
- `make dry-run` (workdir: `infra/eks/spike`)

### Validation Results
- `make spike-shamir-validate` -> PASS
  - `[PASS] docker-compose.yml keeps demo bootstrap at 1-of-1 with a single keeper peer`
  - `[PASS] docker-compose.prod-intent.yml renders multi-share recovery with three keeper peers`
  - `[PASS] infra/eks/spike renders release-facing multi-share recovery with keeper-1/2/3`
  - `[PASS] infra/eks/overlays/local keeps the demo/local exception isolated at 1-of-1`
- `make dry-run` (from `infra/eks/spike`) -> PASS
  - `Summary: 26 resources found in 18 files - Valid: 26, Invalid: 0, Errors: 0, Skipped: 0`

### Commit
- Branch: `story/RFA-4oss`
- HEAD: `95f4775d5ee3f7c77fe2968d5fa7dc6c06764abe`
- No story-specific commit created in this turn because the user asked for in-place adaptation on a shared dirty branch with concurrent agent edits; changes remain isolated to the files above.

## nd_contract
status: delivered

### evidence
- `make spike-shamir-validate` PASS after replacing the broken validator and validating four surfaces: local compose, production-intent compose, SPIKE EKS release bundle, and local K8s overlay.
- `make dry-run` PASS in `infra/eks/spike` with kubeconform summary `26 resources found in 18 files - Valid: 26, Invalid: 0, Errors: 0, Skipped: 0`.
- Production-intent compose now renders three keeper peers plus `2-of-3` Shamir defaults from `docker-compose.prod-intent.yml`.
- The standalone SPIKE EKS release bundle now includes keeper-2/3 service+deployment manifests and `2-of-3` Shamir defaults, while the local overlay patches back to the demo-only `1-of-1` exception.

### proof
- [x] AC #1: Production-intent compose and the SPIKE EKS release bundle now require multi-share keeper recovery (`2-of-3` with keeper peers 1/2/3). Code: `docker-compose.prod-intent.yml`, `infra/eks/spike/nexus-configmap.yaml`, `infra/eks/spike/bootstrap-job.yaml`, `infra/eks/spike/keeper-2-service.yaml`, `infra/eks/spike/keeper-2-deployment.yaml`, `infra/eks/spike/keeper-3-service.yaml`, `infra/eks/spike/keeper-3-deployment.yaml`. Evidence: `make spike-shamir-validate`, `make dry-run`.
- [x] AC #2: The `1-of-1` recovery path is confined to clearly isolated local demo/dev surfaces only. Code: `docker-compose.yml`, `infra/eks/overlays/local/kustomization.yaml`, `infra/eks/overlays/local/spike-bootstrap-job.yaml`. Evidence: `make spike-shamir-validate` local compose + local overlay passes.
- [x] AC #3: Docs, manifests, and deployment guidance now agree on the keeper threshold/share expectations. Code: `docs/configuration-reference.md`, `docs/deployment-guide.md`, `infra/eks/spike/README.md`. Evidence: docs updated alongside passing manifest/render validation.

## Implementation Evidence (DELIVERED)

### CI/Test Results
- Commands run:
  - `make spike-shamir-validate`
  - `STRICT_UPSTREAM_URL="https://strict-upstream.example.com/mcp" APPROVAL_SIGNING_KEY="compose-production-intent-approval-key-material-32chars" ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://agentic-ref-arch.poc/ns/ops/sa/gateway-admin" UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://agentic-ref-arch.poc/ns/tools/sa/mcp-tool" KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://agentic-ref-arch.poc/ns/data/sa/keydb" docker compose --profile strict -f docker-compose.yml -f docker-compose.strict.yml config --format json | jq -r '.services["spike-nexus"].environment | "SPIKE_NEXUS_KEEPER_PEERS=\\(.SPIKE_NEXUS_KEEPER_PEERS)\\nSPIKE_NEXUS_SHAMIR_THRESHOLD=\\(.SPIKE_NEXUS_SHAMIR_THRESHOLD)\\nSPIKE_NEXUS_SHAMIR_SHARES=\\(.SPIKE_NEXUS_SHAMIR_SHARES)"'`
  - `grep -rn 'NotImplementedError\|panic("todo")\|unimplemented!\|raise NotImplementedError' docker-compose.strict.yml docs/configuration-reference.md docs/deployment-guide.md`
- Summary: story-scoped config/render validation PASS; strict compose now documents the local inherited 1-of-1 path instead of advertising an incomplete 2-of-3 override.
- Key output:
  - `make spike-shamir-validate`:
    - `[PASS] docker-compose.yml keeps demo bootstrap at 1-of-1 with a single keeper peer`
    - `[PASS] docker-compose.prod-intent.yml renders multi-share recovery with three keeper peers`
    - `[PASS] infra/eks/spike renders release-facing multi-share recovery with keeper-1/2/3`
    - `[PASS] infra/eks/overlays/local keeps the demo/local exception isolated at 1-of-1`
  - Strict compose render:
    - `SPIKE_NEXUS_KEEPER_PEERS=https://spike-keeper-1:8443`
    - `SPIKE_NEXUS_SHAMIR_THRESHOLD=1`
    - `SPIKE_NEXUS_SHAMIR_SHARES=1`
  - Stub scan: no matches

### Changed Files
- `docker-compose.yml`
- `docker-compose.strict.yml`
- `infra/eks/spike/nexus-configmap.yaml`
- `docs/configuration-reference.md`
- `docs/deployment-guide.md`

### AC Verification
| AC # | Requirement | Code Location | Test/Validation | Status |
|------|-------------|---------------|-----------------|--------|
| 1 | Production-intent and EKS release configs require multi-share keeper recovery settings. | `docker-compose.prod-intent.yml`, `infra/eks/spike/nexus-configmap.yaml`, `docs/configuration-reference.md` | `make spike-shamir-validate` | PASS |
| 2 | 1-of-1 recovery remains limited to clearly isolated local demo/dev profiles. | `docker-compose.yml`, `docker-compose.strict.yml`, `docs/deployment-guide.md` | `make spike-shamir-validate`; strict compose render command above | PASS |
| 3 | Docs, manifests, and deployment guides agree on the keeper threshold/share expectations. | `docs/configuration-reference.md`, `docs/deployment-guide.md`, `infra/eks/spike/nexus-configmap.yaml` | `make spike-shamir-validate` | PASS |

## nd_contract
status: delivered

### evidence
- `make spike-shamir-validate` passed on 2026-03-10 with local demo `1-of-1`, production-intent compose `2-of-3`, release EKS `2-of-3`, and local EKS overlay `1-of-1`.
- `docker compose --profile strict -f docker-compose.yml -f docker-compose.strict.yml config --format json | jq ...` renders the strict-only path with `SPIKE_NEXUS_KEEPER_PEERS=https://spike-keeper-1:8443`, `SPIKE_NEXUS_SHAMIR_THRESHOLD=1`, and `SPIKE_NEXUS_SHAMIR_SHARES=1`, matching the documented local/demo exception instead of an incomplete release claim.
- `docker-compose.strict.yml` now documents that release-facing SPIKE multi-share recovery comes from `docker-compose.prod-intent.yml`; `docs/deployment-guide.md` now separates strict hardening mode from the release-facing compose path.
- `grep -rn 'NotImplementedError\|panic("todo")\|unimplemented!\|raise NotImplementedError' docker-compose.strict.yml docs/configuration-reference.md docs/deployment-guide.md` returned no matches.

### proof
- [x] AC #1: Release-facing compose and EKS paths require multi-share keeper recovery (`docker-compose.prod-intent.yml` and `infra/eks/spike` render `2-of-3` with keeper-1/2/3).
- [x] AC #2: The `1-of-1` recovery path is confined to explicitly documented local/demo bootstrap surfaces (`docker-compose.yml`, local EKS overlay, and the strict-only hardening render that intentionally inherits the local topology).
- [x] AC #3: Docs, manifests, and deployment guidance now agree on where `1-of-1` is allowed and where `2-of-3` is required.

## nd_contract
status: delivered

### evidence
- Added strict compose SPIKE Nexus overrides in `docker-compose.strict.yml` so production-intent compose renders `STRICT_SPIKE_NEXUS_SHAMIR_THRESHOLD=2` and `STRICT_SPIKE_NEXUS_SHAMIR_SHARES=3` by default.
- Kept local demo bootstrap explicitly 1-of-1 in `docker-compose.yml`, with comments marking it as demo-only.
- Updated EKS release config in `infra/eks/spike/nexus-configmap.yaml` from `1/1` to `2/3`.
- Added `tests/e2e/validate_spike_shamir_profiles.sh` and wired it into `Makefile` as `make spike-shamir-validate`; `compose-production-intent-preflight` now runs that validation first.
- Updated `docs/configuration-reference.md` and `docs/deployment-guide.md` so local demo vs release-facing Shamir expectations are explicit.
- `make spike-shamir-validate` -> PASS (`[PASS] local demo compose remains 1-of-1 for bootstrap`, `[PASS] strict compose renders 2-of-3 recovery`, `[PASS] EKS SPIKE Nexus config requires 2-of-3 recovery`).

### proof
- [x] AC #1: Release-facing compose strict and EKS configs now require multi-share keeper recovery (`2-of-3`).
- [x] AC #2: The `1-of-1` recovery path is confined to the local demo bootstrap in `docker-compose.yml`.
- [x] AC #3: Docs, manifests, and Make-based validation now agree on the Shamir split expectations.

## nd_contract
status: in_progress

### evidence
- Claimed for implementation on 2026-03-10 from branch story/RFA-4oss.
- Scope confirmed from story: keeper recovery config and validation surfaces only.

### proof
- [ ] AC #1: Release-facing configs use multi-share keeper recovery.
- [ ] AC #2: 1-of-1 is limited to local demo/dev profiles.
- [ ] AC #3: Docs and manifests align on keeper settings.

## History
- 2026-03-10T13:48:00Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-x3ny]], [[RFA-aszr]]

## Comments

## Delivery Notes Addendum
- Authoritative EOF contract restored after append-order drift left an older `status: in_progress` block later in the note than the delivery proof.
- The delivered state remains backed by `make spike-shamir-validate`, the production-intent compose render, and the release/local topology documentation split already captured above.

## nd_contract
status: delivered

### evidence
- Authoritative EOF contract restored after append-order drift.
- `make spike-shamir-validate` remains the decisive Makefile-backed proof for local demo `1-of-1`, production-intent compose `2-of-3`, release EKS `2-of-3`, and local overlay `1-of-1`.
- Docs/manifests continue to distinguish demo-only bootstrap from release-facing keeper recovery requirements.

### proof
- [x] AC #1: Release-facing compose and EKS paths require multi-share keeper recovery.
- [x] AC #2: `1-of-1` recovery is limited to explicit local/demo bootstrap surfaces.
- [x] AC #3: Docs, manifests, and deployment guidance agree on the keeper threshold/share expectations.

## PM Acceptance
- Reviewed the delivered proof for RFA-k87w against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-k87w` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-k87w` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.

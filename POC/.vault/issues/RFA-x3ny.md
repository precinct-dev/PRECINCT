---
id: RFA-x3ny
title: "EKS staging/prod overlays use tags that admission policy rejects"
status: closed
priority: 0
type: bug
labels: [release-sanity, security, supply-chain, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T04:55:56Z
created_by: ramirosalas
updated_at: 2026-03-10T07:25:27Z
content_hash: "sha256:db382148ca06bdecae1cdda89f599199363e48983b3d61f8466e77631bb9372d"
closed_at: 2026-03-10T07:25:27Z
close_reason: "Accepted: digest-pinned staging/prod overlays, promotion digest rewrites, and render-policy validation independently verified"
led_to: [RFA-565d, RFA-k87w, RFA-83an, RFA-7lrd, RFA-mnw2, RFA-896s, RFA-phtc, RFA-tlml, RFA-j83e, RFA-sn2j, RFA-xsy7, RFA-0udk, RFA-3iip, RFA-ewy4, RFA-quga, RFA-1csi, RFA-dan9, RFA-yekm, RFA-tgov, RFA-gaez]
---

## Description
## Context (Embedded)
- Problem: The staging/prod overlays use mutable image tags, but admission policy denies non-digest images in `gateway` and `tools` namespaces.
- Evidence:
  - Staging uses tags: infra/eks/overlays/staging/kustomization.yaml:22.
  - Prod uses tags: infra/eks/overlays/prod/kustomization.yaml:27.
  - Admission constraint denies non-digest images: infra/eks/admission/constraints/enforce-image-digest.yaml:37.
  - ConstraintTemplate rejects any image without `@sha256:`: infra/eks/admission/constraint-templates/require-image-digest.yaml:63.
- Impact: The documented release overlays are either undeployable or force weakening the supply-chain gate.

## Acceptance Criteria
1. Staging/prod overlays emit digest-pinned image references.
2. Promotion workflow produces the digest-pinned values consumed by those overlays.
3. Rendered manifests satisfy the Gatekeeper digest constraint without exemptions beyond platform-managed images.

## Testing Requirements
- Add a manifest/render validation command in CI that checks staging/prod outputs for digest-pinned images.
- Validate rendered overlays against the existing Gatekeeper rule semantics.

## nd_contract
status: new

### evidence
- 2026-03-10 sanity review of overlays and Gatekeeper policy.

### proof
- [ ] AC #1: Staging/prod overlays are digest-pinned.
- [ ] AC #2: Promotion flow produces digest-pinned overlay values.
- [ ] AC #3: Rendered manifests satisfy the digest policy.

## Acceptance Criteria


## Design


## Notes
## PM Decision
ACCEPTED [2026-03-10]: Independent verification confirms the staging/prod overlays are digest-pinned, promotion rewrites overlays with digests, and rendered overlays satisfy the Gatekeeper digest policy without non-platform exemptions.

## nd_contract
status: accepted

### evidence
- Reviewed delivered proof and the changed workflow/overlay/Makefile surfaces for RFA-x3ny.
- `cd /Users/ramirosalas/workspace/agentic_reference_architecture && rg -n 'NotImplementedError|panic\("todo"\)|unimplemented!\(|raise NotImplementedError|\bpass\b' .github/workflows/promote.yaml POC/infra/eks/overlays/staging/kustomization.yaml POC/infra/eks/overlays/prod/kustomization.yaml POC/tests/e2e/admission/verify-overlay-image-digests.sh POC/Makefile POC/docs/deployment-guide.md POC/infra/eks/gateway/README.md POC/tests/e2e/validate_promotion_identity_policy.sh` -> only benign documentation/make occurrences; no implementation stubs in story scope.
- `cd /Users/ramirosalas/workspace/agentic_reference_architecture/POC && make k8s-overlay-digest-validate OVERLAYS='staging prod'` -> PASS; staging and prod both render digest-pinned gateway/tools workloads with only platform-managed exemptions.
- `cd /Users/ramirosalas/workspace/agentic_reference_architecture/POC && bash tests/e2e/validate_promotion_identity_policy.sh` -> PASS.
- Static review confirmed `.github/workflows/promote.yaml` resolves source refs as tag-or-digest, rewrites overlays via `kustomize edit set image ...@sha256:<digest>`, and runs `make -C POC k8s-overlay-digest-validate OVERLAYS="${TARGET_ENV}"` before optional commit.
- Static review confirmed `POC/Makefile` wires `bash tests/e2e/admission/verify-overlay-image-digests.sh` into `k8s-validate` and exposes `k8s-overlay-digest-validate` as a standalone make-backed validation path.

### proof
- [x] AC #1: `POC/infra/eks/overlays/staging/kustomization.yaml` and `POC/infra/eks/overlays/prod/kustomization.yaml` use digest-pinned image references.
- [x] AC #2: `.github/workflows/promote.yaml` rewrites target overlays with `@sha256:` image refs and validates the rendered target overlay before commit.
- [x] AC #3: `make k8s-overlay-digest-validate OVERLAYS='staging prod'` proved the rendered manifests satisfy the Gatekeeper digest policy with only platform-managed exemptions.

## nd_contract
status: delivered

### evidence
- Final authoritative contract for RFA-x3ny delivery appended after prior in-progress notes.
- Delivered label present.
- Digest overlay, promotion workflow, and render-policy validation evidence recorded above.

### proof
- [x] AC #1: Staging/prod overlays are digest-pinned.
- [x] AC #2: Promotion workflow produces digest-pinned overlay values.
- [x] AC #3: Rendered manifests satisfy the digest policy.

## Implementation Evidence (DELIVERED)

### Files Changed
- `.github/workflows/promote.yaml`
- `POC/infra/eks/overlays/staging/kustomization.yaml`
- `POC/infra/eks/overlays/prod/kustomization.yaml`
- `POC/tests/e2e/admission/verify-overlay-image-digests.sh`
- `POC/Makefile`
- `POC/docs/deployment-guide.md`
- `POC/infra/eks/gateway/README.md`

### CI/Test Results
- Commands run:
  - `bash tests/e2e/admission/verify-overlay-image-digests.sh`
  - `make k8s-overlay-digest-validate OVERLAYS="staging prod"`
  - `bash tests/e2e/admission/verify-admission-manifest-wiring.sh`
  - `bash tests/e2e/validate_promotion_identity_policy.sh`
  - `ruby -e 'require "yaml"; YAML.load_file("/Users/ramirosalas/workspace/agentic_reference_architecture/.github/workflows/promote.yaml"); puts "promote-workflow-yaml-ok"'`
  - `make k8s-validate`
- Summary:
  - `verify-overlay-image-digests.sh`: PASS
  - `make k8s-overlay-digest-validate OVERLAYS="staging prod"`: PASS
  - `verify-admission-manifest-wiring.sh`: PASS
  - `validate_promotion_identity_policy.sh`: PASS
  - promote workflow YAML parse: PASS
  - `make k8s-validate`: FAIL due pre-existing `scripts/k8s-sync-gateway-config.sh --check` drift (`tool-registry.yaml differs from config/tool-registry.yaml`) before the new digest validation block executes.
- Key output:
  - `Overlay staging renders digest-pinned gateway/tools workloads and keeps only platform-managed exemptions.`
  - `Overlay prod renders digest-pinned gateway/tools workloads and keeps only platform-managed exemptions.`
  - `Admission manifest wiring checks passed for dev/staging/prod + local relaxation.`
  - `Promotion identity policy validation passed.`
  - `promote-workflow-yaml-ok`

### Branch
- Branch: `codex/RFA-x3ny`
- Commit: not created in this pass; worktree already contains unrelated in-flight changes outside story scope.

### Wiring
- Promotion workflow now resolves `source_tag` as tag-or-digest, updates overlay image pins with `kustomize edit set image`, and runs `make -C POC k8s-overlay-digest-validate OVERLAYS="${TARGET_ENV}"` before any optional commit.
- `make k8s-validate` now includes `bash tests/e2e/admission/verify-overlay-image-digests.sh` after the admission manifest wiring check.

### AC Verification
| AC # | Requirement | Code Location | Test Location | Status |
|------|-------------|---------------|---------------|--------|
| 1 | Staging/prod overlays emit digest-pinned image references. | `POC/infra/eks/overlays/staging/kustomization.yaml`, `POC/infra/eks/overlays/prod/kustomization.yaml` | `POC/tests/e2e/admission/verify-overlay-image-digests.sh` | PASS |
| 2 | Promotion workflow produces the digest-pinned values consumed by those overlays. | `.github/workflows/promote.yaml` | `POC/tests/e2e/validate_promotion_identity_policy.sh`, `ruby -e ... YAML.load_file(...)` | PASS |
| 3 | Rendered manifests satisfy the Gatekeeper digest constraint without extra exemptions beyond platform-managed images. | `POC/tests/e2e/admission/verify-overlay-image-digests.sh`, `POC/Makefile` | `bash tests/e2e/admission/verify-overlay-image-digests.sh`, `make k8s-overlay-digest-validate OVERLAYS="staging prod"` | PASS |

## nd_contract
status: delivered

### evidence
- Updated staging/prod overlay image transformers from `newTag` to `digest` in the strict EKS overlays.
- Added `POC/tests/e2e/admission/verify-overlay-image-digests.sh` to render staging/prod overlays and enforce the rendered `RequireImageDigest` namespace/exemption semantics against gateway/tools workload images.
- Wired the new digest validation into `POC/Makefile` via `k8s-overlay-digest-validate` and the existing `k8s-validate` flow.
- Updated `.github/workflows/promote.yaml` to resolve source refs as tag or digest, rewrite overlay pins with `kustomize edit set image`, and validate the rendered target overlay before optional commit.
- Command evidence:
  - `bash tests/e2e/admission/verify-overlay-image-digests.sh` -> PASS
  - `make k8s-overlay-digest-validate OVERLAYS="staging prod"` -> PASS
  - `bash tests/e2e/admission/verify-admission-manifest-wiring.sh` -> PASS
  - `bash tests/e2e/validate_promotion_identity_policy.sh` -> PASS
  - `ruby -e 'require "yaml"; YAML.load_file("/Users/ramirosalas/workspace/agentic_reference_architecture/.github/workflows/promote.yaml"); puts "promote-workflow-yaml-ok"'` -> PASS
  - `make k8s-validate` -> FAIL at pre-existing config drift guard: `tool-registry.yaml differs from config/tool-registry.yaml`

### proof
- [x] AC #1: `POC/infra/eks/overlays/staging/kustomization.yaml` and `POC/infra/eks/overlays/prod/kustomization.yaml` now render `@sha256:` image refs for gateway/tools workloads.
- [x] AC #2: `.github/workflows/promote.yaml` now rewrites strict overlay pins via `kustomize edit set image ...@sha256:<digest>` and validates the rendered target overlay.
- [x] AC #3: `POC/tests/e2e/admission/verify-overlay-image-digests.sh` proves staging/prod rendered manifests satisfy the rendered Gatekeeper digest policy with only platform-managed pause-image exemptions.

## nd_contract
status: in_progress

### evidence
- 2026-03-10: Scoped implementation started for staging/prod overlay digest pinning, promotion workflow digest updates, and render-policy validation.

### proof
- [ ] AC #1: Staging/prod overlays are digest-pinned.
- [ ] AC #2: Promotion flow produces digest-pinned overlay values.
- [ ] AC #3: Rendered manifests satisfy the digest policy.

## nd_contract
status: in_progress

### evidence
- Claimed: 2026-03-09

### proof
- [ ] AC #1: Staging/prod overlays are digest-pinned.
- [ ] AC #2: Promotion flow produces digest-pinned overlay values.
- [ ] AC #3: Rendered manifests satisfy the digest policy.

## nd_contract
status: delivered

### evidence
- Final authoritative contract block placed at the end of `## Notes` so the story status resolves to delivered.
- Delivered label present on `RFA-x3ny`.
- Implementation evidence above covers digest-pinned overlays, promotion workflow updates, and render-policy validation.

### proof
- [x] AC #1: Staging/prod overlays are digest-pinned.
- [x] AC #2: Promotion workflow produces digest-pinned overlay values.
- [x] AC #3: Rendered manifests satisfy the digest policy.

## History
- 2026-03-10T07:25:27Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Led to: [[RFA-565d]], [[RFA-k87w]], [[RFA-83an]], [[RFA-7lrd]], [[RFA-mnw2]], [[RFA-896s]], [[RFA-phtc]], [[RFA-tlml]], [[RFA-j83e]], [[RFA-sn2j]], [[RFA-xsy7]], [[RFA-0udk]], [[RFA-3iip]], [[RFA-ewy4]], [[RFA-quga]], [[RFA-1csi]], [[RFA-dan9]], [[RFA-yekm]], [[RFA-tgov]], [[RFA-gaez]]

## Comments

# Biotech Adaptation Reference Path (K8s Baseline + Non-K8s Mapping)

This document defines a concrete adaptation path for small, sensitive biotech
teams that need to expose controlled ML-reasoning workflows to pre-registered
users without weakening the v2.4 security model.

It is a reference architecture and reference implementation map, not a
proprietary environment pack.

Related references:
- `docs/architecture/k8s-hardening-portability-matrix.md`
- `docs/architecture/non-k8s-cloud-adaptation-guide.md`
- `docs/architecture/compose-backport-decision-ledger.md`
- `docs/integrations/neurosymbolic-csv-ingestion-v24.md`

## 1. Minimum Production Posture (Biotech Profile)

### 1.1 Profile Assumptions

- Small technical team (about 5 people, 3 code contributors).
- Sensitive inference domain (bioactive interaction analysis).
- Multi-tenant user-facing gateway with regulated-data exposure risk.
- Requirement to produce machine-readable auditor evidence.

### 1.2 Minimum Architecture (Do Not Go Below This)

1. Identity and transport trust:
- SPIRE/SPIFFE workload identity (`INV-01`)
- mTLS across gateway and internal services (`INV-12`)

2. Control-plane enforcement:
- Gateway 13-layer middleware chain
- OPA authorization before tool/model execution (`INV-02`)
- DLP + response firewall (`INV-03`)

3. Integrity and evidence:
- Hash-chained audit events (`INV-04`)
- Immutable audit retention path for authoritative evidence (`INV-05`)
- Versioned reason-code catalog + conformance checks

4. Runtime guardrails:
- Session/risk controls via KeyDB (`INV-07`)
- Tool registry integrity enforcement (`INV-08`)
- Segmentation and egress allowlists (`INV-09`)
- Runtime hardening and signed-image gates (`INV-10`, `INV-11`)

## 2. K8s-First Implementation Path (Explicit + Testable)

Kubernetes is the reference production baseline.

### 2.1 Baseline Bring-Up and Validation

Run from repository root:

```bash
make -C POC -n k8s-up
make -C POC k8s-validate
make -C POC k8s-runtime-campaign
bash POC/tests/e2e/validate_setup_time.sh k8s --dry-run
bash POC/tests/validate_deployment_patterns.sh
```

### 2.2 Required K8s Evidence Anchors

- Runtime campaign report:
  `docs/architecture/artifacts/k8s-runtime-validation-report.v2.4.json`
- Compose backport ledger:
  `docs/architecture/artifacts/compose-backport-decision-ledger.v2.4.json`
- Immutable audit sink proof path:
  `docs/compliance/immutable-audit-evidence-path.md`

## 3. Non-K8s Mapping Checklist (Invariant Preservation)

When adapting to non-K8s runtimes (for example, managed container services),
all checklist items below must remain true:

- [ ] INV-01..INV-12 are mapped to implemented controls or compensating controls.
- [ ] Every missing K8s primitive has a named compensating control owner.
- [ ] Runtime is explicitly marked as `compose-limited` or `k8s-only` where applicable.
- [ ] Production claims use Kubernetes authoritative evidence for immutable retention.
- [ ] No direct model-provider egress bypasses governed model plane controls.
- [ ] Signed-image policy gates remain required prior to production release.

Validation commands for non-K8s adaptation evidence:

```bash
make -C POC -n up
bash POC/tests/e2e/validate_setup_time.sh compose --dry-run
bash POC/tests/e2e/validate_biotech_adaptation_reference.sh
```

## 4. Control Boundary Rule (Do Not Weaken)

Do not weaken controls to fit runtime constraints.

If a runtime cannot satisfy a required control boundary, the only valid options
are:

1. add a compensating control with equivalent objective and machine-readable evidence,
2. keep the environment as non-production evaluation scope,
3. or reject the adaptation path.

"Equivalent objective" is mandatory; convenience exceptions are not.

## 5. Walkthrough: One Accepted and One Rejected Adaptation

### 5.1 Positive Example (Accepted)

1. Team keeps Kubernetes as production baseline for signed-image admission and immutable retention.
2. Non-K8s runtime is used for evaluation workloads only.
3. Compensating controls are documented for missing NetworkPolicy and admission primitives.
4. Checklist remains fully satisfied and evidence artifacts are generated.

Outcome: accepted.

### 5.2 Negative Example (Rejected)

1. Team deploys production workloads without signed-image admission checks.
2. Gateway egress allowlists are widened to unrestricted internet for convenience.
3. Audit retention is downgraded to mutable local files while still claiming production readiness.

Outcome: rejected for boundary weakening.

## 6. Machine-Readable Checklist Artifact

- `docs/architecture/artifacts/biotech-adaptation-reference-checklist.v1.json`

This artifact records:
- minimum architecture controls,
- k8s-first command validations,
- non-k8s checklist states,
- positive/negative walkthrough outcomes.

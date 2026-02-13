# Immutable Audit Evidence Path (K8s-First)

This guide defines the technical, machine-verifiable path for immutable audit
evidence in Kubernetes, plus explicit Docker Compose fallback boundaries.

## Kubernetes Immutable Sink Validation (Executable)

The reference implementation validates immutable audit sink configuration from
Kustomize-rendered manifests, then emits a machine-readable proof artifact.

Commands:

```bash
kustomize build POC/infra/eks/observability
bash POC/tests/e2e/validate_immutable_audit_sink.sh
```

Expected artifact:

- `POC/tests/e2e/artifacts/immutable-audit-sink-proof.json`

Artifact fields:

- `schema_version` (`audit.immutable_sink.v1`)
- `immutable_sink_verification.configmap_present`
- `immutable_sink_verification.object_lock_mode`
- `immutable_sink_verification.retention_days`
- `immutable_sink_verification.hash_chain_enabled`
- `immutable_sink_verification.irsa_annotation_present`
- `immutable_sink_verification.required_correlation_fields_present`
- `status`

## Evidence Extraction Path

- K8s manifest source: `POC/infra/eks/observability/audit/audit-s3-config.yaml`
- K8s render path: `POC/infra/eks/observability/kustomization.yaml`
- Proof artifact generator: `POC/tests/e2e/validate_immutable_audit_sink.sh`
- Compliance evidence package copy target: `evidence/immutable-audit-sink-proof.json`

## Compose Fallback Boundaries

Docker Compose is not an immutable storage substrate and cannot provide native:

- S3 Object Lock COMPLIANCE mode
- IRSA IAM isolation for bucket write + retention enforcement
- Cloud-provider retention/hold enforcement semantics

### Compensating Checks for Compose

- Hash-chain verification (`prev_hash`) for tamper evidence.
- Off-host log shipping to external immutable-capable storage.
- Restricted file permissions and mount hardening for local audit files.
- Signed export attestations for audit bundles before external archival.

These compensating checks reduce risk in local/dev environments but are not a
substitute for Kubernetes + object-lock-backed immutable retention.

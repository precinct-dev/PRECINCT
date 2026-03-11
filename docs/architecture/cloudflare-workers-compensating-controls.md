# Cloudflare Workers Adaptation and Compensating Controls

Cloudflare Workers is not a Kubernetes runtime. Some controls from the reference
implementation cannot be reproduced 1:1 and require compensating controls.

Use this document with:
- `docs/architecture/non-k8s-cloud-adaptation-guide.md`
- `docs/architecture/k8s-hardening-portability-matrix.md`
- `docs/architecture/cloud-adaptation-playbooks.md`

## What Cannot Be Ported Directly

1. Kubernetes admission controls (Gatekeeper/policy-controller).
2. Kubernetes `NetworkPolicy` semantics.
3. DaemonSet-based node attestation patterns.
4. Kubernetes-native service account federation models as implemented in-cluster.

## Required Compensating Controls (Mandatory)

1. Identity and secrets:
   - Use short-lived tokens and scoped service bindings.
   - Never embed long-lived root credentials in Worker config.
2. Policy enforcement:
   - Enforce allow/deny decisions in the gateway/application layer before tool call execution.
   - Keep deny-by-default for unknown tools/paths.
3. Supply-chain integrity:
   - Shift admission checks left to CI/CD release gates.
   - Fail release if signature, digest, or provenance checks fail.
4. Egress and segmentation:
   - Enforce destination allowlists at Worker and account/network policy layers.
   - Block direct bypass routes to protected tool endpoints.
5. Audit and retention:
   - Preserve tamper-evident audit chaining in app logs.
   - Export authoritative audit events to immutable storage with retention policy.
6. DLP and response controls:
   - Keep request/response scanning active in gateway logic.
   - Maintain token substitution invariants so agents never receive raw secrets.

## Step-by-Step Adaptation Workflow

1. Map controls:
   - Map each invariant from `docs/architecture/non-k8s-cloud-adaptation-guide.md` to Worker-native or compensating controls.
2. Implement fail-closed release gates:
   - Signature/provenance checks must run before deploy and block on failure.
3. Deploy Worker gateway path:
   - Keep middleware order and deny conditions equivalent to the reference.
4. Configure immutable evidence sink:
   - Export audit chain events to immutable storage.
5. Run validation scenarios:
   - unauthorized request denial
   - DLP blocked-content path
   - token substitution and secret non-exposure
   - rate-limit and step-up behaviors
6. Publish evidence pack:
   - machine-readable control results
   - human-readable residual risk summary

## Minimum Acceptance Checklist

- [ ] Every missing K8s primitive has a compensating control with owner.
- [ ] Release is fail-closed on provenance/signature gate failures.
- [ ] Audit chain and immutable retention are proven.
- [ ] Agent secret non-exposure is validated.
- [ ] Residual risks are explicit and accepted.

If any checklist item is missing, adaptation is NO-GO.

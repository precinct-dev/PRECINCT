# Non-K8s Cloud Container Adaptation Guide (No Proprietary Pack)

This guide describes how to adapt the reference architecture to non-Kubernetes cloud
container runtimes without weakening core security invariants. It does not provide a
turnkey environment pack for any proprietary platform.

Related references:
- `docs/architecture/k8s-runtime-validation-campaign.md`
- `docs/architecture/compose-backport-decision-ledger.md`
- `docs/architecture/cloud-adaptation-playbooks.md`
- `docs/architecture/cloudflare-workers-compensating-controls.md`

## Scope and Boundary

- Goal: preserve v2.4 control boundaries when Kubernetes-native primitives are absent.
- In scope: runtime-agnostic invariant mapping, compensating controls, operator checklist, anti-patterns.
- Out of scope: cloud-specific IaC bundles, one-click deployment packs, vendor lock-in templates.

Hard rule: do not weaken invariants to fit runtime limitations. If a runtime cannot
support a required control, implement compensating controls and record an explicit risk
acceptance decision.

## Runtime-Agnostic Core Invariant Mapping

| Invariant ID | Core Invariant | Runtime-Agnostic Enforcement Requirement | Reference Implementation Anchor |
|---|---|---|---|
| INV-01 | Verified workload identity for every request | Every request must carry a cryptographically verifiable workload identity bound to transport | `SPIFFEAuth` middleware and SPIRE integration |
| INV-02 | Policy-based authorization before tool execution | Authorization decisions must occur before any upstream tool call | Embedded OPA middleware policy path |
| INV-03 | Request and response DLP controls | Payloads must be inspected inbound and outbound with deny/transform actions | `DLPMiddleware` + `ResponseFirewall` |
| INV-04 | Tamper-evident audit trail | Every decision must emit structured audit entries with chain linkage | Audit middleware hash chain + reason codes |
| INV-05 | Immutable retention path for authoritative audit evidence | Regulated evidence must be written to immutable retention storage | Immutable audit sink path (K8s authoritative) |
| INV-06 | Secret non-exposure to calling agents | Agents must never receive raw high-value credentials | Token substitution + SPIKE redeemer |
| INV-07 | Stateful risk and session controls | Session context and rate limits must persist across requests and instances | KeyDB-backed session/rate storage |
| INV-08 | Tool registry integrity enforcement | Tool metadata integrity and scope validation must be enforced at runtime | Tool registry hash + scope verification |
| INV-09 | Segmentation and egress boundary controls | Runtime must constrain lateral movement and unauthorized egress | K8s policies or compensating network controls |
| INV-10 | Hardened runtime execution profile | Workloads must run with least privilege and restricted execution settings | Pod Security Admission or compensating runtime guardrails |
| INV-11 | Supply-chain integrity gate before runtime admission | Unsigned/unapproved images must be blocked before production rollout | cosign/policy controller + Gatekeeper equivalents |
| INV-12 | Encryption in transit and at rest for sensitive state | Sensitive data must be protected in transport and persistent storage | mTLS everywhere + encrypted persistent state |

## Missing Kubernetes Primitive Compensating Controls

| Missing K8s Primitive | Risk if Missing | Compensating Controls for Non-K8s Runtimes |
|---|---|---|
| NetworkPolicy | East-west movement and broad egress paths | Dedicated subnets, strict security groups/ACLs, explicit outbound allowlists, gateway destination pinning |
| Pod Security Admission | Over-privileged containers may start | Enforce `non-root`, read-only rootfs, dropped capabilities, seccomp/apparmor profiles, CI policy checks |
| Admission webhooks (cosign/Gatekeeper) | Untrusted images can deploy | CI/CD promotion gates for signature verification, digest pinning checks, registry allowlist checks |
| IRSA workload IAM federation | Static cloud credentials leakage risk | Short-lived workload identity federation (OIDC/JWT), per-service scoped credentials, credential rotation automation |
| k8s_psat node attestation | Weaker node bootstrap trust model | Strong bootstrap identity process, attestation evidence logging, narrower trust domains for non-prod runtimes |
| Encrypted PVC defaults | Persistent state may be unencrypted | Managed disk encryption with CMKs, encrypted datastore backends, key rotation and key custody evidence |

## Verification Checklist (Operator Sign-Off)

Use this checklist to sign off a non-K8s adaptation:

- [ ] INV-01 to INV-12 are each mapped to an implemented control with evidence.
- [ ] Every missing K8s primitive has an explicit compensating control and evidence owner.
- [ ] Audit evidence path states whether retention is authoritative or non-authoritative.
- [ ] No control is downgraded to "best effort" without explicit risk acceptance.
- [ ] All production secrets use short-lived identity-backed access paths.
- [ ] Pre-deploy policy gates block unsigned or unapproved images.
- [ ] Runtime hardening baselines are enforced (non-root, capabilities, read-only rootfs).
- [ ] Segmentation and outbound allowlists are validated against tool destinations.

### Sample Validation Commands Against This Reference Implementation

```bash
make -C POC -n up
make -C POC k8s-validate
bash POC/tests/e2e/validate_k8s_hardening_guide.sh
bash POC/tests/e2e/validate_setup_time.sh compose --dry-run
bash POC/tests/validate_deployment_patterns.sh
```

## Anti-Patterns (Do Not Do This)

1. Disabling policy enforcement to make a platform "work quickly".
2. Replacing identity-based auth with long-lived static API keys.
3. Treating Compose-only controls as production-equivalent evidence.
4. Dropping audit chain or retention guarantees for operational convenience.
5. Allowing unrestricted egress from gateway or tool runtime.

## Adaptation Scenario Walkthrough (One Positive, One Negative)

Scenario: adapting to a managed container runtime that lacks Kubernetes admission
controllers and NetworkPolicy primitives.

### Positive Path (Accepted)

1. Map INV-01..INV-12 to runtime controls and assign evidence owners.
2. Implement compensating controls for missing admission and network primitives.
3. Enforce signature and digest checks in CI/CD before deploy.
4. Validate runtime hardening profile and destination allowlists.
5. Record immutable audit evidence source as Kubernetes-authoritative where required.
6. Complete checklist with links to machine-readable evidence outputs.

Outcome: adaptation is accepted because invariants are preserved without claiming false
platform parity.

### Negative Path (Rejected)

1. Team cannot enforce image signature checks and requests an exception.
2. Segmentation remains open with unrestricted outbound internet access.
3. Audit retention is downgraded to mutable local log files for production claims.
4. Checklist marks controls as "not applicable" without compensating controls.

Outcome: adaptation is rejected. The design weakens invariant boundaries and violates
the do-not-weaken rule for production posture.

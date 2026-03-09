# PRECINCT

**Policy-driven Runtime Enforcement & Cryptographic Identity for Networked Compute and Tools**

[precinct.dev](https://precinct.dev)

---

PRECINCT is an open-source security reference architecture for agentic AI systems. It defines the controls, contracts, and enforcement patterns needed to deploy autonomous AI agents safely in production environments.

## What PRECINCT Provides

- **Zero-trust identity** -- Cryptographic agent identity via SPIFFE/SPIRE, eliminating shared secrets
- **Policy enforcement** -- OPA-based authorization at every tool call, model invocation, and data access
- **Multi-agent governance** -- RLM lineage tracking with subcall budgets, loop state machine with operator halt (human kill switch), and 8-dimension immutable budget enforcement
- **Context memory tiering** -- Four-tier classification (ephemeral/session/long_term/regulated) with DLP enforcement and step-up gating
- **Ingress security** -- Canonical connector envelope validation with SPIFFE source principal matching, SHA-256 payload content-addressing, and replay detection
- **Shell injection prevention** -- CLI tool adapter with command allowlists, max-args limits, and denied-arg-token detection
- **Audit contracts** -- Structured decision records for every gateway action, enabling compliance and forensics
- **Supply-chain integrity** -- Signed container images and provenance verification for all components
- **Compliance mappings** -- Pre-built profiles for SOC 2, HIPAA, PCI-DSS, GDPR, and FedRAMP

## Repository Structure

```
POC/                          Reference implementation (Go gateway, Python agents, Docker/K8s infra)
precinct-reference-architecture.md   Full architecture specification
precinct-executive-narrative.md      Executive summary
precinct-compliance-raci-mapping.md  Compliance RACI matrix
precinct-stride-pasta-assurance.md   Threat modeling (STRIDE/PASTA)
precinct-production-readiness-gaps.md Production gap analysis
precinct-production-closure-architecture.md  Gap closure plan
precinct-security-review.md          Security review report
```

## Quick Start

See [POC/README.md](POC/README.md) for the reference implementation, including Docker Compose and Kubernetes deployment guides.

## License

See [LICENSE](LICENSE) for details.

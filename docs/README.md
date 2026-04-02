# PRECINCT Documentation

**Policy-driven Runtime Enforcement and Cryptographic Identity for Networked Compute and Tools**

PRECINCT is an open-source security reference architecture for agentic AI systems. It defines the controls, contracts, and enforcement patterns needed to deploy autonomous AI agents safely in production environments, built around five core pillars: SPIFFE/SPIRE (workload identity), SPIKE (secrets management), OPA (authorization), the PRECINCT Gateway (inline enforcement), and OpenTelemetry (observability).

This directory is the documentation hub for the project. The reference implementation lives at the repository root.

---

## Start Here

If you are new to PRECINCT, begin with these documents in order:

1. [Securing Agentic AI -- Reference Architecture](securing-agentic-ai-reference-architecture.md) -- High-level narrative explaining the problem space and PRECINCT's approach
2. [Prerequisites](getting-started/prerequisites.md) -- Tools and versions required to run the reference implementation
3. [Deployment Guide](deployment-guide.md) -- Step-by-step instructions for Docker Compose and Kubernetes deployment
4. [Architecture Reference](architecture/reference-architecture.md) -- The full architecture specification (v2.5, 200+ pages)

---

Live planning and backlog state are tracked in `nd`. Repository-backed release-readiness
state is captured in `docs/status/production-readiness-state.json`.

---

## Getting Started

| Document | Description |
|----------|-------------|
| [Prerequisites](getting-started/prerequisites.md) | Required tools and minimum versions for Docker Compose and Kubernetes deployments |
| [Deployment Guide](deployment-guide.md) | Consolidated deployment guide covering Docker Compose, local Kubernetes, and EKS |
| [Docker MCP Setup](docker-mcp-setup.md) | How to configure and run the Docker MCP server to provide tools to the security gateway |

---

## Architecture

| Document | Description |
|----------|-------------|
| [Reference Architecture](architecture/reference-architecture.md) | Full architecture specification (v2.5): identity, authorization, secrets, gateway, observability, and threat coverage |
| [Production Closure Architecture](architecture/production-closure.md) | Concrete architecture extensions to close production-readiness gaps from the v2.3 baseline |
| [Deployment Patterns](architecture/deployment-patterns.md) | Classification of all security controls by deployment mode: Universal, K8s-Native, or K8s-Equivalent |
| [Cloud Adaptation Playbooks](architecture/cloud-adaptation-playbooks.md) | Step-by-step playbooks for reproducing validated controls on AWS (EKS/Fargate), GCP (GKE), and Azure (AKS) |
| [Non-K8s Adaptation Guide](architecture/non-k8s-cloud-adaptation-guide.md) | How to adapt the architecture to non-Kubernetes runtimes while preserving core security invariants |
| [K8s Hardening and Portability Matrix](architecture/k8s-hardening-portability-matrix.md) | Kubernetes-first hardening guide with explicit portability classifications for each control |
| [App Integration Pack Model](architecture/app-integration-pack-model.md) | How application teams onboard through thin adaptation layers without coupling into gateway core |
| [Cloudflare Workers Compensating Controls](architecture/cloudflare-workers-compensating-controls.md) | Compensating controls for deploying on Cloudflare Workers where K8s primitives are unavailable |
| [Compose Backport Decision Ledger](architecture/compose-backport-decision-ledger.md) | Machine-readable portability decisions for v2.4 features across Docker Compose and Kubernetes |
| [K8s Runtime Validation Campaign](architecture/k8s-runtime-validation-campaign.md) | Checklist and evidence for runtime control-plane validation on Kubernetes |
| [LLMTrace Prompt-Injection Option](architecture/llmtrace-prompt-injection-exploration-option.md) | Exploration of LLMTrace as an optional prompt-injection analysis backend for the gateway |

---

## Security

| Document | Description |
|----------|-------------|
| [STRIDE/PASTA Assurance Mapping](security/stride-pasta-assurance.md) | Mapping of the reference architecture to STRIDE threat classes and the PASTA risk lifecycle |
| [Agentic Zero-Trust FAQ](security/agentic-zero-trust-faq.md) | Answers to recurring stakeholder questions about the zero-trust posture for agent identity, policy, and egress |
| [Security Scan Baseline](security/baseline.md) | Auditable baseline for security scan results and evidence provenance as of 2026-02-15 |
| [Evidence Collection](security/evidence-collection.md) | How to collect and validate security scan evidence for production-readiness reviews |
| [Manifest Policy Controls](security/manifest-policy-controls.md) | Manifest hardening contract for digest-pinned images and Kubernetes privileged-pattern restrictions |
| [Enforcement Profile Selection](security/enforcement-profile-selection.md) | Guide to selecting the correct runtime enforcement profile (dev, prod_standard, prod_regulated_hipaa) |
| [Compose Signature Prerequisite Contract](security/compose-signature-prerequisite-contract.md) | Mandatory prerequisites for fail-closed live signature verification in compose production-intent mode |
| [Control Verification Matrix](security/control-verification-matrix.md) | Evidence gate matrix for security, usability, and blind-spot controls with machine-readable source |
| [Framework Taxonomy Signal Mappings](security/framework-taxonomy-signal-mappings.md) | Mapping of gateway audit signal keys to MITRE ATLAS technique identifiers and OWASP Agentic Top 10 categories |

---

## Compliance

| Document | Description |
|----------|-------------|
| [Compliance Crosswalk and RACI Mapping](compliance/raci-mapping.md) | Compliance crosswalk for SOC 2 Type 2, ISO 27001, CCPA/CPRA, GDPR, and HIPAA with RACI operating model |
| [GDPR Article 30 ROPA](compliance/gdpr-article-30-ropa.md) | Records of Processing Activities as required by GDPR Article 30 |
| [HIPAA Technical Profile](compliance/hipaa-technical-profile.md) | HIPAA technical safeguard mappings limited to controls that can be evidenced from code and runtime artifacts |
| [PCI-DSS Technical Profile](compliance/pci-dss-technical-profile.md) | PCI-DSS technical control mappings with evidence sources from runtime artifacts |
| [Control Taxonomy Technical Scope](compliance/control-taxonomy-technical-scope.md) | Defines which controls are in scope (technical/runtime) and out of scope (organizational/process) for this reference |
| [Evidence Bundle Schema v2](compliance/evidence-schema-v2.md) | Machine-readable compliance evidence bundle schema emitted by the compliance report generator |
| [Immutable Audit Evidence Path](compliance/immutable-audit-evidence-path.md) | Technical, machine-verifiable path for immutable audit evidence in Kubernetes with Compose fallback boundaries |

---

## Operations

| Document | Description |
|----------|-------------|
| [Performance Benchmarks](operations/performance.md) | Latency cost of the 13-middleware security chain with benchmark instructions |
| [Session Data Management](operations/session-management.md) | Operational guide for KeyDB session data, retention policy, and GDPR/CCPA right-to-deletion procedures |
| [SLO/SLI Ownership Matrix](operations/slo-sli-ownership.md) | SLO targets and SLI ownership for gateway availability, policy enforcement, and identity path |
| [Managed Cloud Bootstrap Prerequisites](operations/managed-cloud-bootstrap-prerequisites.md) | Minimum managed-cloud inputs required for staging bootstrap and runtime validation |
| [OpenSearch Observability Profile](operations/opensearch-observability.md) | Optional OpenSearch profile for searchable audit evidence and security operations dashboards |

### Runbooks

| Document | Description |
|----------|-------------|
| [Incident Triage and Response](operations/runbooks/incident-triage-and-response.md) | Incident response procedures for the gateway, SPIRE, SPIKE, KeyDB, and observability path |
| [Rollback Runbook](operations/runbooks/rollback-runbook.md) | Steps to roll back the gateway and runtime posture to the last accepted release candidate |
| [Security Event Response](operations/runbooks/security-event-response.md) | Response procedures for unauthorized access attempts, attestation failures, and policy bypass attempts |
| [Compose Signature Credential Injection](operations/runbooks/compose-signature-credential-injection.md) | Secure operator steps for supplying registry credentials for compose live signature verification |

---

## Reference

| Document | Description |
|----------|-------------|
| [API Reference](api-reference.md) | Authoritative reference for the PRECINCT Gateway HTTP API: endpoints, JSON-RPC protocol, error codes |
| [Configuration Reference](configuration-reference.md) | All environment variables, configuration files, and policy customization options for the gateway and infrastructure |
| [SPIFFE ID Setup](spiffe-setup.md) | SPIFFE ID schema and SPIRE registration process for all workloads in the reference implementation |
| [Supply Chain Images](supply-chain-images.md) | Approved base images pinned by digest with hardening rationale for all containerized services |
| [SPIKE Token Substitution](spike-token-substitution.md) | How the gateway intercepts SPIKE token references and substitutes real secret values at runtime |
| [EKS IaC Approach](eks-iac.md) | OpenTofu-based IaC recommendation for provisioning the EKS cluster |
| [Docker MCP Integration](docker-mcp-integration.md) | Integration plan for the Docker MCP server as a tool proxy, including JSON-RPC protocol details |

---

## SDK and Integration

| Document | Description |
|----------|-------------|
| [Go SDK](../sdk/go/README.md) | Go client for making MCP JSON-RPC tool calls through the gateway, with retry logic and session management |
| [Python SDK](../sdk/python/README.md) | Python client library compatible with PydanticAI, DSPy, LangGraph, CrewAI, or raw HTTP |
| [Sidecar Identity](sidecar-identity.md) | Deploy third-party tools (mcp2cli, DSPy, LangGraph, etc.) with automatic SPIFFE identity via Envoy sidecar -- no code changes required |
| [No-Upstream-Mod Integration Playbook](sdk/no-upstream-mod-integration-playbook.md) | Claim-ready guide for onboarding agent applications without modifying upstream source code |
| [App Pack Authoring Guide](sdk/app-pack-authoring-guide.md) | How application teams author integration packs to onboard to the gateway |
| [Gateway Bypass Conformance](sdk/gateway-bypass-case26-conformance.md) | Conformance spec verifying that agent traffic cannot bypass gateway controls for remote-skill and model paths |

---

## Patterns

| Document | Description |
|----------|-------------|
| [Multi-Agent Orchestration Security Patterns](patterns/multi-agent-orchestration.md) | Security patterns for orchestrator-to-worker delegation through the gateway, including SPIFFE identity flow and audit attribution |
| [Securing Agentic AI -- Reference Architecture](securing-agentic-ai-reference-architecture.md) | Narrative reference architecture describing how PRECINCT governs autonomous agents without changing upstream code |

---

## Ports

| Document | Description |
|----------|-------------|
| [Channel Integration Guide](ports/channel-integration-guide.md) | Current channel support, what happens with unsupported channels, and how to extend -- with or without source code changes |
| [OpenClaw Adaptation](../ports/openclaw/docs/) | Documentation for the OpenClaw port, adapting the reference architecture to the OpenClaw messaging platform |

---

## Executive

| Document | Description |
|----------|-------------|
| [Executive Narrative](executive-narrative.md) | Non-technical narrative for CIO, CISO, CTO, Risk, and Legal audiences explaining the security posture and trade-offs |

---

## Status

| Artifact | Description |
|----------|-------------|
| [Production Readiness State](status/production-readiness-state.json) | Machine-readable release-readiness snapshot validated against the live `nd` state |

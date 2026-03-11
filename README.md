# PRECINCT

**Policy-driven Runtime Enforcement and Cryptographic Identity for Networked Compute and Tools**

[precinct.dev](https://precinct.dev)

---

PRECINCT is a security reference architecture and working implementation for **agentic AI systems** -- autonomous agents that reason about goals, invoke tools, access data, and orchestrate sub-agents.

Traditional security frameworks assume human users and static service accounts. Agents break those assumptions: they generate unpredictable tool calls, chain actions across trust boundaries, and operate at machine speed. PRECINCT addresses this by placing an inline **MCP Security Gateway** between agents and their resources, enforcing identity, authorization, data protection, and audit at every interaction -- without modifying upstream agent code.

## What's in This Repository

This repo contains two things:

| Layer | What it is | Where |
|-------|-----------|-------|
| **Reference Architecture** | A 200+ page specification defining security controls, threat models, compliance mappings, and deployment patterns for securing agentic AI | [`docs/`](docs/) |
| **Working Implementation** | A Go gateway with a 13-layer security middleware chain, Docker Compose and Kubernetes deployments, Go/Python SDKs, and 43 E2E tests that exercise every control against real infrastructure (no mocks) | [`POC/`](POC/) |

### What's Ready to Run

The implementation in `POC/` is a fully functional security gateway you can deploy locally in under five minutes. It includes:

- A **13-layer middleware chain** (size limits, JSON-RPC validation, SPIFFE auth, audit, tool registry, OPA policy, DLP, session tracking, step-up gating, deep scan, rate limiting, circuit breaker, secret injection)
- **Docker Compose** deployment with all supporting infrastructure (SPIRE, SPIKE Nexus, KeyDB, OPA, Phoenix, optional OpenSearch)
- **Kubernetes manifests** (EKS-targeted, with a local overlay for Docker Desktop)
- **Go and Python SDKs** for integrating your own agents
- **43 E2E demo tests** (21 Go + 22 Python) that exercise every middleware layer through the full stack
- **Compliance automation** generating SOC 2, ISO 27001, HIPAA, and PCI-DSS evidence bundles
- **Observability** via OpenTelemetry traces (Phoenix UI) and optional OpenSearch dashboards

### What's a Reference You Adapt

The architecture documents in `docs/` define patterns you adapt to your environment:

- **Cloud adaptation playbooks** for AWS (EKS/Fargate), GCP (GKE), and Azure (AKS) -- step-by-step guides, not deployable IaC
- **Compliance mappings** (SOC 2, HIPAA, PCI-DSS, GDPR, ISO 27001) -- control inventories and RACI matrices you tailor to your org
- **Threat models** (STRIDE/PASTA) -- threat coverage analysis you extend with your own attack surfaces
- **Deployment patterns** -- classification of controls as Universal, K8s-Native, or K8s-Equivalent, so you know what translates to your runtime

## Quick Start

Prerequisites: Docker 25+, Docker Compose 2.24+, Go 1.24.6+, make, bash 4+.

```bash
git clone https://github.com/precinct-dev/PRECINCT.git
cd PRECINCT/POC

make setup            # Interactive setup wizard (configures .env)
make phoenix-up       # Start observability (Phoenix + OTel collector)
make up               # Start all services (SPIRE, SPIKE, KeyDB, gateway, mock MCP)
make demo-compose     # Run 43 E2E tests through the full stack
```

Phoenix trace UI: `http://localhost:6006`

To enable LLM-based deep content scanning (layer 10):

```bash
export GROQ_API_KEY=your-key-here
make down && make up
```

For Kubernetes deployment on Docker Desktop:

```bash
make k8s-up           # Build, push to local registry, deploy to Docker Desktop K8s
make demo-k8s         # Run E2E tests against K8s deployment
```

See the full [Deployment Guide](docs/deployment-guide.md) for production and EKS instructions.

## Architecture at a Glance

```
Agent --> [Size] --> [Shape] --> [Auth] --> [Audit] --> [Registry]
      --> [Policy] --> [DLP] --> [Session] --> [StepUp] --> [DeepScan]
      --> [RateLimit] --> [CircuitBreaker] --> [TokenSub] --> MCP Server
```

| # | Middleware | What It Does |
|---|-----------|-------------|
| 1 | Size Guard | Rejects oversized payloads (configurable, default 10 MB) |
| 2 | Shape Validator | Validates JSON-RPC 2.0 envelope structure |
| 3 | SPIFFE Auth | Cryptographic agent identity via SPIRE SVIDs (mTLS in prod, header in dev) |
| 4 | Audit Logger | Hash-chained structured decision records with OTel spans |
| 5 | Tool Registry | SHA-256 tool hash verification with cosign-attested hot-reload |
| 6 | OPA Policy | Embedded Rego evaluation for tool grants, risk levels, and step-up rules |
| 7 | DLP Scanner | Credential blocking (fail-closed), PII flagging, injection detection |
| 8 | Session Context | KeyDB-backed cross-request exfiltration detection with GDPR delete |
| 9 | Step-Up Gating | Risk-based approval (auto/manual/deny) with configurable thresholds |
| 10 | Deep Scan | LLM-based content analysis via configurable guard model |
| 11 | Rate Limiter | Token bucket per SPIFFE ID via KeyDB (configurable RPM/burst) |
| 12 | Circuit Breaker | Per-tool circuit breaker (closed/open/half-open states) |
| 13 | Token Substitution | SPIKE late-binding secret injection (innermost layer -- security invariant) |

### Control Plane Endpoints

Beyond MCP tool call proxying, the gateway provides five governance planes:

| Endpoint | Plane | Purpose |
|----------|-------|---------|
| `POST /v1/ingress/admit` | Ingress | Envelope validation, SPIFFE source matching, SHA-256 content-addressing, replay detection |
| `POST /v1/context/admit` | Context | Memory tier enforcement (ephemeral/session/long_term/regulated), DLP classification |
| `POST /v1/model/call` | Model | Provider authorization, data residency, HIPAA-aware prompt safety, budget tracking |
| `POST /v1/tool/execute` | Tool | Capability registry, shell-injection prevention, step-up gating |
| `POST /v1/loop/check` | Loop | 8-state governance machine, 8-dimension budget limits, operator halt (kill switch) |

### Supporting Infrastructure

| Component | Role |
|-----------|------|
| [SPIRE](https://spiffe.io/) | SPIFFE workload identity -- cryptographic agent identity without shared secrets |
| [SPIKE Nexus](https://spike.ist/) | Late-binding secrets vault with SPIFFE-based access control |
| [KeyDB](https://docs.keydb.dev/) | Session state persistence, rate-limit counters, exfiltration detection |
| [OPA](https://www.openpolicyagent.org/) | Policy-as-code engine (Rego) for authorization decisions |
| [Phoenix](https://phoenix.arize.com/) + OTel | Distributed tracing and AI observability |
| [OpenSearch](https://opensearch.org/) (optional) | Indexed audit evidence for compliance and forensics |

## Documentation

All documentation lives in [`docs/`](docs/). The [documentation index](docs/README.md) has the complete catalog. Key entry points by audience:

### "I want to understand the architecture"

| Document | Description |
|----------|-------------|
| [Securing Agentic AI](docs/securing-agentic-ai-reference-architecture.md) | Narrative overview -- the problem, the approach, and why existing frameworks fall short |
| [Reference Architecture](docs/architecture/reference-architecture.md) | The full v2.5 specification: identity, authorization, secrets, gateway, observability |
| [Multi-Agent Orchestration Patterns](docs/patterns/multi-agent-orchestration.md) | Security patterns for orchestrator-to-worker delegation through the gateway |

### "I want to deploy and run it"

| Document | Description |
|----------|-------------|
| [Prerequisites](docs/getting-started/prerequisites.md) | Required tools and minimum versions |
| [Deployment Guide](docs/deployment-guide.md) | Step-by-step for Docker Compose, local K8s, and EKS |
| [Configuration Reference](docs/configuration-reference.md) | Every environment variable and config file |
| [API Reference](docs/api-reference.md) | Gateway HTTP API: endpoints, JSON-RPC protocol, error codes |
| [SPIFFE Setup](docs/spiffe-setup.md) | SPIFFE ID schema and SPIRE registration |

### "I want to integrate my own agents"

| Document | Description |
|----------|-------------|
| [Go SDK](POC/sdk/go/README.md) | Go client with retry logic and session management |
| [Python SDK](POC/sdk/python/README.md) | Python client compatible with PydanticAI, DSPy, LangGraph, CrewAI |
| [Integration Playbook](docs/sdk/no-upstream-mod-integration-playbook.md) | How to onboard agent apps without modifying upstream source |
| [App Pack Authoring](docs/sdk/app-pack-authoring-guide.md) | Write thin adaptation layers to connect your app to the gateway |

### "I need compliance and security documentation"

| Document | Description |
|----------|-------------|
| [Security Review](docs/security/security-review.md) | Independent review: threat coverage, trust boundaries, residual risks |
| [STRIDE/PASTA Mapping](docs/security/stride-pasta-assurance.md) | Threat model mapped to STRIDE classes and PASTA risk lifecycle |
| [RACI Mapping](docs/compliance/raci-mapping.md) | SOC 2, ISO 27001, GDPR, HIPAA crosswalk with 10-role RACI |
| [GDPR Article 30 ROPA](docs/compliance/gdpr-article-30-ropa.md) | Records of Processing Activities |
| [HIPAA Technical Profile](docs/compliance/hipaa-technical-profile.md) | Technical safeguard mappings with evidence sources |
| [Zero-Trust FAQ](docs/security/agentic-zero-trust-faq.md) | Answers to recurring stakeholder security questions |

### "I want to adapt this for my cloud"

| Document | Description |
|----------|-------------|
| [Cloud Adaptation Playbooks](docs/architecture/cloud-adaptation-playbooks.md) | Step-by-step for AWS, GCP, Azure |
| [Non-K8s Adaptation](docs/architecture/non-k8s-cloud-adaptation-guide.md) | Adapting to non-Kubernetes runtimes |
| [K8s Hardening Matrix](docs/architecture/k8s-hardening-portability-matrix.md) | Per-control portability classification |
| [Cloudflare Workers](docs/architecture/cloudflare-workers-compensating-controls.md) | Compensating controls for serverless edge |
| [Deployment Patterns](docs/architecture/deployment-patterns.md) | Universal vs K8s-Native vs K8s-Equivalent controls |

### "I want the executive summary"

| Document | Description |
|----------|-------------|
| [Executive Narrative](docs/executive-narrative.md) | CIO/CISO/CTO-level brief on security posture and trade-offs |
| [Current State and Roadmap](docs/current-state-and-roadmap.md) | What is implemented, what is planned |

## Repository Structure

```
docs/                 All documentation (architecture, security, compliance, operations, SDK)
POC/                  Reference implementation
  cmd/gateway/          Gateway binary entrypoint
  internal/gateway/     Gateway core + 13-layer middleware chain
  config/               OPA policies, tool registry, SPIFFE IDs, risk thresholds
  sdk/go/               Go SDK
  sdk/python/           Python SDK
  ports/openclaw/       Example port: securing OpenClaw without modifying its source
  docker/               Dockerfiles for all services
  infra/eks/            Kubernetes manifests (base + EKS + local overlays)
  tests/                Unit, integration, E2E, conformance, and benchmark tests
  tools/compliance/     Compliance report automation
  demo/                 Demo harness (Go + Python test clients, mock MCP server)
  scripts/              Setup, security, and operational scripts
site/                 Project website (precinct.dev)
scripts/              Repository-level scripts
```

## Key Make Targets

Run these from the `POC/` directory:

| Target | Description |
|--------|-------------|
| `make setup` | Interactive setup wizard |
| `make up` | Start Docker Compose stack (waits for healthy) |
| `make down` | Stop stack |
| `make demo-compose` | Run 43 E2E tests (Docker Compose) |
| `make demo-k8s` | Run E2E tests (Kubernetes) |
| `make test` | Run all tests (unit + integration + OPA) |
| `make k8s-up` | Deploy to local Kubernetes |
| `make security-scan` | Run security scans (gosec, trivy) |
| `make compliance-report` | Generate compliance evidence bundle |
| `make phoenix-up` | Start Phoenix observability |
| `make opensearch-up` | Start OpenSearch (optional compliance/forensics) |
| `make help` | Show all available targets |

## Implementation Metrics

| Metric | Value |
|--------|-------|
| Go source | ~16,700 lines |
| Go tests | ~43,300 lines (1,002 test functions) |
| OPA Rego policies | ~2,000 lines (67 policy tests) |
| Kubernetes YAML | ~28,400 lines |
| OpenTofu IaC | ~29,400 lines |
| E2E demo tests | 43 (21 Go + 22 Python) |
| K8s NetworkPolicies | 26 across 6 namespaces |
| Completed epics | 29 |

## Contributing

Contributing guidelines are coming soon. If you find issues or want to discuss the architecture, please open a GitHub issue.

When submitting PRs with known pre-existing test failures, use explicit baseline language in acceptance criteria: declare which tests are already failing and write criteria as "all tests pass OR only baseline failures `<list>` remain."

## License

See [LICENSE](LICENSE) for details.

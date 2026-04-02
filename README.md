<p align="center">
  <img src="docs/assets/precinct-logo.svg" alt="PRECINCT" width="500">
</p>

<p align="center">
  <strong>Policy-driven Runtime Enforcement & Cryptographic Identity for Networked Compute and Tools</strong>
</p>

<p align="center">
  <a href="https://github.com/precinct-dev/PRECINCT/actions/workflows/ci.yml"><img src="https://github.com/precinct-dev/PRECINCT/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/precinct-dev/PRECINCT/actions/workflows/security-scan.yml"><img src="https://github.com/precinct-dev/PRECINCT/actions/workflows/security-scan.yml/badge.svg?branch=main" alt="Security Scan"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://pkg.go.dev/github.com/precinct-dev/precinct"><img src="https://pkg.go.dev/badge/github.com/precinct-dev/precinct.svg" alt="Go Reference"></a>
  <a href="https://precinct.dev"><img src="https://img.shields.io/badge/docs-precinct.dev-00d4aa" alt="Docs"></a>
</p>

---

> Website: [https://precinct.dev](https://precinct.dev)

## What Is This?

This is a **reference implementation of the PRECINCT gateway runtime**. The
latency-sensitive data plane runs in `precinct-gateway`, while admin and
control-plane endpoints run in `precinct-control`. The shared enforcement stack
implements the 13-layer middleware chain for securing AI agent tool calls. It validates the
[PRECINCT v2.5](docs/architecture/reference-architecture.md)
reference architecture, while the current canonical control-plane contract set
in this repository remains [v2.4](contracts/v2.4/contract-set.v2.4.md).

The runtime interposes between AI agents and MCP tool servers, enforcing
authentication, authorization, audit, data-loss prevention, rate limiting,
and secret management at every layer -- without the agents needing to know
about any of it.

```
Agent --> [1.Size] --> [2.Shape] --> [3.Auth] --> [4.Audit] --> [5.Registry]
      --> [6.Policy] --> [7.DLP] --> [8.Session] --> [9.StepUp] --> [10.DeepScan]
      --> [11.RateLimit] --> [12.CircuitBreaker] --> [13.TokenSub] --> MCP Server
```

Two deployment modes are supported: **Docker Compose** (local development) and
**Kubernetes** (EKS-targeted, with a local overlay for Docker Desktop K8s).
Go and Python SDKs are provided for agent integration.

Current service split:

- `precinct-gateway`: data-plane enforcement, upstream MCP mediation, latency-sensitive request path
- `precinct-control`: admin and control-plane APIs protected by the same SPIFFE/SPIRE, OPA, and SPIKE zero-trust contracts


## Architecture at a Glance

| # | Middleware Layer | Description |
|---|-----------------|-------------|
| 1 | Request Size Guard | Rejects oversized payloads (configurable, default 10 MB) |
| 2 | Request Shape Validator | Validates JSON-RPC 2.0 envelope structure |
| 3 | SPIFFE Authentication | Validates SPIFFE identity from mTLS client certs in prod or `X-SPIFFE-ID` in dev |
| 4 | Audit Logger | Decision journal with structured JSON logging + OTel spans |
| 5 | Tool Registry | Verifies tool existence and SHA-256 hash integrity |
| 6 | OPA Policy Engine | Embedded Rego evaluation (tool grants, risk levels, step-up) |
| 7 | DLP Scanner | Credentials detection (always block), PII flagging, injection detection |
| 8 | Session Context | Cross-request exfiltration detection via KeyDB |
| 9 | Step-Up Gating | Risk-based approval flow (auto/manual/deny by risk level) |
| 10 | Deep Scan (Guard Model) | LLM-based content analysis via configurable guard model (default Groq) |
| 11 | Rate Limiter | Token bucket via KeyDB (configurable RPM/burst per SPIFFE ID) |
| 12 | Circuit Breaker | Per-tool circuit breaker (closed/open/half-open states) |
| 13 | Token Substitution | SPIKE late-binding secret injection (MUST be innermost -- security invariant) |

### Control Plane Endpoints (Phase 3)

The gateway exposes per-plane control endpoints for framework-agnostic governance:

| Endpoint | Plane | Function |
|----------|-------|----------|
| `POST /v1/ingress/submit` | Ingress | Canonical envelope validation, SPIFFE source principal matching, SHA-256 payload content-addressing, replay detection (30min nonce TTL). `/v1/ingress/admit` remains a compatibility alias |
| `POST /v1/context/admit` | Context | Memory tier enforcement (ephemeral/session/long_term/regulated), provenance validation, DLP classification |
| `POST /v1/model/call` | Model | Provider authorization, data residency, HIPAA-aware prompt safety, budget tracking |
| `POST /v1/tool/execute` | Tool | Capability registry, CLI shell-injection prevention (command allowlist, max-args, denied-arg-tokens), step-up |
| `POST /v1/loop/check` | Loop | 8-state governance state machine, 8-dimension immutable budget limits, operator halt, provider unavailability |

### Multi-Agent Governance

- **RLM Governance Engine**: Cross-cutting lineage tracking with depth (max 6), subcall (max 64), and budget-unit (max 128) limits. UASGS bypass prevention.
- **Loop State Machine**: 8 states (CREATED, RUNNING, WAITING_APPROVAL, COMPLETED, HALTED_POLICY, HALTED_BUDGET, HALTED_PROVIDER_UNAVAILABLE, HALTED_OPERATOR)
- **Loop Admin API**: `GET /admin/loop/runs`, `GET /admin/loop/runs/<id>`, `POST /admin/loop/runs/<id>/halt` (operator kill switch)
- **CLI Tool Adapter**: Shell injection prevention via command allowlists, max-args, denied-arg-token detection (`;`, `&&`, `||`, `|`, `$(`, `` ` ``, `>`, `<`)
- **Context Memory Tiering**: Four-tier classification with DLP enforcement for `long_term` writes and step-up for `regulated` reads
- **Ingress Connector Envelope**: SPIFFE principal matching, SHA-256 content-addressing, replay detection with composite nonce key + 30min TTL
- **Go SDK SPIKE Token Builder**: `BuildSPIKETokenRef` and `BuildSPIKETokenRefWithScope` functions matching the Python SDK

Supporting infrastructure:

- **SPIRE** -- SPIFFE identity for all workloads (mTLS-ready)
- **SPIKE Nexus** -- Late-binding secret vault with SPIFFE-based access control
- **KeyDB** -- Session state and rate-limit counters
- **OPA** -- Policy-as-code with Rego
- **Phoenix + OTel Collector** -- Distributed tracing and observability
- **OpenSearch + Dashboards (optional)** -- Indexed audit evidence search for compliance operations and forensics


## Third-Party Tool Compatibility

Third-party tools -- mcp2cli, DSPy agents, LangGraph orchestrators, CrewAI, or any
MCP client -- work inside PRECINCT **without modification**. An Envoy sidecar
(`deploy/sidecar/`) runs alongside the tool and automatically injects SPIFFE identity
headers into every request. The tool points at `127.0.0.1:9090`; the sidecar forwards
to the gateway with the correct `X-SPIFFE-ID` header attached.

- Tools do not need SPIFFE-aware code; the sidecar handles identity injection
- Network-level controls (Docker network isolation or Kubernetes NetworkPolicy) ensure
  tools can only reach the gateway -- direct calls to upstream tool servers or model
  providers are blocked
- Full 13-layer security enforcement applies to sidecar-proxied traffic identically
  to SDK-integrated traffic

See [docs/sidecar-identity.md](docs/sidecar-identity.md) for deployment instructions
(Docker Compose and Kubernetes) and SPIRE registration templates.


## Quick Start

Prerequisites: Docker, Docker Compose, Go 1.26.1, make.

```bash
make phoenix-up      # Start observability stack (Phoenix + OTel collector)
make up              # Start all services (SPIRE, SPIKE, KeyDB, gateway, control, mock MCP server)
make demo-compose    # Run 43 E2E demo tests (21 Go + 22 Python)
```

The demo exercises every middleware layer with real requests through the full
stack -- no mocks. Expected output: all 43 tests pass.

To enable deep scan (requires a Groq API key):

```bash
export GROQ_API_KEY=your-key-here
# Restart the stack to pick up the key
make down && make up
```

Phoenix UI is available at `http://localhost:6006` for trace inspection.

Optional compliance/forensics observability profile (Apache-2 stack):

```bash
make opensearch-up
make opensearch-seed
```

OpenSearch Dashboards is available at `http://localhost:5601`.

## Git Hooks (historical beads compatibility)

`nd` is the canonical tracker for current work. The repo still carries a root
`.beads` symlink only for historical hook compatibility when
inspecting older automation or archived branches that still reference `bd`.

If you ever see a pre-commit warning about a missing historical beads database, treat it as
a warning (not a failed commit) and set:

```bash
export BEADS_DIR=.beads  # historical compatibility only
```

from the repository root before committing.

For current delivery workflow, prefer:

```bash
nd ready
nd show <story-id>
nd update <story-id> --status=in_progress
nd update <story-id> --append-notes "<nd_contract block>"
make story-evidence-validate STORY_ID=<story-id>
make tracker-surface-validate
```


## Directory Structure

```
cmd/gateway/              Gateway binary entrypoint
internal/gateway/         Gateway core + 13-layer middleware chain
config/                   OPA policies, tool registry, SPIFFE IDs, risk thresholds
sdk/go/mcpgateway/        Go SDK
sdk/python/               Python SDK
deploy/compose/           Docker Compose files and Dockerfiles
deploy/k8s/               Cloud-agnostic Kubernetes manifests (base + overlays)
deploy/terraform/         EKS-specific Terraform and Kustomize overlays
deploy/sidecar/           Envoy sidecar for automatic SPIFFE identity on third-party tools
deploy/helm/              Helm chart for PRECINCT
tools/compliance/         GDPR/SOC2/ISO27001/NIST compliance automation
docs/                     All documentation
tests/e2e/                E2E demo test suites
tests/integration/        Go integration tests
tests/benchmark/          Load testing scripts
cli/                      PRECINCT CLI
sample-agents/            Reference agent implementations
ports/                    Runtime platform adapters (Discord, Email, OpenClaw)
packs/                    Declarative app integration manifests and validation assets
examples/                 Starter examples for extending the gateway
contracts/                PRECINCT specification versions
scripts/                  Setup and operational scripts
```

Website source lives in the private companion repository:
`https://github.com/precinct-dev/precinct-site`


## Make Commands

| Target | Description |
|--------|-------------|
| `make help` | Show available targets |
| `make setup` | Interactive CLI setup wizard |
| **Core** | |
| `make up` | Start Docker Compose stack (waits for all services healthy) |
| `make down` | Stop Docker Compose stack |
| `make test` | Run all tests (unit + tagged integration + OPA) |
| `make test-unit` | Run unit tests (Go packages + non-tagged suites) |
| `make test-integration` | Run tagged integration tests against an ensured local stack |
| `make test-opa` | Run OPA policy tests |
| `make test-e2e` | Run the full E2E demo suite (Compose + K8s) |
| `make lint` | Run linters (golangci-lint or go fmt/vet) |
| `make clean` | Full cleanup (containers, volumes, build artifacts, logs) |
| `make logs` | Tail gateway logs |
| **Demo** | |
| `make demo` | Run E2E demo (Docker Compose + K8s) and leave both environments up for observation |
| `make demo-compose` | Run E2E demo (Docker Compose only) |
| `make demo-k8s` | Run E2E demo (K8s only) |
| **Phoenix Observability** | |
| `make phoenix-up` | Start Phoenix + OTel collector (persistent traces) |
| `make phoenix-down` | Stop Phoenix stack (preserves trace data) |
| `make phoenix-reset` | Stop Phoenix stack and destroy trace data |
| **OpenSearch Observability (Optional)** | |
| `make opensearch-up` | Start OpenSearch + Dashboards + audit forwarder |
| `make opensearch-seed` | Seed OpenSearch index template and dashboard objects |
| `make opensearch-validate` | Validate OpenSearch health and template wiring |
| `make opensearch-down` | Stop OpenSearch profile (preserves indexed data) |
| `make opensearch-reset` | Stop OpenSearch profile and destroy indexed data |
| `make observability-up` | Start both observability backends (Phoenix + OpenSearch) |
| `make observability-down` | Stop both observability backends (preserves data) |
| `make observability-reset` | Destroy all observability backend data |
| **Kubernetes** | |
| `make k8s-up` | Deploy to local K8s (Docker Desktop; syncs config, builds, deploys) |
| `make k8s-sync-config` | Sync K8s overlay gateway config from canonical config/ source |
| `make k8s-check-config` | Check K8s overlay gateway config for drift (CI use) |
| `make k8s-opensearch-up` | Deploy local K8s stack plus OpenSearch observability extension |
| `make k8s-opensearch-down` | Remove OpenSearch extension resources from local K8s deployment |
| `make k8s-down` | Tear down local K8s deployment |
| **CI / Quality** | |
| `make ci` | Full CI pipeline (lint + test + build) |
| `make security-scan` | Run security scans (gosec, trivy) |
| `make story-evidence-validate STORY_ID=<id>` | Validate evidence paths referenced in an `nd` story |
| `make tracker-surface-validate` | Audit active release workflow surfaces for stale non-archival `bd`/beads references |
| `make benchmark` | Run performance benchmarks (Go microbenchmarks + load test) |
| **Compliance** | |
| `make compliance-report` | Generate SOC2/ISO27001/NIST compliance report |
| `make gdpr-ropa` | Display GDPR Article 30 Record of Processing Activities |
| `make gdpr-delete` | GDPR right-to-erasure (usage: `make gdpr-delete SPIFFE_ID=...`) |


## Documentation

| Document | Description |
|----------|-------------|
| [docs/BUSINESS.md](docs/BUSINESS.md) | Business outcomes and goals |
| [docs/DESIGN.md](docs/DESIGN.md) | User needs, UX/DX design |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Full technical architecture |
| [docs/current-state-and-roadmap.md](docs/current-state-and-roadmap.md) | Project status and roadmap |
| [docs/spiffe-setup.md](docs/spiffe-setup.md) | SPIFFE/SPIRE identity setup |
| [docs/spike-token-substitution.md](docs/spike-token-substitution.md) | SPIKE late-binding secrets |
| [docs/operations/performance.md](docs/operations/performance.md) | Performance benchmarks |
| [docs/operations/session-management.md](docs/operations/session-management.md) | Session and exfiltration detection |
| [docs/operations/opensearch-observability.md](docs/operations/opensearch-observability.md) | Optional OpenSearch + Dashboards observability profile |
| [docs/compliance/gdpr-article-30-ropa.md](docs/compliance/gdpr-article-30-ropa.md) | GDPR Article 30 compliance |
| [docs/security/baseline.md](docs/security/baseline.md) | Security baseline |
| [docs/security/agentic-zero-trust-faq.md](docs/security/agentic-zero-trust-faq.md) | Living FAQ for zero-trust security review questions |
| [docs/architecture/deployment-patterns.md](docs/architecture/deployment-patterns.md) | Deployment architecture |
| [docs/architecture/cloud-adaptation-playbooks.md](docs/architecture/cloud-adaptation-playbooks.md) | Step-by-step adaptation playbooks for AWS/GCP/Azure |
| [docs/architecture/cloudflare-workers-compensating-controls.md](docs/architecture/cloudflare-workers-compensating-controls.md) | Cloudflare Workers compensating controls and sign-off checklist |
| [docs/patterns/multi-agent-orchestration.md](docs/patterns/multi-agent-orchestration.md) | Multi-agent orchestration patterns |
| [docs/api-reference.md](docs/api-reference.md) | Gateway HTTP API reference (endpoints, wire format, error codes) |
| [docs/deployment-guide.md](docs/deployment-guide.md) | Deployment guide (Docker Compose, K8s, Phoenix) |
| [docs/configuration-reference.md](docs/configuration-reference.md) | All environment variables and configuration files |
| [docs/agentic-security-architecture.skill.md](docs/agentic-security-architecture.skill.md) | AI coding assistant skill file |
| [sdk/go/README.md](sdk/go/README.md) | Go SDK documentation and usage |
| [sdk/python/README.md](sdk/python/README.md) | Python SDK documentation and usage |


## Status

This is a **reference implementation** validating
[PRECINCT v2.5](docs/architecture/reference-architecture.md).
It demonstrates that a 13-layer security middleware chain can be implemented,
deployed, and tested end-to-end with real infrastructure (SPIRE, SPIKE, KeyDB,
OPA, Phoenix, optional OpenSearch) in both Docker Compose and Kubernetes environments.

All 233 backlog stories have been completed and verified.

# Agentic AI Security Reference Architecture -- Reference Implementation

## What Is This?

This is a **reference implementation of an MCP Security Gateway** that implements a 13-layer
middleware chain for securing AI agent tool calls. It validates the
[Agentic AI Security Reference Architecture v2.2](../agentic-ai-security-reference-architecture.md),
a 200+ page document defining security patterns for production agentic AI systems.

The gateway interposes between AI agents and MCP tool servers, enforcing
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


## Architecture at a Glance

| # | Middleware Layer | Description |
|---|-----------------|-------------|
| 1 | Request Size Guard | Rejects oversized payloads (configurable, default 1 MB) |
| 2 | Request Shape Validator | Validates JSON-RPC 2.0 envelope structure |
| 3 | SPIFFE Authentication | Validates X-SPIFFE-ID header against trust domain |
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

Supporting infrastructure:

- **SPIRE** -- SPIFFE identity for all workloads (mTLS-ready)
- **SPIKE Nexus** -- Late-binding secret vault with SPIFFE-based access control
- **KeyDB** -- Session state and rate-limit counters
- **OPA** -- Policy-as-code with Rego
- **Phoenix + OTel Collector** -- Distributed tracing and observability


## Quick Start

Prerequisites: Docker, Docker Compose, Go 1.23+, make.

```bash
make phoenix-up      # Start observability stack (Phoenix + OTel collector)
make up              # Start all services (SPIRE, SPIKE, KeyDB, gateway, mock MCP server)
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

## Git Hooks (beads)

The repo includes a root `.beads` symlink to `POC/.beads` so `bd` git hooks can
resolve the beads database when commits are made from subdirectories.

If you ever see a pre-commit warning about a missing beads database, treat it as
a warning (not a failed commit) and set:

```bash
export BEADS_DIR=.beads
```

from the repository root before committing.


## Directory Structure

```
cmd/gateway/              Gateway binary entrypoint
internal/gateway/         Gateway core + 13-layer middleware chain
config/                   OPA policies, tool registry, SPIFFE IDs, risk thresholds
sdk/go/mcpgateway/        Go SDK
sdk/python/               Python SDK
docker/                   Dockerfiles for all services
infra/eks/                Kubernetes manifests (base + overlays)
tools/compliance/         GDPR/SOC2/ISO27001/NIST compliance automation
docs/                     All documentation
tests/e2e/                E2E demo test suites
tests/integration/        Go integration tests
tests/benchmark/          Load testing scripts
demo/                     Demo harness (Go + Python test clients, mock MCP server)
scripts/                  Setup and operational scripts
.learnings/               Retrospective insights from development
```


## Make Commands

| Target | Description |
|--------|-------------|
| `make help` | Show available targets |
| `make setup` | Interactive CLI setup wizard |
| **Core** | |
| `make up` | Start Docker Compose stack (waits for all services healthy) |
| `make down` | Stop Docker Compose stack |
| `make test` | Run all tests (unit + OPA) |
| `make lint` | Run linters (golangci-lint or go fmt/vet) |
| `make clean` | Full cleanup (containers, volumes, build artifacts, logs) |
| `make logs` | Tail gateway logs |
| **Demo** | |
| `make demo` | Run E2E demo (Docker Compose + K8s) |
| `make demo-compose` | Run E2E demo (Docker Compose only) |
| `make demo-k8s` | Run E2E demo (K8s only) |
| **Phoenix Observability** | |
| `make phoenix-up` | Start Phoenix + OTel collector (persistent traces) |
| `make phoenix-down` | Stop Phoenix stack (preserves trace data) |
| `make phoenix-reset` | Stop Phoenix stack and destroy trace data |
| **Kubernetes** | |
| `make k8s-up` | Deploy to local K8s (Docker Desktop) |
| `make k8s-down` | Tear down local K8s deployment |
| **CI / Quality** | |
| `make ci` | Full CI pipeline (lint + test + build) |
| `make security-scan` | Run security scans (gosec, trivy) |
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
| [docs/compliance/gdpr-article-30-ropa.md](docs/compliance/gdpr-article-30-ropa.md) | GDPR Article 30 compliance |
| [docs/security/baseline.md](docs/security/baseline.md) | Security baseline |
| [docs/architecture/deployment-patterns.md](docs/architecture/deployment-patterns.md) | Deployment architecture |
| [docs/patterns/multi-agent-orchestration.md](docs/patterns/multi-agent-orchestration.md) | Multi-agent orchestration patterns |
| [docs/api-reference.md](docs/api-reference.md) | Gateway HTTP API reference (endpoints, wire format, error codes) |
| [docs/deployment-guide.md](docs/deployment-guide.md) | Deployment guide (Docker Compose, K8s, Phoenix) |
| [docs/configuration-reference.md](docs/configuration-reference.md) | All environment variables and configuration files |
| [docs/agentic-security-architecture.skill.md](docs/agentic-security-architecture.skill.md) | AI coding assistant skill file |
| [sdk/go/README.md](sdk/go/README.md) | Go SDK documentation and usage |
| [sdk/python/README.md](sdk/python/README.md) | Python SDK documentation and usage |


## Status

This is a **reference implementation** validating the
[Agentic AI Security Reference Architecture v2.2](../agentic-ai-security-reference-architecture.md).
It demonstrates that a 13-layer security middleware chain can be implemented,
deployed, and tested end-to-end with real infrastructure (SPIRE, SPIKE, KeyDB,
OPA, Phoenix) in both Docker Compose and Kubernetes environments.

All 233 backlog stories have been completed and verified.

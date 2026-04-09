# Contributing to PRECINCT

Thank you for your interest in contributing to PRECINCT. This document covers the
process for submitting changes and the standards we hold all contributions to.

## Prerequisites

- **Go 1.26.2+** (see `go.mod`)
- **Docker** and **Docker Compose** (for integration and E2E tests)
- **Make** (all workflows are wrapped in Makefile targets)
- **Python 3.13+** and **uv** (only if working on sample agents or compliance tests)

## Getting Started

```bash
git clone https://github.com/precinct-dev/precinct.git
cd precinct
make help          # list all available targets
make lint          # run linters (golangci-lint, OPA)
make test-unit     # run unit tests
make up            # start the full Compose stack
make test          # run all tests (unit + integration + OPA + CLI)
```

## Development Workflow

1. **Fork** the repository and create a feature branch from `main`.
2. Make your changes. Keep commits atomic and focused.
3. Run `make lint` and `make test` locally before pushing.
4. Open a pull request against `main`.

## Testing Requirements

Every contribution must meet the following coverage gates:

| Level              | Gate for          | Minimum coverage | Mocks allowed? |
|--------------------|-------------------|------------------|----------------|
| **Unit tests**     | PR merge          | 80%              | Yes            |
| **Integration tests** | PR acceptance  | Required         | No             |
| **E2E tests**      | PR acceptance     | 100% of affected paths | No      |

- **Unit tests** isolate a single function or module. Mocks are acceptable here.
- **Integration tests** run against real dependencies (database, Compose services).
  They must not contain mocks.
- **E2E tests** exercise the full system. They must not contain mocks.

PRs that lack integration or E2E tests for the changed code paths will not be merged.

Run the full suite with:

```bash
make test              # unit + integration + OPA + CLI
make test-e2e          # full E2E demo suite (requires Docker)
```

## AI-Generated Code

We accept AI-generated contributions under the same standards as human-written code,
with one additional requirement: AI-generated PRs must have **100% E2E coverage** of
the submitted change, in addition to the integration and unit test gates above.

All PRs are reviewed by a human maintainer. There is no automated acceptance process.
Expect review cycles to take time.

## Code Style

- Go code must pass `golangci-lint` (configuration is in the repo).
- Follow the existing patterns in the codebase. Read the code around your change
  before writing new code.
- Keep changes narrow. Do not bundle unrelated refactors into a feature PR.
- Do not add dead code, speculative abstractions, or commented-out blocks.

## Security

PRECINCT is a security-critical project. If your change touches authentication,
authorization, cryptographic identity, policy enforcement, or data handling:

- Run `make production-readiness-validate` (gosec + trivy + policy checks).
- Explain the security implications in your PR description.

If you discover a security vulnerability, **do not open a public issue**. Instead,
report it privately via GitHub's
[security advisory](https://github.com/precinct-dev/precinct/security/advisories/new)
feature or email the maintainers directly.

## Commit Messages

Write clear, concise commit messages. Lead with what changed and why, not how.
One logical change per commit.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).

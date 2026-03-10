# Dependency Updates Plan

Captured 2026-03-10 after repo rename from `RamXX/agentic_reference_architecture` to `precinct-dev/PRECINCT`.

All dependabot PRs (#28--#45) were closed without merging. This document captures the
recommended updates for a single coordinated PR once CI is re-enabled.

## Go Version

| Current (go.mod) | System installed | Recommendation |
|-------------------|------------------|----------------|
| 1.24.6            | 1.26.1           | Update go.mod to `go 1.26` and run `go mod tidy` |

## GitHub Actions (batch into one PR)

All are major version bumps. Require Actions Runner v2.327.1+ (Node 24 runtime).

| Action                      | Current | Target | Breaking changes                                    |
|-----------------------------|---------|--------|-----------------------------------------------------|
| actions/checkout            | 4       | 6      | Credential persistence changed; skips v5            |
| actions/setup-go            | 5       | 6      | Toolchain handling changed (breaking)               |
| actions/upload-artifact     | 4       | 7      | ESM, new `archive` param; skips v5 and v6           |
| docker/setup-buildx-action  | 3       | 4      | Removes deprecated inputs, Node 24 runtime          |
| docker/metadata-action      | 5       | 6      | Comment handling change, Node 24 runtime            |
| docker/login-action         | 3       | 4      | Node 24 runtime                                     |
| docker/build-push-action    | 6       | 7      | Removes deprecated envs, Node 24 runtime            |
| imjasonh/setup-crane        | 0.4     | 0.5    | Skip release lookup, retry (non-breaking)           |

### Procedure

1. Create a single branch `chore/update-github-actions`
2. Update all 8 actions in `ci.yaml`, `promote.yaml`, `security-scan.yml`
3. Verify runner version supports Node 24
4. Test CI end-to-end before merging

## Go Dependencies

### OpenTelemetry (batch all 6 together)

| Module                             | Current | Target | Notes                       |
|------------------------------------|---------|--------|-----------------------------|
| go.opentelemetry.io/otel           | 1.40.0  | 1.42.0 | Core module                 |
| go.opentelemetry.io/otel/trace     | 1.40.0  | 1.42.0 | Trace API                   |
| go.opentelemetry.io/otel/metric    | 1.40.0  | 1.42.0 | Metric API                  |
| go.opentelemetry.io/otel/sdk       | 1.40.0  | 1.42.0 | SDK implementation          |
| otel/exporters/otlp/otlptrace/otlptracegrpc | 1.40.0 | 1.42.0 | gRPC trace exporter |
| otel/exporters/otlp/otlpmetric/otlpmetricgrpc | 1.40.0 | 1.42.0 | gRPC metric exporter |

**Constraint**: OTel 1.42.0 may require Go >= 1.25. Verify before merging.
These modules are tightly coupled and must be updated together.

### Procedure

1. Create branch `chore/update-otel-1.42`
2. Update all 6 OTel modules in `POC/go.mod`
3. Run `go mod tidy`
4. Run full test suite

### AWS SDK (batch all 3 together)

| Module                          | Current | Target | Notes                              |
|---------------------------------|---------|--------|------------------------------------|
| github.com/aws/aws-sdk-go-v2   | 1.41.1  | 1.41.3 | Patch: Go version bump, regen      |
| aws-sdk-go-v2/config            | 1.32.7  | 1.32.11| Patch: endpoint model updates      |
| aws-sdk-go-v2/service/s3        | 1.96.0  | 1.96.4 | Patch: sigv4a fix, deser fix       |

All patches, no breaking changes. Safe to merge after tests pass.

### Procedure

1. Create branch `chore/update-aws-sdk`
2. Update all 3 AWS modules in `POC/go.mod`
3. Run `go mod tidy`
4. Run full test suite

### Redis

| Module                    | Current | Target | Notes                                   |
|---------------------------|---------|--------|-----------------------------------------|
| github.com/redis/go-redis | 9.17.3 | 9.18.0 | Minor: Redis 8.6, OTel metrics, fixes  |

Additive API, no breaking changes. Includes PubSub nil pointer fix and zombie connection
queue fix. Test if using PubSub or Streams.

### Procedure

1. Create branch `chore/update-redis`
2. Update in `POC/go.mod`
3. Run `go mod tidy`
4. Run full test suite, especially PubSub-related tests

## Repo Rename Checklist

Completed programmatically via `scripts/rename-repo.sh`:

- [x] Git remote URL
- [x] Go module paths
- [x] All Go import statements
- [x] Site HTML GitHub links
- [x] CI/CD workflow references
- [x] Container image names
- [x] SPIFFE trust domain
- [x] Kubernetes manifests
- [x] Helm values
- [x] Documentation links
- [x] Cosign/policy references

## CI Status

CI workflows are currently **disabled** (files moved to `.github/workflows-disabled/`).
Re-enable by moving them back once the rename and dependency updates are complete.

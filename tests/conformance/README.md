# Conformance Harness

The conformance harness gates production-readiness claims for four required suites:

- `contracts`
- `connectors`
- `ruleops`
- `profiles`

It consumes fixture-driven pass/fail checks and emits a stable machine-readable JSON artifact (`conformance.report.v1`).

## Local Invocation

Run in embedded mode (no live gateway dependency):

```bash
go run ./tests/conformance/cmd/harness --output ./build/conformance/conformance-report.json
```

Run against a live local stack gateway for connector and RuleOps suite execution:

```bash
go run ./tests/conformance/cmd/harness \
  --live \
  --gateway-url http://localhost:9090 \
  --output ./build/conformance/conformance-report.live.json
```

## CI Invocation

```bash
make conformance
```

This target writes `build/conformance/conformance-report.json` and fails on any conformance mismatch.

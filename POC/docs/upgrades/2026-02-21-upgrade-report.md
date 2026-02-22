# Upgrade Report: 2026-02-21

## Summary
Status: SUCCESS
Components upgraded: 2
Tests run: make ci, make demo-compose
Duration: 263s

## Changes
| Component | Old Version | New Version | Status |
|-----------|-------------|-------------|--------|
| otel-collector | latest | 0.146.1 | OK |\n| phoenix | latest | 13.3.0 | OK |\n| go-modules | -- | -- | SKIP (no latest) |\n| python-deps | -- | -- | SKIP (no latest) |\n

## Test Results
- make ci: PASS
- make demo-compose: PASS

## Rollback Info
Snapshot: versions.yaml.snapshot.1771722517
Snapshot Dir: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config/upgrade-snapshots/1771722517

## Logs
- make ci log: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config/upgrade-snapshots/1771722517/make-ci.log
- make demo-compose log: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config/upgrade-snapshots/1771722517/make-demo-compose.log

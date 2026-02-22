# Upgrade Report: 2026-02-21

## Summary
Status: SUCCESS
Components upgraded: 0
Tests run: make ci, make demo-compose
Duration: 251s

## Changes
| Component | Old Version | New Version | Status |
|-----------|-------------|-------------|--------|
| otel-collector | 0.146.1 | 0.146.1 | UP TO DATE |\n| phoenix | 13.3.0 | 13.3.0 | UP TO DATE |\n| go-modules | -- | -- | SKIP (no latest) |\n| python-deps | -- | -- | SKIP (no latest) |\n

## Test Results
- make ci: PASS
- make demo-compose: PASS

## Rollback Info
Snapshot: versions.yaml.snapshot.1771722788
Snapshot Dir: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config/upgrade-snapshots/1771722788

## Logs
- make ci log: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config/upgrade-snapshots/1771722788/make-ci.log
- make demo-compose log: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config/upgrade-snapshots/1771722788/make-demo-compose.log

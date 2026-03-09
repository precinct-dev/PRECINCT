# Upgrade Report: 2026-02-26

## Summary
Status: SUCCESS
Components upgraded: 0
Tests run: make ci, make demo-compose
Duration: 437s

## Changes
| Component | Old Version | New Version | Status |
|-----------|-------------|-------------|--------|
| otel-collector | 0.146.1 | 0.146.1 | UP TO DATE |
| phoenix | 13.3.0 | 13.3.0 | UP TO DATE |
| go-modules | -- | -- | SKIP (no latest) |
| python-deps | -- | -- | SKIP (no latest) |


## Test Results
- make ci: PASS
- make demo-compose: PASS

## Rollback Info
Snapshot: versions.yaml.snapshot.1772122177
Snapshot Dir: config/upgrade-snapshots/1772122177

## Logs
- make ci log: config/upgrade-snapshots/1772122177/make-ci.log
- make demo-compose log: config/upgrade-snapshots/1772122177/make-demo-compose.log

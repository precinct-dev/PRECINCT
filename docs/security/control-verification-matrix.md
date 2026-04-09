# Threat-Model Verification Matrix

This matrix is the evidence gate for security, usability, and blind-spot controls.

Machine-readable source:

- `docs/security/artifacts/control-verification-matrix.v1.json`

Run the gate:

```bash
make control-matrix-check
```

Expected outputs:

- `build/security-scan/latest/control-verification-report.json`
- `build/security-scan/latest/control-verification-report.md`

Failure conditions:

- Required control evidence file missing
- Required evidence file stale (`max_age_hours` exceeded)
- Missing test references or test commands
- Runtime signal keys not present in approved taxonomy catalogs
- No control coverage for `security`, `usability`, or `blindspot` domains

This gate is CI-enforced and included in `make production-readiness-validate`.

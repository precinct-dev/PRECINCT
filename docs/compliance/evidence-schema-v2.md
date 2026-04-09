# Evidence Bundle Schema v2

This document defines the machine-readable compliance evidence bundle emitted by:

- `python3 tools/compliance/generate.py`
- `make compliance-report`

Schema file:

- `tools/compliance/evidence_schema_v2.json`

## Bundle Files

The generator writes both evidence bundle formats to the selected output directory:

- `compliance-evidence.v2.json`
- `compliance-evidence.v2.csv`

When PCI-DSS framework rows are present, the generator also emits profile-scoped
technical evidence bundles:

- `compliance-evidence.pci-dss.json`
- `compliance-evidence.pci-dss.csv`

When HIPAA-tagged profile controls are present in taxonomy mappings, the generator
also emits:

- `compliance-evidence.hipaa.json`
- `compliance-evidence.hipaa.csv`

The existing analyst-focused exports are also preserved:

- `compliance-report.csv`
- `compliance-report.xlsx`
- `compliance-summary.pdf`

## Required Record Fields

Every evidence record includes the auditor-required fields:

- `control_id`
- `source`
- `timestamp`
- `status`
- `artifact_reference`

Additional fields are included for framework mapping and human readability:

- `framework`
- `framework_requirement`
- `control_name`

## Top-Level Envelope

- `schema_version`: always `evidence.bundle.v2`
- `generated_at`: UTC ISO 8601 timestamp
- `record_count`: number of records emitted
- `records`: list of evidence records

## Generation Reproducibility

Single-command reproducible generation:

```bash
make compliance-report
```

Direct CLI generation:

```bash
python3 tools/compliance/generate.py --audit-log /tmp/audit.jsonl --project-root .
```

# Control Taxonomy Technical Scope Boundary

This reference implementation only models technical controls that can be
implemented, tested, and evidenced from code/runtime artifacts.

## In Scope (Technical Controls)

- Middleware-enforced controls in the gateway request/response path.
- Policy/configuration controls with machine-verifiable artifacts.
- Test-backed controls where evidence is sourced from unit/integration suites.
- Runtime audit controls with deterministic extraction from JSONL events.

## Out of Scope (Org/Process Controls)

- Security awareness programs and HR policy controls.
- Governance committee cadence, audit scheduling, and tabletop exercises.
- Legal and contractual attestations that require manual process evidence.

## Mapping Metadata Contract

Every technical control is expected to include (explicitly or via loader defaults):

- `mapping_metadata.control_scope`
- `mapping_metadata.control_family`
- `mapping_metadata.implementation_tier`
- `mapping_metadata.evidence_owner`

Every technical control must also expose at least one machine-readable
evidence extraction path via `evidence_paths`.

Primary source taxonomy:

- `tools/compliance/control_taxonomy.yaml`

Companion technical profile packs:

- `docs/compliance/pci-dss-technical-profile.md`

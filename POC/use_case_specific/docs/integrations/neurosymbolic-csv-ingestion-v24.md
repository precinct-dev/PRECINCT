# Neuro-Symbolic CSV Ingestion Hardening Guide (v2.4)

This guide defines the reference integration slice for CSV-to-facts ingestion
through the v2.4 context admission plane.

## Objective

- Validate CSV payloads before facts are admitted into model-bound context flows.
- Attach provenance hashes and handle-based references to every ingestion request.
- Enforce deterministic deny/allow outcomes with canonical reason codes.

## Pipeline Shape

1. CSV upload is analyzed by the ingestion adapter:
   - schema headers and row structure validation
   - size bound validation
   - malicious content pattern detection
2. Adapter emits context admission attributes with:
   - `facts_hash` (`sha256:<digest>`)
   - `context_handle` (`facts:<short-hash>`)
   - provenance block (`source`, `checksum`, verification metadata)
3. Gateway `/v1/context/admit` enforces:
   - neuro-symbolic CSV validation invariants
   - provenance hash invariants
   - existing model-bound context invariants (`no_scan_no_send`, minimum necessary)

## Canonical Reason Codes

- Allow path:
  - `CONTEXT_ALLOW`
- Deny paths:
  - `CONTEXT_FACTS_CSV_VALIDATION_FAILED`
  - `CONTEXT_FACTS_PROVENANCE_INVALID`

## Reference Implementation

- Ingestion adapter:
  - `internal/integrations/neurosymbolic/csv_ingestion.go`
- Gateway invariants:
  - `internal/gateway/phase3_runtime_helpers.go`
- Reason code constants/catalog:
  - `internal/gateway/phase3_contracts.go`
  - `contracts/v2.4/reason-code-catalog.v2.4.json`

## Validation Commands

Run from repository root:

```bash
go test ./internal/integrations/neurosymbolic/... -count=1
go test ./internal/gateway/... -run ContextInvariants -count=1
go test ./tests/integration/... -run NeuroSymbolicCSVIngestion -count=1
COMPOSE_FILE=POC/docker-compose.yml bash POC/tests/e2e/scenario_k_neurosymbolic_csv_ingestion.sh
```

E2E artifact output:

- Runtime: `POC/tests/e2e/artifacts/scenario_k_<run_id>.json`
- Checked-in snapshot:
  `POC/docs/integrations/artifacts/neurosymbolic-csv-ingestion-report.v1.json`

## Notes

- This implementation is a hardened reference path for ingestion and admission,
  not a full reasoner runtime.
- The adapter is intentionally isolated from reasoner internals to preserve
  portability across deployment environments.

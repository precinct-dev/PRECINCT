# Contract Changelog

## 2.4.0 - 2026-02-13

- Frozen canonical control-plane contract set for ingress/context/model/tool/loop planes.
- Published machine-readable manifest and JSON schemas for request/response contracts.
- Published connector manifest schema and CCA lifecycle endpoint contracts.
- Published DLP RuleOps lifecycle contract (create/validate/approve/sign/promote/rollback/active).
- Published frozen reason-code catalog with stability and deprecation policy.
- Added compatibility mapping for `/v1/ingress/admit` -> `/v1/ingress/submit` and model alias surfaces.
- Documented deterministic ingress runtime guards for source authenticity, replay, and freshness checks across both canonical and compatibility ingress paths.
- Added horizontal hardening notes for v2.4 endpoints: middleware-chain enforcement on governance routes, unified error envelope for request failures, and endpoint telemetry parity metadata.
- Added approval capability governance lifecycle endpoints (`/admin/approvals/*`) for request/grant/deny/consume with signed, scoped, short-lived tokens.

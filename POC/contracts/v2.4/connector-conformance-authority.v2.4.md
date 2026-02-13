# Connector Conformance Authority (CCA) v2.4

This document defines the Connector Conformance Authority lifecycle and runtime
admission behavior for ingress-facing connectors.

## Scope

- Connector manifest schema and signature validation.
- Connector lifecycle state machine.
- Runtime ingress gate requiring active connector state and valid signature.
- Machine-readable conformance report linked to audit correlation IDs.

## Manifest Contract

- Schema: `POC/contracts/v2.4/schemas/connector_manifest_v1.schema.json`
- Signature algorithm in the reference implementation: `sha256-manifest-v1`.

## Lifecycle Endpoints

- `POST /v1/connectors/register`
- `POST /v1/connectors/validate`
- `POST /v1/connectors/approve`
- `POST /v1/connectors/activate`
- `POST /v1/connectors/revoke`
- `GET /v1/connectors/status?connector_id=<id>`
- `GET /v1/connectors/report`

## State Machine

`registered -> validated -> approved -> active -> revoked`

Invalid transitions are rejected.

## Runtime Ingress Gate

Ingress checks `connector_id` (or `source_id`) and `connector_signature` from
policy attributes. Requests are denied when:

- connector is unknown
- connector is not in `active` state
- signature is missing or invalid

## Conformance Report

`GET /v1/connectors/report` returns JSON with each connector's state and
latest audit correlation markers (`last_decision_id`, `last_trace_id`).

## Portability Notes

- Kubernetes: optional admission integration can be layered on top of runtime checks.
- Compose/non-K8s: runtime gate is mandatory and authoritative.

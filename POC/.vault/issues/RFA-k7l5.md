---
id: RFA-k7l5
title: "Strict compose profile still inherits insecure dev/demo gateway settings"
status: closed
priority: 0
type: bug
labels: [release-sanity, security, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T04:55:56Z
created_by: ramirosalas
updated_at: 2026-03-10T06:48:57Z
content_hash: "sha256:537501b9ae2ef946509575abda2908827d1a28cab029becb7073612795fec6bc"
closed_at: 2026-03-10T06:48:57Z
close_reason: "Accepted: strict compose runtime is isolated from inherited dev/demo gateway settings and docs/regression checks passed"
led_to: [RFA-mnw2, RFA-uehp, RFA-7lrd, RFA-565d, RFA-phtc]
---

## Description
## Context (Embedded)
- Problem: The production-intent compose path still inherits the base file's insecure dev/demo gateway settings.
- Evidence:
  - Base compose publishes HTTP dev listener and enables demo/dev flags: docker-compose.yml:563, docker-compose.yml:568, docker-compose.yml:574, docker-compose.yml:575, docker-compose.yml:576, docker-compose.yml:577.
  - Strict override only adds prod vars and 9443; it does not clear inherited dev/demo values: docker-compose.strict.yml:5, docker-compose.strict.yml:8, docker-compose.strict.yml:10.
  - Rendered proof from `docker compose --profile strict -f docker-compose.yml -f docker-compose.strict.yml config` shows ports 9090 and 9443, plus `ALLOW_INSECURE_DEV_MODE=1`, `ALLOW_NON_LOOPBACK_DEV_BIND=1`, `DEMO_RUGPULL_ADMIN_ENABLED=1`, `DEV_LISTEN_HOST=0.0.0.0`, `GUARD_MODEL_ENDPOINT=http://mock-guard-model:8080/openai/v1`, and `MODEL_PROVIDER_ENDPOINT_GROQ=http://mock-guard-model:8080/openai/v1/chat/completions`.
- Impact: The marketed production-intent compose path still exposes a dev-mode HTTP surface and demo behavior.

## Acceptance Criteria
1. `docker compose --profile strict -f docker-compose.yml -f docker-compose.strict.yml config` no longer publishes `9090:9090` for the gateway.
2. The strict compose gateway no longer inherits `ALLOW_INSECURE_DEV_MODE`, `ALLOW_NON_LOOPBACK_DEV_BIND`, `DEMO_RUGPULL_ADMIN_ENABLED`, `DEV_LISTEN_HOST=0.0.0.0`, or mock-guard endpoints from the base file.
3. Documentation for the strict compose path matches the rendered configuration.

## Testing Requirements
- Config render: run the strict compose render command above and capture the gateway service block.
- Regression: ensure the default local demo profile still works when invoked without `--profile strict`.

## nd_contract
status: new

### evidence
- 2026-03-10 sanity review with local `docker compose ... config` render.

### proof
- [ ] AC #1: Strict compose does not publish the dev HTTP listener.
- [ ] AC #2: Strict compose clears inherited demo/insecure gateway settings.
- [ ] AC #3: Docs and rendered config match.

## Acceptance Criteria


## Design


## Notes
## PM Decision
ACCEPTED [2026-03-10]: Verified the delivered fix directly from commit 7307960 and focused reruns. The newest nd_contract below is authoritative and supersedes earlier duplicated handoff blocks.

## nd_contract
status: accepted

### evidence
- PM acceptance review completed on 2026-03-10 in `/Users/ramirosalas/workspace/agentic_reference_architecture/POC`.
- Confirmed `git rev-parse --short HEAD` -> `7307960`, matching the implementation commit cited in delivery evidence.
- Reviewed the delivered surfaces for AC coverage: `docker-compose.strict.yml`, `tests/e2e/validate_strict_runtime_wiring.sh`, and `docs/deployment-guide.md`.
- Ran `tests/e2e/validate_strict_runtime_wiring.sh` -> PASS (`[PASS] Strict runtime wiring validation passed`).
- Ran `docker compose -f docker-compose.yml config` -> PASS (default compose regression render succeeded).
- Performed a static completeness sweep on the changed delivery files; no incomplete implementation markers relevant to this story were found.
- Parent epic `RFA-rlpe` still has open children, so only this story is being closed.

### proof
- [x] AC #1: The strict compose render no longer publishes the gateway dev HTTP listener on `9090`; the validator passed and the strict override publishes only `9443:9443`.
- [x] AC #2: The strict compose gateway no longer inherits the listed dev/demo and mock-endpoint settings; the validator's negative assertions passed and the strict override replaces the inherited environment block.
- [x] AC #3: The strict compose documentation matches the rendered configuration; the docs describe the same HTTPS-only `9443:9443` runtime and the same forbidden inherited settings validated by the rerun.

## nd_contract
status: accepted

### evidence
- PM acceptance review: 2026-03-09
- Re-ran `tests/e2e/validate_strict_runtime_wiring.sh` with strict profile env vars set: PASS.
- Re-ran `docker compose --profile strict -f docker-compose.yml -f docker-compose.strict.yml config | sed -n '/mcp-security-gateway:/,/^[^[:space:]]/p'` with strict profile env vars set: rendered gateway publishes only 9443 and omits the inherited dev/demo envs called out in the story.
- Reviewed implementation surfaces: `docker-compose.strict.yml`, `tests/e2e/validate_strict_runtime_wiring.sh`, `docs/deployment-guide.md`.
- Delivery preflight helper `scripts/verify-delivery.sh` is not present in this repo; acceptance was validated directly from nd evidence plus independent reruns.

### proof
- [x] AC #1: Strict compose does not publish the dev HTTP listener.
- [x] AC #2: Strict compose clears inherited demo/insecure gateway settings.
- [x] AC #3: Docs and rendered config match.


## Implementation Evidence (DELIVERED)

### CI/Test Results
- Commands run:
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC strict-runtime-validate`
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC compose-verify`
  - `STRICT_UPSTREAM_URL=https://strict-upstream.example.com/mcp APPROVAL_SIGNING_KEY=compose-approval-signing-key-material-at-least-32 UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS=spiffe://agentic-ref-arch.poc/ns/tools/sa/mcp-tool KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS=spiffe://agentic-ref-arch.poc/ns/data/sa/keydb docker compose --profile strict -f docker-compose.yml -f docker-compose.strict.yml config`
  - `docker compose -f docker-compose.yml config`
- Summary: strict runtime validation PASS; base compose verification PASS; strict compose render PASS; default compose render PASS.
- Key output:
  - `make strict-runtime-validate`: `[INFO] Validating strict Compose runtime wiring...` then `[PASS] Strict runtime wiring validation passed`
  - `make compose-verify`: `[PASS] No third-party services use :latest`, `[PASS] All third-party services are digest-pinned (@sha256:...)`, `compose-verify: PASS`
  - Strict render for `mcp-security-gateway` now shows only `published: "9443"` and does not include `ALLOW_INSECURE_DEV_MODE`, `ALLOW_NON_LOOPBACK_DEV_BIND`, `DEMO_RUGPULL_ADMIN_ENABLED`, `DEV_LISTEN_HOST`, `GUARD_MODEL_ENDPOINT`, or `MODEL_PROVIDER_ENDPOINT_GROQ`.

### Commit
- Branch: `codex/story/RFA-k7l5`
- SHA: `7307960`

### AC Verification
| AC # | Requirement | Code Location | Test Location | Status |
|------|-------------|---------------|---------------|--------|
| 1 | Strict compose does not publish the dev HTTP listener. | `docker-compose.strict.yml:7-12` | `tests/e2e/validate_strict_runtime_wiring.sh:87-90` | PASS |
| 2 | Strict compose clears inherited demo/insecure gateway settings. | `docker-compose.strict.yml:12-49` | `tests/e2e/validate_strict_runtime_wiring.sh:100-105` | PASS |
| 3 | Docs and rendered strict config match. | `docs/deployment-guide.md:552-570` | `tests/e2e/validate_strict_runtime_wiring.sh:74-105` | PASS |

## nd_contract
status: delivered

### evidence
- Claimed story and appended in-progress contract in nd.
- Replaced the strict compose gateway `ports` and `environment` blocks with Compose `!override` semantics so strict mode no longer inherits dev/demo state from the base file.
- Added explicit negative assertions to `tests/e2e/validate_strict_runtime_wiring.sh` for port 9090 and inherited dev/demo/mock endpoint vars.
- Updated strict compose deployment docs to describe the expected rendered runtime state.
- Validation commands:
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC strict-runtime-validate` -> PASS
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC compose-verify` -> PASS
  - `docker compose --profile strict -f docker-compose.yml -f docker-compose.strict.yml config` with strict env vars set -> PASS; gateway block rendered only `9443:9443`
  - `docker compose -f docker-compose.yml config` -> PASS
- Commit: `7307960` on `codex/story/RFA-k7l5`.

### proof
- [x] AC #1: Strict compose render publishes only `9443:9443` for `mcp-security-gateway` (Code: `docker-compose.strict.yml:10-11`; Test: `tests/e2e/validate_strict_runtime_wiring.sh:87-90`; Evidence: strict render output showed `published: "9443"` and no `published: "9090"`).
- [x] AC #2: Strict compose render excludes inherited `ALLOW_INSECURE_DEV_MODE`, `ALLOW_NON_LOOPBACK_DEV_BIND`, `DEMO_RUGPULL_ADMIN_ENABLED`, `DEV_LISTEN_HOST=0.0.0.0`, and mock guard/model provider endpoints (Code: `docker-compose.strict.yml:12-49`; Test: `tests/e2e/validate_strict_runtime_wiring.sh:100-105`; Evidence: strict render output omitted each asserted pattern).
- [x] AC #3: Deployment docs now describe the strict render as HTTPS-only with the same forbidden inherited settings absent (Code: `docs/deployment-guide.md:562-568`; Test: `tests/e2e/validate_strict_runtime_wiring.sh:74-105`; Evidence: docs and rendered config both match the validated absence/presence checks).


## Implementation Evidence (DELIVERED)

### CI/Test Results
- Commands run:
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC strict-runtime-validate`
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC compose-verify`
  - `STRICT_UPSTREAM_URL=https://strict-upstream.example.com/mcp APPROVAL_SIGNING_KEY=compose-approval-signing-key-material-at-least-32 UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS=spiffe://agentic-ref-arch.poc/ns/tools/sa/mcp-tool KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS=spiffe://agentic-ref-arch.poc/ns/data/sa/keydb docker compose --profile strict -f docker-compose.yml -f docker-compose.strict.yml config`
  - `docker compose -f docker-compose.yml config`
- Summary: strict runtime validation PASS; base compose verification PASS; strict compose render PASS; default compose render PASS.
- Key output:
  - `make strict-runtime-validate`: `[INFO] Validating strict Compose runtime wiring...` then `[PASS] Strict runtime wiring validation passed`
  - `make compose-verify`: `[PASS] No third-party services use :latest`, `[PASS] All third-party services are digest-pinned (@sha256:...)`, `compose-verify: PASS`
  - Strict render for `mcp-security-gateway` now shows only `published: "9443"` and does not include `ALLOW_INSECURE_DEV_MODE`, `ALLOW_NON_LOOPBACK_DEV_BIND`, `DEMO_RUGPULL_ADMIN_ENABLED`, `DEV_LISTEN_HOST`, `GUARD_MODEL_ENDPOINT`, or `MODEL_PROVIDER_ENDPOINT_GROQ`.

### Commit
- Branch: `codex/story/RFA-k7l5`
- SHA: `7307960`

### AC Verification
| AC # | Requirement | Code Location | Test Location | Status |
|------|-------------|---------------|---------------|--------|
| 1 | Strict compose does not publish the dev HTTP listener. | `docker-compose.strict.yml:7-12` | `tests/e2e/validate_strict_runtime_wiring.sh:87-90` | PASS |
| 2 | Strict compose clears inherited demo/insecure gateway settings. | `docker-compose.strict.yml:12-49` | `tests/e2e/validate_strict_runtime_wiring.sh:100-105` | PASS |
| 3 | Docs and rendered strict config match. | `docs/deployment-guide.md:552-570` | `tests/e2e/validate_strict_runtime_wiring.sh:74-105` | PASS |

## nd_contract
status: delivered

### evidence
- Claimed story and appended in-progress contract in nd.
- Replaced the strict compose gateway `ports` and `environment` blocks with Compose `!override` semantics so strict mode no longer inherits dev/demo state from the base file.
- Added explicit negative assertions to `tests/e2e/validate_strict_runtime_wiring.sh` for port 9090 and inherited dev/demo/mock endpoint vars.
- Updated strict compose deployment docs to describe the expected rendered runtime state.
- Validation commands:
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC strict-runtime-validate` -> PASS
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC compose-verify` -> PASS
  - `docker compose --profile strict -f docker-compose.yml -f docker-compose.strict.yml config` with strict env vars set -> PASS; gateway block rendered only `9443:9443`
  - `docker compose -f docker-compose.yml config` -> PASS
- Commit: `7307960` on `codex/story/RFA-k7l5`.

### proof
- [x] AC #1: Strict compose render publishes only `9443:9443` for `mcp-security-gateway` (Code: `docker-compose.strict.yml:10-11`; Test: `tests/e2e/validate_strict_runtime_wiring.sh:87-90`; Evidence: strict render output showed `published: "9443"` and no `published: "9090"`).
- [x] AC #2: Strict compose render excludes inherited `ALLOW_INSECURE_DEV_MODE`, `ALLOW_NON_LOOPBACK_DEV_BIND`, `DEMO_RUGPULL_ADMIN_ENABLED`, `DEV_LISTEN_HOST=0.0.0.0`, and mock guard/model provider endpoints (Code: `docker-compose.strict.yml:12-49`; Test: `tests/e2e/validate_strict_runtime_wiring.sh:100-105`; Evidence: strict render output omitted each asserted pattern).
- [x] AC #3: Deployment docs now describe the strict render as HTTPS-only with the same forbidden inherited settings absent (Code: `docs/deployment-guide.md:562-568`; Test: `tests/e2e/validate_strict_runtime_wiring.sh:74-105`; Evidence: docs and rendered config both match the validated absence/presence checks).

## Implementation Evidence (DELIVERED)

### CI/Test Results
- Commands run:
  - \tests/e2e/validate_strict_runtime_wiring.sh
[INFO] Validating strict K8s runtime wiring (staging/prod overlays)...
[INFO] Validating strict Compose runtime wiring...
[PASS] Strict runtime wiring validation passed
  - \[PASS] No third-party services use :latest
[PASS] All third-party services are digest-pinned (@sha256:...)
[PASS] All compose Dockerfile FROM references are digest-pinned (@sha256:...)

compose-verify: PASS
  - \name: poc
services:
  content-scanner:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/demo/content-scanner
      dockerfile: Dockerfile
    cap_drop:
      - ALL
    container_name: content-scanner
    hostname: content-scanner
    healthcheck:
      test:
        - CMD
        - wget
        - --spider
        - -q
        - http://localhost:8085/health
      timeout: 3s
      interval: 5s
      retries: 5
    networks:
      tool-plane: null
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
  keydb:
    container_name: keydb
    hostname: keydb
    healthcheck:
      test:
        - CMD
        - keydb-cli
        - ping
      timeout: 3s
      interval: 10s
      retries: 5
    image: eqalpha/keydb@sha256:6537505c42355ca1f571276bddf83f5b750f760f07b2a185a676481791e388ac
    labels:
      component: session-store
      spiffe-id: keydb
    networks:
      data-plane: null
    ports:
      - mode: ingress
        target: 6379
        published: "6379"
        protocol: tcp
      - mode: ingress
        target: 6380
        published: "6380"
        protocol: tcp
    volumes:
      - type: volume
        source: keydb-data
        target: /data
        volume: {}
      - type: volume
        source: keydb-certs
        target: /certs
        read_only: true
        volume: {}
  mcp-security-gateway:
    profiles:
      - strict
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.gateway
    cap_drop:
      - ALL
    container_name: mcp-security-gateway
    depends_on:
      content-scanner:
        condition: service_healthy
        required: true
      keydb:
        condition: service_healthy
        required: true
      mock-guard-model:
        condition: service_healthy
        required: true
      mock-mcp-server:
        condition: service_healthy
        required: true
      spike-nexus:
        condition: service_healthy
        required: true
      spike-secret-seeder:
        condition: service_completed_successfully
        required: true
      spire-agent:
        condition: service_healthy
        required: true
    environment:
      APPROVAL_SIGNING_KEY: compose-approval-signing-key-material-at-least-32
      AUDIT_LOG_PATH: /tmp/audit.jsonl
      CAPABILITY_REGISTRY_V2_PATH: /config/capability-registry-v2.yaml
      DEEP_SCAN_FALLBACK: fail_closed
      DEEP_SCAN_TIMEOUT: "5"
      DLP_INJECTION_POLICY: ""
      DLP_PII_POLICY: block
      ENFORCE_MODEL_MEDIATION_GATE: "true"
      ENFORCEMENT_PROFILE: prod_standard
      GUARD_ARTIFACT_PATH: /config/guard-artifact.bin
      GUARD_ARTIFACT_PUBLIC_KEY: /config/attestation-ed25519.pub
      GUARD_ARTIFACT_SHA256: 8232540100ebde3b5682c2b47d1eee50764f6dadca3842400157061656fc95a3
      GUARD_ARTIFACT_SIGNATURE_PATH: /config/guard-artifact.bin.sig
      GUARD_MODEL_NAME: ""
      KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS: spiffe://agentic-ref-arch.poc/ns/data/sa/keydb
      KEYDB_URL: ""
      LOG_LEVEL: info
      MAX_REQUEST_SIZE_BYTES: "10485760"
      MCP_TRANSPORT_MODE: mcp
      MODEL_POLICY_INTENT_PREPEND_ENABLED: "true"
      MODEL_PROVIDER_CATALOG_PATH: /config/model-provider-catalog.v2.yaml
      MODEL_PROVIDER_CATALOG_PUBLIC_KEY: /config/attestation-ed25519.pub
      OPA_POLICY_DIR: /config/opa
      OTEL_EXPORTER_OTLP_ENDPOINT: otel-collector:4317
      OTEL_SERVICE_NAME: mcp-security-gateway
      RATE_LIMIT_BURST: "10"
      RATE_LIMIT_RPM: "60"
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIFFE_LISTEN_PORT: "9443"
      SPIFFE_MODE: prod
      SPIFFE_TRUST_DOMAIN: poc.local
      SPIKE_NEXUS_URL: https://spike-nexus:8443
      SPIRE_AGENT_SOCKET: /tmp/spire-agent/public/api.sock
      TOOL_REGISTRY_CONFIG_PATH: /config/tool-registry.yaml
      TOOL_REGISTRY_PUBLIC_KEY: /config/attestation-ed25519.pub
      UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS: spiffe://agentic-ref-arch.poc/ns/tools/sa/mcp-tool
      UPSTREAM_URL: https://strict-upstream.example.com/mcp
    hostname: mcp-security-gateway
    healthcheck:
      test:
        - CMD
        - /app/gateway
        - health
      timeout: 3s
      interval: 10s
      retries: 3
      start_period: 45s
    image: mcp-security-gateway:latest
    labels:
      component: gateway
      spiffe-id: mcp-security-gateway
    networks:
      agentic-net: null
      data-plane: null
      phoenix-net: null
      secrets-plane: null
      tool-plane: null
    ports:
      - mode: ingress
        target: 9443
        published: "9443"
        protocol: tcp
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config
        target: /config
        read_only: true
        bind: {}
  messaging-sim:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.messaging-sim
    cap_drop:
      - ALL
    container_name: messaging-sim
    environment:
      PORT: "8090"
    hostname: messaging-sim
    healthcheck:
      test:
        - CMD
        - /messaging-sim
        - -healthcheck
      timeout: 3s
      interval: 5s
      retries: 5
    networks:
      tool-plane: null
    read_only: true
    security_opt:
      - no-new-privileges:true
  mock-guard-model:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/demo/mock-guard-model
      dockerfile: Dockerfile
    cap_drop:
      - ALL
    container_name: mock-guard-model
    hostname: mock-guard-model
    healthcheck:
      test:
        - CMD
        - wget
        - --spider
        - -q
        - http://localhost:8080/health
      timeout: 3s
      interval: 5s
      retries: 5
    networks:
      tool-plane: null
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
  mock-mcp-server:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/demo/mock-mcp-server
      dockerfile: Dockerfile
    cap_drop:
      - ALL
    container_name: mock-mcp-server
    hostname: mock-mcp-server
    healthcheck:
      test:
        - CMD
        - wget
        - --spider
        - -q
        - http://localhost:8082/health
      timeout: 3s
      interval: 5s
      retries: 5
    networks:
      tool-plane: null
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
  spike-bootstrap:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.spike-bootstrap
    command:
      - -init
    container_name: spike-bootstrap
    depends_on:
      spike-keeper-1:
        condition: service_healthy
        required: true
      spike-nexus:
        condition: service_started
        required: true
      spire-entry-registrar:
        condition: service_completed_successfully
        required: true
    environment:
      BOOTSTRAP_TIMEOUT: "30"
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIKE_NEXUS_API_URL: https://spike-nexus:8443
      SPIKE_NEXUS_KEEPER_PEERS: https://spike-keeper-1:8443
      SPIKE_NEXUS_SHAMIR_SHARES: "1"
      SPIKE_NEXUS_SHAMIR_THRESHOLD: "1"
      SPIKE_SYSTEM_LOG_LEVEL: DEBUG
      SPIKE_TRUST_ROOT: poc.local
      SPIKE_TRUST_ROOT_BOOTSTRAP: poc.local
      SPIKE_TRUST_ROOT_KEEPER: poc.local
      SPIKE_TRUST_ROOT_LITE_WORKLOAD: poc.local
      SPIKE_TRUST_ROOT_NEXUS: poc.local
      SPIKE_TRUST_ROOT_PILOT: poc.local
    image: poc-spike-bootstrap:latest
    labels:
      spiffe-id: spike-bootstrap
    networks:
      secrets-plane: null
    restart: "no"
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
  spike-keeper-1:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.spike-keeper
    cap_drop:
      - ALL
    container_name: spike-keeper-1
    depends_on:
      spire-entry-registrar:
        condition: service_completed_successfully
        required: true
    environment:
      HEALTHCHECK_ADDR: 127.0.0.1:8443
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIKE_KEEPER_TLS_PORT: :8443
      SPIKE_SYSTEM_LOG_LEVEL: INFO
      SPIKE_TRUST_ROOT: poc.local
      SPIKE_TRUST_ROOT_BOOTSTRAP: poc.local
      SPIKE_TRUST_ROOT_KEEPER: poc.local
      SPIKE_TRUST_ROOT_LITE_WORKLOAD: poc.local
      SPIKE_TRUST_ROOT_NEXUS: poc.local
      SPIKE_TRUST_ROOT_PILOT: poc.local
    hostname: spike-keeper-1
    image: spike-keeper:latest
    labels:
      component: secrets
      service: spike
      spiffe-id: spike-keeper-1
    networks:
      secrets-plane: null
    read_only: true
    restart: "no"
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
  spike-nexus:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.spike-nexus
    cap_drop:
      - ALL
    container_name: spike-nexus
    depends_on:
      spike-keeper-1:
        condition: service_healthy
        required: true
      spire-entry-registrar:
        condition: service_completed_successfully
        required: true
    environment:
      HEALTHCHECK_URL: https://127.0.0.1:8443/
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIKE_NEXUS_BACKEND_STORE: sqlite
      SPIKE_NEXUS_DATA_DIR: /opt/spike/data
      SPIKE_NEXUS_KEEPER_PEERS: https://spike-keeper-1:8443
      SPIKE_NEXUS_KEEPER_UPDATE_INTERVAL: 5s
      SPIKE_NEXUS_SHAMIR_SHARES: "1"
      SPIKE_NEXUS_SHAMIR_THRESHOLD: "1"
      SPIKE_NEXUS_TLS_PORT: :8443
      SPIKE_SYSTEM_LOG_LEVEL: INFO
      SPIKE_TRUST_ROOT: poc.local
      SPIKE_TRUST_ROOT_BOOTSTRAP: poc.local
      SPIKE_TRUST_ROOT_KEEPER: poc.local
      SPIKE_TRUST_ROOT_LITE_WORKLOAD: poc.local
      SPIKE_TRUST_ROOT_NEXUS: poc.local
      SPIKE_TRUST_ROOT_PILOT: poc.local
    hostname: spike-nexus
    image: spike-nexus:latest
    labels:
      component: secrets
      service: spike
      spiffe-id: spike-nexus
    networks:
      secrets-plane: null
    ports:
      - mode: ingress
        target: 8443
        published: "8443"
        protocol: tcp
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
      - type: volume
        source: spike-nexus-data
        target: /opt/spike/data
        volume: {}
  spike-secret-seeder:
    command:
      - |
        set -eu
        # RFA-cjc: Source .env from mounted secret file to keep keys out of docker compose config
        if [ -f /run/secrets/env ]; then
          set -a
          . /run/secrets/env
          set +a
        fi
        echo 'spike-seeder: waiting for SPIKE Nexus readiness...'
        sleep 5
        echo 'spike-seeder: seeding ref=deadbeef'
        seeded=0
        attempt=1
        max_attempts=15
        while [ "$$attempt" -le "$$max_attempts" ]; do
          echo "spike-seeder: secret put attempt $$attempt/$$max_attempts"
          PUT_OUT="$$(spike secret put deadbeef value=test-secret-value-12345 2>&1 || true)"
          echo "$$PUT_OUT"

          LIST_OUT="$$(spike secret list 2>&1 || true)"
          echo "$$LIST_OUT"

          if ! echo "$$PUT_OUT" | grep -qi "Error:" && echo "$$LIST_OUT" | grep -q "deadbeef"; then
            seeded=1
            break
          fi

          attempt=$$((attempt + 1))
          sleep 2
        done

        if [ "$$seeded" -ne 1 ]; then
          echo 'spike-seeder: warning: failed to seed deadbeef after retries (continuing for POC compatibility)'
        fi

        # RFA-cjc: Seed Groq API key for step-up guard model (late-binding via SPIKE)
        if [ -n "$${GROQ_API_KEY:-}" ]; then
          echo 'spike-seeder: seeding groq-api-key'
          groq_seeded=0
          attempt=1
          while [ "$$attempt" -le "$$max_attempts" ]; do
            echo "spike-seeder: groq-api-key put attempt $$attempt/$$max_attempts"
            GROQ_OUT="$$(spike secret put groq-api-key "value=$$GROQ_API_KEY" 2>&1 || true)"

            GROQ_LIST="$$(spike secret list 2>&1 || true)"
            if ! echo "$$GROQ_OUT" | grep -qi "Error:" || echo "$$GROQ_LIST" | grep -q "groq-api-key"; then
              groq_seeded=1
              break
            fi

            attempt=$$((attempt + 1))
            sleep 2
          done

          if [ "$$groq_seeded" -eq 1 ]; then
            echo 'spike-seeder: groq-api-key seeded successfully'
          else
            echo 'spike-seeder: warning: failed to seed groq-api-key after retries (step-up guard will degrade to fail-open)'
          fi
        else
          echo 'spike-seeder: GROQ_API_KEY not set, skipping guard model key seeding (step-up guard will degrade to fail-open)'
        fi

        # RFA-ajf6: Seed messaging platform API keys for per-message SPIKE token resolution.
        # These are placeholder values for the POC. In production, real platform credentials
        # would be pre-seeded by an operator or secrets pipeline. The messaging simulator
        # accepts any non-empty Bearer token, so placeholder values work for E2E testing.
        echo 'spike-seeder: seeding messaging platform secrets...'
        spike secret put whatsapp-api-key value=whatsapp-api-key-placeholder || echo 'spike-seeder: whatsapp-api-key put failed (non-fatal)'
        spike secret put telegram-bot-token value=telegram-bot-token-placeholder || echo 'spike-seeder: telegram-bot-token put failed (non-fatal)'
        spike secret put slack-bot-token value=slack-bot-token-placeholder || echo 'spike-seeder: slack-bot-token put failed (non-fatal)'
        echo 'spike-seeder: messaging secrets seeded'

        echo 'spike-seeder: creating gateway-read ACL policy'
        policy_created=0
        attempt=1
        while [ "$$attempt" -le "$$max_attempts" ]; do
          echo "spike-seeder: policy create attempt $$attempt/$$max_attempts"
          POLICY_OUT="$$(spike policy create --name=gateway-read \
          --path-pattern='.*' \
          --spiffeid-pattern='^spiffe://poc.local/gateways/.*' \
          --permissions=read 2>&1 || true)"
          echo "$$POLICY_OUT"

          if ! echo "$$POLICY_OUT" | grep -qi "Error:" || echo "$$POLICY_OUT" | grep -qi "already exists"; then
            policy_created=1
            break
          fi

          attempt=$$((attempt + 1))
          sleep 2
        done

        if [ "$$policy_created" -ne 1 ]; then
          echo 'spike-seeder: warning: failed to create policy after retries (continuing for POC compatibility)'
        fi

        echo 'spike-seeder: done'
    container_name: spike-secret-seeder
    depends_on:
      spike-bootstrap:
        condition: service_completed_successfully
        required: true
      spike-nexus:
        condition: service_healthy
        required: true
    entrypoint:
      - /bin/sh
      - -c
    environment:
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIKE_NEXUS_API_URL: https://spike-nexus:8443
      SPIKE_TRUST_ROOT: poc.local
      SPIKE_TRUST_ROOT_NEXUS: poc.local
      SPIKE_TRUST_ROOT_PILOT: poc.local
    image: ghcr.io/spiffe/spike-pilot:0.8.0@sha256:86b26666c171c5284c522bfb42f16473c85be6f3e3e32b1e3deaa8cd5a18eaff
    labels:
      spiffe-id: spike-seeder
    networks:
      secrets-plane: null
    restart: "no"
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/.env
        target: /run/secrets/env
        read_only: true
        bind: {}
  spire-agent:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.spire-agent
    container_name: spire-agent
    depends_on:
      spire-server:
        condition: service_healthy
        required: true
      spire-token-generator:
        condition: service_completed_successfully
        required: true
    hostname: spire-agent
    healthcheck:
      test:
        - CMD
        - /opt/spire/bin/spire-agent
        - healthcheck
      timeout: 5s
      interval: 10s
      retries: 5
      start_period: 20s
    image: spire-agent-wrapper:latest
    networks:
      control-plane: null
    pid: host
    privileged: true
    volumes:
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config/spire/agent.conf
        target: /opt/spire/conf/agent/agent.conf
        read_only: true
        bind: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/data/spire-agent
        target: /opt/spire/data/agent
        bind: {}
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        volume: {}
      - type: volume
        source: spire-join-token
        target: /token
        read_only: true
        volume: {}
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
        read_only: true
        bind: {}
  spire-entry-registrar:
    container_name: spire-entry-registrar
    depends_on:
      spire-agent:
        condition: service_healthy
        required: true
    entrypoint:
      - /bin/sh
      - /register.sh
    image: spire-token-generator:latest
    networks:
      control-plane: null
    restart: "no"
    volumes:
      - type: volume
        source: spire-server-socket
        target: /tmp/spire-server
        read_only: true
        volume: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/scripts/register-spire-entries.sh
        target: /register.sh
        read_only: true
        bind: {}
  spire-server:
    command:
      - -config
      - /opt/spire/conf/server/server.conf
    container_name: spire-server
    hostname: spire-server
    healthcheck:
      test:
        - CMD
        - /opt/spire/bin/spire-server
        - healthcheck
      timeout: 5s
      interval: 10s
      retries: 5
      start_period: 30s
    image: ghcr.io/spiffe/spire-server:1.10.0@sha256:26daa394b3bfbc9dcadc734e9b110ce7ac5f2e1fe16050eb4418772280748b5e
    networks:
      control-plane: null
    ports:
      - mode: ingress
        target: 8081
        published: "18081"
        protocol: tcp
      - mode: ingress
        target: 8080
        published: "18080"
        protocol: tcp
    volumes:
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config/spire/server.conf
        target: /opt/spire/conf/server/server.conf
        read_only: true
        bind: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/data/spire-server
        target: /opt/spire/data
        bind: {}
      - type: volume
        source: spire-server-socket
        target: /tmp/spire-server
        volume: {}
  spire-token-generator:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.token-generator
    container_name: spire-token-generator
    depends_on:
      spire-server:
        condition: service_healthy
        required: true
    image: spire-token-generator:latest
    networks:
      control-plane: null
    restart: "no"
    volumes:
      - type: volume
        source: spire-server-socket
        target: /tmp/spire-server
        read_only: true
        volume: {}
      - type: volume
        source: spire-join-token
        target: /token
        volume: {}
networks:
  agentic-net:
    name: agentic-security-network
    driver: bridge
    internal: true
  control-plane:
    name: agentic-security-control-plane
    driver: bridge
    internal: true
  data-plane:
    name: agentic-security-data-plane
    driver: bridge
    internal: true
  phoenix-net:
    name: phoenix-observability-network
    external: true
  secrets-plane:
    name: agentic-security-secrets-plane
    driver: bridge
    internal: true
  tool-plane:
    name: agentic-security-tool-plane
    driver: bridge
    internal: true
volumes:
  keydb-certs:
    name: keydb-certs
  keydb-data:
    name: keydb-data
  spike-nexus-data:
    name: spike-nexus-data
  spire-agent-socket:
    name: spire-agent-socket
  spire-join-token:
    name: spire-join-token
  spire-server-socket:
    name: spire-server-socket
  - \name: poc
services:
  content-scanner:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/demo/content-scanner
      dockerfile: Dockerfile
    cap_drop:
      - ALL
    container_name: content-scanner
    hostname: content-scanner
    healthcheck:
      test:
        - CMD
        - wget
        - --spider
        - -q
        - http://localhost:8085/health
      timeout: 3s
      interval: 5s
      retries: 5
    networks:
      tool-plane: null
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
  keydb:
    container_name: keydb
    hostname: keydb
    healthcheck:
      test:
        - CMD
        - keydb-cli
        - ping
      timeout: 3s
      interval: 10s
      retries: 5
    image: eqalpha/keydb@sha256:6537505c42355ca1f571276bddf83f5b750f760f07b2a185a676481791e388ac
    labels:
      component: session-store
      spiffe-id: keydb
    networks:
      data-plane: null
    ports:
      - mode: ingress
        target: 6379
        published: "6379"
        protocol: tcp
      - mode: ingress
        target: 6380
        published: "6380"
        protocol: tcp
    volumes:
      - type: volume
        source: keydb-data
        target: /data
        volume: {}
      - type: volume
        source: keydb-certs
        target: /certs
        read_only: true
        volume: {}
  mcp-security-gateway:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.gateway
    cap_drop:
      - ALL
    container_name: mcp-security-gateway
    depends_on:
      content-scanner:
        condition: service_healthy
        required: true
      keydb:
        condition: service_healthy
        required: true
      mock-guard-model:
        condition: service_healthy
        required: true
      mock-mcp-server:
        condition: service_healthy
        required: true
      spike-nexus:
        condition: service_healthy
        required: true
      spike-secret-seeder:
        condition: service_completed_successfully
        required: true
      spire-agent:
        condition: service_healthy
        required: true
    environment:
      ALLOW_INSECURE_DEV_MODE: "1"
      ALLOW_NON_LOOPBACK_DEV_BIND: "1"
      AUDIT_LOG_PATH: /tmp/audit.jsonl
      CAPABILITY_REGISTRY_V2_PATH: /config/capability-registry-v2.yaml
      DEEP_SCAN_FALLBACK: fail_closed
      DEEP_SCAN_TIMEOUT: "5"
      DEMO_RUGPULL_ADMIN_ENABLED: "1"
      DEV_LISTEN_HOST: 0.0.0.0
      DLP_INJECTION_POLICY: ""
      DLP_PII_POLICY: block
      ENFORCEMENT_PROFILE: dev
      EXTENSION_REGISTRY_PATH: /config/extensions-demo.yaml
      GUARD_API_KEY: demo-guard-key
      GUARD_MODEL_ENDPOINT: http://mock-guard-model:8080/openai/v1
      GUARD_MODEL_NAME: ""
      KEYDB_URL: redis://keydb:6379
      LOG_LEVEL: info
      MAX_REQUEST_SIZE_BYTES: "10485760"
      MCP_TRANSPORT_MODE: mcp
      MESSAGING_PLATFORM_ENDPOINT_WHATSAPP: http://messaging-sim:8090/v1/messages
      MODEL_PROVIDER_CATALOG_PATH: /config/model-provider-catalog.v2.yaml
      MODEL_PROVIDER_ENDPOINT_GROQ: http://mock-guard-model:8080/openai/v1/chat/completions
      OPA_POLICY_DIR: /config/opa
      OTEL_EXPORTER_OTLP_ENDPOINT: otel-collector:4317
      OTEL_SERVICE_NAME: mcp-security-gateway
      PORT: "9090"
      RATE_LIMIT_BURST: "10"
      RATE_LIMIT_RPM: "60"
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIFFE_LISTEN_PORT: "9443"
      SPIFFE_MODE: dev
      SPIFFE_TRUST_DOMAIN: poc.local
      SPIKE_NEXUS_URL: https://spike-nexus:8443
      SPIRE_AGENT_SOCKET: /tmp/spire-agent/public/api.sock
      TOOL_REGISTRY_CONFIG_PATH: /config/tool-registry.yaml
      UPSTREAM_URL: http://mock-mcp-server:8082
    hostname: mcp-security-gateway
    healthcheck:
      test:
        - CMD
        - /app/gateway
        - health
      timeout: 3s
      interval: 10s
      retries: 3
      start_period: 45s
    image: mcp-security-gateway:latest
    labels:
      component: gateway
      spiffe-id: mcp-security-gateway
    networks:
      agentic-net: null
      data-plane: null
      phoenix-net: null
      secrets-plane: null
      tool-plane: null
    ports:
      - mode: ingress
        target: 9090
        published: "9090"
        protocol: tcp
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config
        target: /config
        read_only: true
        bind: {}
  messaging-sim:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.messaging-sim
    cap_drop:
      - ALL
    container_name: messaging-sim
    environment:
      PORT: "8090"
    hostname: messaging-sim
    healthcheck:
      test:
        - CMD
        - /messaging-sim
        - -healthcheck
      timeout: 3s
      interval: 5s
      retries: 5
    networks:
      tool-plane: null
    read_only: true
    security_opt:
      - no-new-privileges:true
  mock-guard-model:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/demo/mock-guard-model
      dockerfile: Dockerfile
    cap_drop:
      - ALL
    container_name: mock-guard-model
    hostname: mock-guard-model
    healthcheck:
      test:
        - CMD
        - wget
        - --spider
        - -q
        - http://localhost:8080/health
      timeout: 3s
      interval: 5s
      retries: 5
    networks:
      tool-plane: null
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
  mock-mcp-server:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/demo/mock-mcp-server
      dockerfile: Dockerfile
    cap_drop:
      - ALL
    container_name: mock-mcp-server
    hostname: mock-mcp-server
    healthcheck:
      test:
        - CMD
        - wget
        - --spider
        - -q
        - http://localhost:8082/health
      timeout: 3s
      interval: 5s
      retries: 5
    networks:
      tool-plane: null
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
  spike-bootstrap:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.spike-bootstrap
    command:
      - -init
    container_name: spike-bootstrap
    depends_on:
      spike-keeper-1:
        condition: service_healthy
        required: true
      spike-nexus:
        condition: service_started
        required: true
      spire-entry-registrar:
        condition: service_completed_successfully
        required: true
    environment:
      BOOTSTRAP_TIMEOUT: "30"
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIKE_NEXUS_API_URL: https://spike-nexus:8443
      SPIKE_NEXUS_KEEPER_PEERS: https://spike-keeper-1:8443
      SPIKE_NEXUS_SHAMIR_SHARES: "1"
      SPIKE_NEXUS_SHAMIR_THRESHOLD: "1"
      SPIKE_SYSTEM_LOG_LEVEL: DEBUG
      SPIKE_TRUST_ROOT: poc.local
      SPIKE_TRUST_ROOT_BOOTSTRAP: poc.local
      SPIKE_TRUST_ROOT_KEEPER: poc.local
      SPIKE_TRUST_ROOT_LITE_WORKLOAD: poc.local
      SPIKE_TRUST_ROOT_NEXUS: poc.local
      SPIKE_TRUST_ROOT_PILOT: poc.local
    image: poc-spike-bootstrap:latest
    labels:
      spiffe-id: spike-bootstrap
    networks:
      secrets-plane: null
    restart: "no"
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
  spike-keeper-1:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.spike-keeper
    cap_drop:
      - ALL
    container_name: spike-keeper-1
    depends_on:
      spire-entry-registrar:
        condition: service_completed_successfully
        required: true
    environment:
      HEALTHCHECK_ADDR: 127.0.0.1:8443
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIKE_KEEPER_TLS_PORT: :8443
      SPIKE_SYSTEM_LOG_LEVEL: INFO
      SPIKE_TRUST_ROOT: poc.local
      SPIKE_TRUST_ROOT_BOOTSTRAP: poc.local
      SPIKE_TRUST_ROOT_KEEPER: poc.local
      SPIKE_TRUST_ROOT_LITE_WORKLOAD: poc.local
      SPIKE_TRUST_ROOT_NEXUS: poc.local
      SPIKE_TRUST_ROOT_PILOT: poc.local
    hostname: spike-keeper-1
    image: spike-keeper:latest
    labels:
      component: secrets
      service: spike
      spiffe-id: spike-keeper-1
    networks:
      secrets-plane: null
    read_only: true
    restart: "no"
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
  spike-nexus:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.spike-nexus
    cap_drop:
      - ALL
    container_name: spike-nexus
    depends_on:
      spike-keeper-1:
        condition: service_healthy
        required: true
      spire-entry-registrar:
        condition: service_completed_successfully
        required: true
    environment:
      HEALTHCHECK_URL: https://127.0.0.1:8443/
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIKE_NEXUS_BACKEND_STORE: sqlite
      SPIKE_NEXUS_DATA_DIR: /opt/spike/data
      SPIKE_NEXUS_KEEPER_PEERS: https://spike-keeper-1:8443
      SPIKE_NEXUS_KEEPER_UPDATE_INTERVAL: 5s
      SPIKE_NEXUS_SHAMIR_SHARES: "1"
      SPIKE_NEXUS_SHAMIR_THRESHOLD: "1"
      SPIKE_NEXUS_TLS_PORT: :8443
      SPIKE_SYSTEM_LOG_LEVEL: INFO
      SPIKE_TRUST_ROOT: poc.local
      SPIKE_TRUST_ROOT_BOOTSTRAP: poc.local
      SPIKE_TRUST_ROOT_KEEPER: poc.local
      SPIKE_TRUST_ROOT_LITE_WORKLOAD: poc.local
      SPIKE_TRUST_ROOT_NEXUS: poc.local
      SPIKE_TRUST_ROOT_PILOT: poc.local
    hostname: spike-nexus
    image: spike-nexus:latest
    labels:
      component: secrets
      service: spike
      spiffe-id: spike-nexus
    networks:
      secrets-plane: null
    ports:
      - mode: ingress
        target: 8443
        published: "8443"
        protocol: tcp
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
      - type: volume
        source: spike-nexus-data
        target: /opt/spike/data
        volume: {}
  spike-secret-seeder:
    command:
      - |
        set -eu
        # RFA-cjc: Source .env from mounted secret file to keep keys out of docker compose config
        if [ -f /run/secrets/env ]; then
          set -a
          . /run/secrets/env
          set +a
        fi
        echo 'spike-seeder: waiting for SPIKE Nexus readiness...'
        sleep 5
        echo 'spike-seeder: seeding ref=deadbeef'
        seeded=0
        attempt=1
        max_attempts=15
        while [ "$$attempt" -le "$$max_attempts" ]; do
          echo "spike-seeder: secret put attempt $$attempt/$$max_attempts"
          PUT_OUT="$$(spike secret put deadbeef value=test-secret-value-12345 2>&1 || true)"
          echo "$$PUT_OUT"

          LIST_OUT="$$(spike secret list 2>&1 || true)"
          echo "$$LIST_OUT"

          if ! echo "$$PUT_OUT" | grep -qi "Error:" && echo "$$LIST_OUT" | grep -q "deadbeef"; then
            seeded=1
            break
          fi

          attempt=$$((attempt + 1))
          sleep 2
        done

        if [ "$$seeded" -ne 1 ]; then
          echo 'spike-seeder: warning: failed to seed deadbeef after retries (continuing for POC compatibility)'
        fi

        # RFA-cjc: Seed Groq API key for step-up guard model (late-binding via SPIKE)
        if [ -n "$${GROQ_API_KEY:-}" ]; then
          echo 'spike-seeder: seeding groq-api-key'
          groq_seeded=0
          attempt=1
          while [ "$$attempt" -le "$$max_attempts" ]; do
            echo "spike-seeder: groq-api-key put attempt $$attempt/$$max_attempts"
            GROQ_OUT="$$(spike secret put groq-api-key "value=$$GROQ_API_KEY" 2>&1 || true)"

            GROQ_LIST="$$(spike secret list 2>&1 || true)"
            if ! echo "$$GROQ_OUT" | grep -qi "Error:" || echo "$$GROQ_LIST" | grep -q "groq-api-key"; then
              groq_seeded=1
              break
            fi

            attempt=$$((attempt + 1))
            sleep 2
          done

          if [ "$$groq_seeded" -eq 1 ]; then
            echo 'spike-seeder: groq-api-key seeded successfully'
          else
            echo 'spike-seeder: warning: failed to seed groq-api-key after retries (step-up guard will degrade to fail-open)'
          fi
        else
          echo 'spike-seeder: GROQ_API_KEY not set, skipping guard model key seeding (step-up guard will degrade to fail-open)'
        fi

        # RFA-ajf6: Seed messaging platform API keys for per-message SPIKE token resolution.
        # These are placeholder values for the POC. In production, real platform credentials
        # would be pre-seeded by an operator or secrets pipeline. The messaging simulator
        # accepts any non-empty Bearer token, so placeholder values work for E2E testing.
        echo 'spike-seeder: seeding messaging platform secrets...'
        spike secret put whatsapp-api-key value=whatsapp-api-key-placeholder || echo 'spike-seeder: whatsapp-api-key put failed (non-fatal)'
        spike secret put telegram-bot-token value=telegram-bot-token-placeholder || echo 'spike-seeder: telegram-bot-token put failed (non-fatal)'
        spike secret put slack-bot-token value=slack-bot-token-placeholder || echo 'spike-seeder: slack-bot-token put failed (non-fatal)'
        echo 'spike-seeder: messaging secrets seeded'

        echo 'spike-seeder: creating gateway-read ACL policy'
        policy_created=0
        attempt=1
        while [ "$$attempt" -le "$$max_attempts" ]; do
          echo "spike-seeder: policy create attempt $$attempt/$$max_attempts"
          POLICY_OUT="$$(spike policy create --name=gateway-read \
          --path-pattern='.*' \
          --spiffeid-pattern='^spiffe://poc.local/gateways/.*' \
          --permissions=read 2>&1 || true)"
          echo "$$POLICY_OUT"

          if ! echo "$$POLICY_OUT" | grep -qi "Error:" || echo "$$POLICY_OUT" | grep -qi "already exists"; then
            policy_created=1
            break
          fi

          attempt=$$((attempt + 1))
          sleep 2
        done

        if [ "$$policy_created" -ne 1 ]; then
          echo 'spike-seeder: warning: failed to create policy after retries (continuing for POC compatibility)'
        fi

        echo 'spike-seeder: done'
    container_name: spike-secret-seeder
    depends_on:
      spike-bootstrap:
        condition: service_completed_successfully
        required: true
      spike-nexus:
        condition: service_healthy
        required: true
    entrypoint:
      - /bin/sh
      - -c
    environment:
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIKE_NEXUS_API_URL: https://spike-nexus:8443
      SPIKE_TRUST_ROOT: poc.local
      SPIKE_TRUST_ROOT_NEXUS: poc.local
      SPIKE_TRUST_ROOT_PILOT: poc.local
    image: ghcr.io/spiffe/spike-pilot:0.8.0@sha256:86b26666c171c5284c522bfb42f16473c85be6f3e3e32b1e3deaa8cd5a18eaff
    labels:
      spiffe-id: spike-seeder
    networks:
      secrets-plane: null
    restart: "no"
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/.env
        target: /run/secrets/env
        read_only: true
        bind: {}
  spire-agent:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.spire-agent
    container_name: spire-agent
    depends_on:
      spire-server:
        condition: service_healthy
        required: true
      spire-token-generator:
        condition: service_completed_successfully
        required: true
    hostname: spire-agent
    healthcheck:
      test:
        - CMD
        - /opt/spire/bin/spire-agent
        - healthcheck
      timeout: 5s
      interval: 10s
      retries: 5
      start_period: 20s
    image: spire-agent-wrapper:latest
    networks:
      control-plane: null
    pid: host
    privileged: true
    volumes:
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config/spire/agent.conf
        target: /opt/spire/conf/agent/agent.conf
        read_only: true
        bind: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/data/spire-agent
        target: /opt/spire/data/agent
        bind: {}
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        volume: {}
      - type: volume
        source: spire-join-token
        target: /token
        read_only: true
        volume: {}
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
        read_only: true
        bind: {}
  spire-entry-registrar:
    container_name: spire-entry-registrar
    depends_on:
      spire-agent:
        condition: service_healthy
        required: true
    entrypoint:
      - /bin/sh
      - /register.sh
    image: spire-token-generator:latest
    networks:
      control-plane: null
    restart: "no"
    volumes:
      - type: volume
        source: spire-server-socket
        target: /tmp/spire-server
        read_only: true
        volume: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/scripts/register-spire-entries.sh
        target: /register.sh
        read_only: true
        bind: {}
  spire-server:
    command:
      - -config
      - /opt/spire/conf/server/server.conf
    container_name: spire-server
    hostname: spire-server
    healthcheck:
      test:
        - CMD
        - /opt/spire/bin/spire-server
        - healthcheck
      timeout: 5s
      interval: 10s
      retries: 5
      start_period: 30s
    image: ghcr.io/spiffe/spire-server:1.10.0@sha256:26daa394b3bfbc9dcadc734e9b110ce7ac5f2e1fe16050eb4418772280748b5e
    networks:
      control-plane: null
    ports:
      - mode: ingress
        target: 8081
        published: "18081"
        protocol: tcp
      - mode: ingress
        target: 8080
        published: "18080"
        protocol: tcp
    volumes:
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config/spire/server.conf
        target: /opt/spire/conf/server/server.conf
        read_only: true
        bind: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/data/spire-server
        target: /opt/spire/data
        bind: {}
      - type: volume
        source: spire-server-socket
        target: /tmp/spire-server
        volume: {}
  spire-token-generator:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.token-generator
    container_name: spire-token-generator
    depends_on:
      spire-server:
        condition: service_healthy
        required: true
    image: spire-token-generator:latest
    networks:
      control-plane: null
    restart: "no"
    volumes:
      - type: volume
        source: spire-server-socket
        target: /tmp/spire-server
        read_only: true
        volume: {}
      - type: volume
        source: spire-join-token
        target: /token
        volume: {}
networks:
  agentic-net:
    name: agentic-security-network
    driver: bridge
    internal: true
  control-plane:
    name: agentic-security-control-plane
    driver: bridge
    internal: true
  data-plane:
    name: agentic-security-data-plane
    driver: bridge
    internal: true
  phoenix-net:
    name: phoenix-observability-network
    external: true
  secrets-plane:
    name: agentic-security-secrets-plane
    driver: bridge
    internal: true
  tool-plane:
    name: agentic-security-tool-plane
    driver: bridge
    internal: true
volumes:
  keydb-certs:
    name: keydb-certs
  keydb-data:
    name: keydb-data
  spike-nexus-data:
    name: spike-nexus-data
  spire-agent-socket:
    name: spire-agent-socket
  spire-join-token:
    name: spire-join-token
  spire-server-socket:
    name: spire-server-socket
- Summary: strict runtime validation PASS; base compose verification PASS; strict compose render PASS; default compose render PASS.
- Key output:
  - \tests/e2e/validate_strict_runtime_wiring.sh
[INFO] Validating strict K8s runtime wiring (staging/prod overlays)...
[INFO] Validating strict Compose runtime wiring...
[PASS] Strict runtime wiring validation passed: \ then \
  - \[PASS] No third-party services use :latest
[PASS] All third-party services are digest-pinned (@sha256:...)
[PASS] All compose Dockerfile FROM references are digest-pinned (@sha256:...)

compose-verify: PASS: \, \, \
  - Strict render for \ now shows only \ and does not include \, \, \, \, \, or \.

### Commit
- Branch: \
- SHA: \

### AC Verification
| AC # | Requirement | Code Location | Test Location | Status |
|------|-------------|---------------|---------------|--------|
| 1 | Strict compose does not publish the dev HTTP listener. | \ | \ | PASS |
| 2 | Strict compose clears inherited demo/insecure gateway settings. | \ | \ | PASS |
| 3 | Docs and rendered strict config match. | \ | \ | PASS |

## nd_contract
status: delivered

### evidence
- Claimed story and appended in-progress contract in nd.
- Replaced the strict compose gateway \ and \ blocks with Compose \ semantics so strict mode no longer inherits dev/demo state from the base file.
- Added explicit negative assertions to \[INFO] Validating strict K8s runtime wiring (staging/prod overlays)...
[INFO] Validating strict Compose runtime wiring...
[PASS] Strict runtime wiring validation passed for port 9090 and inherited dev/demo/mock endpoint vars.
- Updated strict compose deployment docs to describe the expected rendered runtime state.
- Validation commands:
  - \tests/e2e/validate_strict_runtime_wiring.sh
[INFO] Validating strict K8s runtime wiring (staging/prod overlays)...
[INFO] Validating strict Compose runtime wiring...
[PASS] Strict runtime wiring validation passed -> PASS
  - \[PASS] No third-party services use :latest
[PASS] All third-party services are digest-pinned (@sha256:...)
[PASS] All compose Dockerfile FROM references are digest-pinned (@sha256:...)

compose-verify: PASS -> PASS
  - \ with strict env vars set -> PASS; gateway block rendered only \
  - \name: poc
services:
  content-scanner:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/demo/content-scanner
      dockerfile: Dockerfile
    cap_drop:
      - ALL
    container_name: content-scanner
    hostname: content-scanner
    healthcheck:
      test:
        - CMD
        - wget
        - --spider
        - -q
        - http://localhost:8085/health
      timeout: 3s
      interval: 5s
      retries: 5
    networks:
      tool-plane: null
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
  keydb:
    container_name: keydb
    hostname: keydb
    healthcheck:
      test:
        - CMD
        - keydb-cli
        - ping
      timeout: 3s
      interval: 10s
      retries: 5
    image: eqalpha/keydb@sha256:6537505c42355ca1f571276bddf83f5b750f760f07b2a185a676481791e388ac
    labels:
      component: session-store
      spiffe-id: keydb
    networks:
      data-plane: null
    ports:
      - mode: ingress
        target: 6379
        published: "6379"
        protocol: tcp
      - mode: ingress
        target: 6380
        published: "6380"
        protocol: tcp
    volumes:
      - type: volume
        source: keydb-data
        target: /data
        volume: {}
      - type: volume
        source: keydb-certs
        target: /certs
        read_only: true
        volume: {}
  mcp-security-gateway:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.gateway
    cap_drop:
      - ALL
    container_name: mcp-security-gateway
    depends_on:
      content-scanner:
        condition: service_healthy
        required: true
      keydb:
        condition: service_healthy
        required: true
      mock-guard-model:
        condition: service_healthy
        required: true
      mock-mcp-server:
        condition: service_healthy
        required: true
      spike-nexus:
        condition: service_healthy
        required: true
      spike-secret-seeder:
        condition: service_completed_successfully
        required: true
      spire-agent:
        condition: service_healthy
        required: true
    environment:
      ALLOW_INSECURE_DEV_MODE: "1"
      ALLOW_NON_LOOPBACK_DEV_BIND: "1"
      AUDIT_LOG_PATH: /tmp/audit.jsonl
      CAPABILITY_REGISTRY_V2_PATH: /config/capability-registry-v2.yaml
      DEEP_SCAN_FALLBACK: fail_closed
      DEEP_SCAN_TIMEOUT: "5"
      DEMO_RUGPULL_ADMIN_ENABLED: "1"
      DEV_LISTEN_HOST: 0.0.0.0
      DLP_INJECTION_POLICY: ""
      DLP_PII_POLICY: block
      ENFORCEMENT_PROFILE: dev
      EXTENSION_REGISTRY_PATH: /config/extensions-demo.yaml
      GUARD_API_KEY: demo-guard-key
      GUARD_MODEL_ENDPOINT: http://mock-guard-model:8080/openai/v1
      GUARD_MODEL_NAME: ""
      KEYDB_URL: redis://keydb:6379
      LOG_LEVEL: info
      MAX_REQUEST_SIZE_BYTES: "10485760"
      MCP_TRANSPORT_MODE: mcp
      MESSAGING_PLATFORM_ENDPOINT_WHATSAPP: http://messaging-sim:8090/v1/messages
      MODEL_PROVIDER_CATALOG_PATH: /config/model-provider-catalog.v2.yaml
      MODEL_PROVIDER_ENDPOINT_GROQ: http://mock-guard-model:8080/openai/v1/chat/completions
      OPA_POLICY_DIR: /config/opa
      OTEL_EXPORTER_OTLP_ENDPOINT: otel-collector:4317
      OTEL_SERVICE_NAME: mcp-security-gateway
      PORT: "9090"
      RATE_LIMIT_BURST: "10"
      RATE_LIMIT_RPM: "60"
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIFFE_LISTEN_PORT: "9443"
      SPIFFE_MODE: dev
      SPIFFE_TRUST_DOMAIN: poc.local
      SPIKE_NEXUS_URL: https://spike-nexus:8443
      SPIRE_AGENT_SOCKET: /tmp/spire-agent/public/api.sock
      TOOL_REGISTRY_CONFIG_PATH: /config/tool-registry.yaml
      UPSTREAM_URL: http://mock-mcp-server:8082
    hostname: mcp-security-gateway
    healthcheck:
      test:
        - CMD
        - /app/gateway
        - health
      timeout: 3s
      interval: 10s
      retries: 3
      start_period: 45s
    image: mcp-security-gateway:latest
    labels:
      component: gateway
      spiffe-id: mcp-security-gateway
    networks:
      agentic-net: null
      data-plane: null
      phoenix-net: null
      secrets-plane: null
      tool-plane: null
    ports:
      - mode: ingress
        target: 9090
        published: "9090"
        protocol: tcp
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config
        target: /config
        read_only: true
        bind: {}
  messaging-sim:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.messaging-sim
    cap_drop:
      - ALL
    container_name: messaging-sim
    environment:
      PORT: "8090"
    hostname: messaging-sim
    healthcheck:
      test:
        - CMD
        - /messaging-sim
        - -healthcheck
      timeout: 3s
      interval: 5s
      retries: 5
    networks:
      tool-plane: null
    read_only: true
    security_opt:
      - no-new-privileges:true
  mock-guard-model:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/demo/mock-guard-model
      dockerfile: Dockerfile
    cap_drop:
      - ALL
    container_name: mock-guard-model
    hostname: mock-guard-model
    healthcheck:
      test:
        - CMD
        - wget
        - --spider
        - -q
        - http://localhost:8080/health
      timeout: 3s
      interval: 5s
      retries: 5
    networks:
      tool-plane: null
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
  mock-mcp-server:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/demo/mock-mcp-server
      dockerfile: Dockerfile
    cap_drop:
      - ALL
    container_name: mock-mcp-server
    hostname: mock-mcp-server
    healthcheck:
      test:
        - CMD
        - wget
        - --spider
        - -q
        - http://localhost:8082/health
      timeout: 3s
      interval: 5s
      retries: 5
    networks:
      tool-plane: null
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
  spike-bootstrap:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.spike-bootstrap
    command:
      - -init
    container_name: spike-bootstrap
    depends_on:
      spike-keeper-1:
        condition: service_healthy
        required: true
      spike-nexus:
        condition: service_started
        required: true
      spire-entry-registrar:
        condition: service_completed_successfully
        required: true
    environment:
      BOOTSTRAP_TIMEOUT: "30"
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIKE_NEXUS_API_URL: https://spike-nexus:8443
      SPIKE_NEXUS_KEEPER_PEERS: https://spike-keeper-1:8443
      SPIKE_NEXUS_SHAMIR_SHARES: "1"
      SPIKE_NEXUS_SHAMIR_THRESHOLD: "1"
      SPIKE_SYSTEM_LOG_LEVEL: DEBUG
      SPIKE_TRUST_ROOT: poc.local
      SPIKE_TRUST_ROOT_BOOTSTRAP: poc.local
      SPIKE_TRUST_ROOT_KEEPER: poc.local
      SPIKE_TRUST_ROOT_LITE_WORKLOAD: poc.local
      SPIKE_TRUST_ROOT_NEXUS: poc.local
      SPIKE_TRUST_ROOT_PILOT: poc.local
    image: poc-spike-bootstrap:latest
    labels:
      spiffe-id: spike-bootstrap
    networks:
      secrets-plane: null
    restart: "no"
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
  spike-keeper-1:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.spike-keeper
    cap_drop:
      - ALL
    container_name: spike-keeper-1
    depends_on:
      spire-entry-registrar:
        condition: service_completed_successfully
        required: true
    environment:
      HEALTHCHECK_ADDR: 127.0.0.1:8443
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIKE_KEEPER_TLS_PORT: :8443
      SPIKE_SYSTEM_LOG_LEVEL: INFO
      SPIKE_TRUST_ROOT: poc.local
      SPIKE_TRUST_ROOT_BOOTSTRAP: poc.local
      SPIKE_TRUST_ROOT_KEEPER: poc.local
      SPIKE_TRUST_ROOT_LITE_WORKLOAD: poc.local
      SPIKE_TRUST_ROOT_NEXUS: poc.local
      SPIKE_TRUST_ROOT_PILOT: poc.local
    hostname: spike-keeper-1
    image: spike-keeper:latest
    labels:
      component: secrets
      service: spike
      spiffe-id: spike-keeper-1
    networks:
      secrets-plane: null
    read_only: true
    restart: "no"
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
  spike-nexus:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.spike-nexus
    cap_drop:
      - ALL
    container_name: spike-nexus
    depends_on:
      spike-keeper-1:
        condition: service_healthy
        required: true
      spire-entry-registrar:
        condition: service_completed_successfully
        required: true
    environment:
      HEALTHCHECK_URL: https://127.0.0.1:8443/
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIKE_NEXUS_BACKEND_STORE: sqlite
      SPIKE_NEXUS_DATA_DIR: /opt/spike/data
      SPIKE_NEXUS_KEEPER_PEERS: https://spike-keeper-1:8443
      SPIKE_NEXUS_KEEPER_UPDATE_INTERVAL: 5s
      SPIKE_NEXUS_SHAMIR_SHARES: "1"
      SPIKE_NEXUS_SHAMIR_THRESHOLD: "1"
      SPIKE_NEXUS_TLS_PORT: :8443
      SPIKE_SYSTEM_LOG_LEVEL: INFO
      SPIKE_TRUST_ROOT: poc.local
      SPIKE_TRUST_ROOT_BOOTSTRAP: poc.local
      SPIKE_TRUST_ROOT_KEEPER: poc.local
      SPIKE_TRUST_ROOT_LITE_WORKLOAD: poc.local
      SPIKE_TRUST_ROOT_NEXUS: poc.local
      SPIKE_TRUST_ROOT_PILOT: poc.local
    hostname: spike-nexus
    image: spike-nexus:latest
    labels:
      component: secrets
      service: spike
      spiffe-id: spike-nexus
    networks:
      secrets-plane: null
    ports:
      - mode: ingress
        target: 8443
        published: "8443"
        protocol: tcp
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
      - type: volume
        source: spike-nexus-data
        target: /opt/spike/data
        volume: {}
  spike-secret-seeder:
    command:
      - |
        set -eu
        # RFA-cjc: Source .env from mounted secret file to keep keys out of docker compose config
        if [ -f /run/secrets/env ]; then
          set -a
          . /run/secrets/env
          set +a
        fi
        echo 'spike-seeder: waiting for SPIKE Nexus readiness...'
        sleep 5
        echo 'spike-seeder: seeding ref=deadbeef'
        seeded=0
        attempt=1
        max_attempts=15
        while [ "$$attempt" -le "$$max_attempts" ]; do
          echo "spike-seeder: secret put attempt $$attempt/$$max_attempts"
          PUT_OUT="$$(spike secret put deadbeef value=test-secret-value-12345 2>&1 || true)"
          echo "$$PUT_OUT"

          LIST_OUT="$$(spike secret list 2>&1 || true)"
          echo "$$LIST_OUT"

          if ! echo "$$PUT_OUT" | grep -qi "Error:" && echo "$$LIST_OUT" | grep -q "deadbeef"; then
            seeded=1
            break
          fi

          attempt=$$((attempt + 1))
          sleep 2
        done

        if [ "$$seeded" -ne 1 ]; then
          echo 'spike-seeder: warning: failed to seed deadbeef after retries (continuing for POC compatibility)'
        fi

        # RFA-cjc: Seed Groq API key for step-up guard model (late-binding via SPIKE)
        if [ -n "$${GROQ_API_KEY:-}" ]; then
          echo 'spike-seeder: seeding groq-api-key'
          groq_seeded=0
          attempt=1
          while [ "$$attempt" -le "$$max_attempts" ]; do
            echo "spike-seeder: groq-api-key put attempt $$attempt/$$max_attempts"
            GROQ_OUT="$$(spike secret put groq-api-key "value=$$GROQ_API_KEY" 2>&1 || true)"

            GROQ_LIST="$$(spike secret list 2>&1 || true)"
            if ! echo "$$GROQ_OUT" | grep -qi "Error:" || echo "$$GROQ_LIST" | grep -q "groq-api-key"; then
              groq_seeded=1
              break
            fi

            attempt=$$((attempt + 1))
            sleep 2
          done

          if [ "$$groq_seeded" -eq 1 ]; then
            echo 'spike-seeder: groq-api-key seeded successfully'
          else
            echo 'spike-seeder: warning: failed to seed groq-api-key after retries (step-up guard will degrade to fail-open)'
          fi
        else
          echo 'spike-seeder: GROQ_API_KEY not set, skipping guard model key seeding (step-up guard will degrade to fail-open)'
        fi

        # RFA-ajf6: Seed messaging platform API keys for per-message SPIKE token resolution.
        # These are placeholder values for the POC. In production, real platform credentials
        # would be pre-seeded by an operator or secrets pipeline. The messaging simulator
        # accepts any non-empty Bearer token, so placeholder values work for E2E testing.
        echo 'spike-seeder: seeding messaging platform secrets...'
        spike secret put whatsapp-api-key value=whatsapp-api-key-placeholder || echo 'spike-seeder: whatsapp-api-key put failed (non-fatal)'
        spike secret put telegram-bot-token value=telegram-bot-token-placeholder || echo 'spike-seeder: telegram-bot-token put failed (non-fatal)'
        spike secret put slack-bot-token value=slack-bot-token-placeholder || echo 'spike-seeder: slack-bot-token put failed (non-fatal)'
        echo 'spike-seeder: messaging secrets seeded'

        echo 'spike-seeder: creating gateway-read ACL policy'
        policy_created=0
        attempt=1
        while [ "$$attempt" -le "$$max_attempts" ]; do
          echo "spike-seeder: policy create attempt $$attempt/$$max_attempts"
          POLICY_OUT="$$(spike policy create --name=gateway-read \
          --path-pattern='.*' \
          --spiffeid-pattern='^spiffe://poc.local/gateways/.*' \
          --permissions=read 2>&1 || true)"
          echo "$$POLICY_OUT"

          if ! echo "$$POLICY_OUT" | grep -qi "Error:" || echo "$$POLICY_OUT" | grep -qi "already exists"; then
            policy_created=1
            break
          fi

          attempt=$$((attempt + 1))
          sleep 2
        done

        if [ "$$policy_created" -ne 1 ]; then
          echo 'spike-seeder: warning: failed to create policy after retries (continuing for POC compatibility)'
        fi

        echo 'spike-seeder: done'
    container_name: spike-secret-seeder
    depends_on:
      spike-bootstrap:
        condition: service_completed_successfully
        required: true
      spike-nexus:
        condition: service_healthy
        required: true
    entrypoint:
      - /bin/sh
      - -c
    environment:
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/public/api.sock
      SPIKE_NEXUS_API_URL: https://spike-nexus:8443
      SPIKE_TRUST_ROOT: poc.local
      SPIKE_TRUST_ROOT_NEXUS: poc.local
      SPIKE_TRUST_ROOT_PILOT: poc.local
    image: ghcr.io/spiffe/spike-pilot:0.8.0@sha256:86b26666c171c5284c522bfb42f16473c85be6f3e3e32b1e3deaa8cd5a18eaff
    labels:
      spiffe-id: spike-seeder
    networks:
      secrets-plane: null
    restart: "no"
    volumes:
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        read_only: true
        volume: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/.env
        target: /run/secrets/env
        read_only: true
        bind: {}
  spire-agent:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.spire-agent
    container_name: spire-agent
    depends_on:
      spire-server:
        condition: service_healthy
        required: true
      spire-token-generator:
        condition: service_completed_successfully
        required: true
    hostname: spire-agent
    healthcheck:
      test:
        - CMD
        - /opt/spire/bin/spire-agent
        - healthcheck
      timeout: 5s
      interval: 10s
      retries: 5
      start_period: 20s
    image: spire-agent-wrapper:latest
    networks:
      control-plane: null
    pid: host
    privileged: true
    volumes:
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config/spire/agent.conf
        target: /opt/spire/conf/agent/agent.conf
        read_only: true
        bind: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/data/spire-agent
        target: /opt/spire/data/agent
        bind: {}
      - type: volume
        source: spire-agent-socket
        target: /tmp/spire-agent/public
        volume: {}
      - type: volume
        source: spire-join-token
        target: /token
        read_only: true
        volume: {}
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
        read_only: true
        bind: {}
  spire-entry-registrar:
    container_name: spire-entry-registrar
    depends_on:
      spire-agent:
        condition: service_healthy
        required: true
    entrypoint:
      - /bin/sh
      - /register.sh
    image: spire-token-generator:latest
    networks:
      control-plane: null
    restart: "no"
    volumes:
      - type: volume
        source: spire-server-socket
        target: /tmp/spire-server
        read_only: true
        volume: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/scripts/register-spire-entries.sh
        target: /register.sh
        read_only: true
        bind: {}
  spire-server:
    command:
      - -config
      - /opt/spire/conf/server/server.conf
    container_name: spire-server
    hostname: spire-server
    healthcheck:
      test:
        - CMD
        - /opt/spire/bin/spire-server
        - healthcheck
      timeout: 5s
      interval: 10s
      retries: 5
      start_period: 30s
    image: ghcr.io/spiffe/spire-server:1.10.0@sha256:26daa394b3bfbc9dcadc734e9b110ce7ac5f2e1fe16050eb4418772280748b5e
    networks:
      control-plane: null
    ports:
      - mode: ingress
        target: 8081
        published: "18081"
        protocol: tcp
      - mode: ingress
        target: 8080
        published: "18080"
        protocol: tcp
    volumes:
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/config/spire/server.conf
        target: /opt/spire/conf/server/server.conf
        read_only: true
        bind: {}
      - type: bind
        source: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/data/spire-server
        target: /opt/spire/data
        bind: {}
      - type: volume
        source: spire-server-socket
        target: /tmp/spire-server
        volume: {}
  spire-token-generator:
    build:
      context: /Users/ramirosalas/workspace/agentic_reference_architecture/POC
      dockerfile: docker/Dockerfile.token-generator
    container_name: spire-token-generator
    depends_on:
      spire-server:
        condition: service_healthy
        required: true
    image: spire-token-generator:latest
    networks:
      control-plane: null
    restart: "no"
    volumes:
      - type: volume
        source: spire-server-socket
        target: /tmp/spire-server
        read_only: true
        volume: {}
      - type: volume
        source: spire-join-token
        target: /token
        volume: {}
networks:
  agentic-net:
    name: agentic-security-network
    driver: bridge
    internal: true
  control-plane:
    name: agentic-security-control-plane
    driver: bridge
    internal: true
  data-plane:
    name: agentic-security-data-plane
    driver: bridge
    internal: true
  phoenix-net:
    name: phoenix-observability-network
    external: true
  secrets-plane:
    name: agentic-security-secrets-plane
    driver: bridge
    internal: true
  tool-plane:
    name: agentic-security-tool-plane
    driver: bridge
    internal: true
volumes:
  keydb-certs:
    name: keydb-certs
  keydb-data:
    name: keydb-data
  spike-nexus-data:
    name: spike-nexus-data
  spire-agent-socket:
    name: spire-agent-socket
  spire-join-token:
    name: spire-join-token
  spire-server-socket:
    name: spire-server-socket -> PASS
- Commit: \ on \.

### proof
- [x] AC #1: Strict compose render publishes only \ for \ (Code: \; Test: \; Evidence: strict render output showed \ and no \).
- [x] AC #2: Strict compose render excludes inherited \, \, \, \, and mock guard/model provider endpoints (Code: \; Test: \; Evidence: strict render output omitted each asserted pattern).
- [x] AC #3: Deployment docs now describe the strict render as HTTPS-only with the same forbidden inherited settings absent (Code: \; Test: \; Evidence: docs and rendered config both match the validated absence/presence checks).

## nd_contract
status: in_progress

### evidence
- Claimed: 2026-03-09
- Read story AC and current compose/docs/test surfaces for strict profile.

### proof
- [ ] AC #1: Strict compose does not publish the dev HTTP listener.
- [ ] AC #2: Strict compose clears inherited demo/insecure gateway settings.
- [ ] AC #3: Docs and rendered config match.

## History
- 2026-03-10T06:48:57Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Led to: [[RFA-mnw2]], [[RFA-uehp]], [[RFA-7lrd]], [[RFA-565d]], [[RFA-phtc]]

## Comments

## nd_contract
status: delivered

### evidence
- Code change committed on `codex/story/RFA-k7l5` at `7307960`.
- `docker-compose.strict.yml` now uses Compose `!override` for the gateway `ports` and `environment` blocks, so strict mode no longer inherits the base file's dev/demo listener or mock guard/model endpoint settings.
- `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC strict-runtime-validate` passed.
- `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC compose-verify` passed.
- `STRICT_UPSTREAM_URL=https://strict-upstream.example.com/mcp APPROVAL_SIGNING_KEY=compose-approval-signing-key-material-at-least-32 UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS=spiffe://agentic-ref-arch.poc/ns/tools/sa/mcp-tool KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS=spiffe://agentic-ref-arch.poc/ns/data/sa/keydb docker compose --profile strict -f docker-compose.yml -f docker-compose.strict.yml config` rendered `mcp-security-gateway` with only `published: "9443"` and without `ALLOW_INSECURE_DEV_MODE`, `ALLOW_NON_LOOPBACK_DEV_BIND`, `DEMO_RUGPULL_ADMIN_ENABLED`, `DEV_LISTEN_HOST`, `GUARD_MODEL_ENDPOINT`, or `MODEL_PROVIDER_ENDPOINT_GROQ`.
- `docker compose -f docker-compose.yml config` passed for the default local demo profile.

### proof
- [x] AC #1: Strict compose no longer publishes `9090:9090` for the gateway. (Code: `docker-compose.strict.yml:10-11`; Test: `tests/e2e/validate_strict_runtime_wiring.sh:87-90`)
- [x] AC #2: Strict compose no longer inherits the listed demo/insecure gateway settings from the base file. (Code: `docker-compose.strict.yml:12-49`; Test: `tests/e2e/validate_strict_runtime_wiring.sh:100-105`)
- [x] AC #3: Strict compose documentation now matches the rendered strict configuration. (Code: `docs/deployment-guide.md:562-568`; Test: `tests/e2e/validate_strict_runtime_wiring.sh:74-105`)
